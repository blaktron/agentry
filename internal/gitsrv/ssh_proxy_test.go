package gitsrv

// White-box: behind a TCP proxy the SSH listener takes the client's address
// from a PROXY header sent by a trusted peer, so the key-offer budget is
// per client, not one budget for everyone the proxy carries. The key lookup
// is the boundary faked here; the wire is the real one.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/ratelimit"
)

// proxyTestServer starts an SSH listener with the given key-offer budget and
// PROXY trust list, whose every key lookup fails and is counted.
func proxyTestServer(t *testing.T, budget int, proxyFrom []string) (*SSHServer, *atomic.Int32) {
	t.Helper()
	cfg := config.Default()
	cfg.Limits.SSHKeyOffersPerMin = budget
	cfg.Git.SSHProxyProtocolCIDRs = proxyFrom
	h := &Handler{cfg: cfg, keyOffers: ratelimit.New(time.Hour), log: slog.Default()}
	t.Cleanup(func() { _ = h.keyOffers.Close() })
	srv, err := h.NewSSHServer("127.0.0.1:0", filepath.Join(t.TempDir(), "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	lookups := &atomic.Int32{}
	srv.resolveKey = func(context.Context, string) (*auth.Principal, error) {
		lookups.Add(1)
		return nil, errors.New("unknown key")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, lookups
}

// offerVia connects from the loopback address `from`, writes prefix (a
// PROXY header, or nothing), then offers one fresh key nobody registered.
// It reports whether the SSH handshake got as far as authentication.
func offerVia(t *testing.T, srv *SSHServer, from string, prefix []byte) (reachedAuth bool) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}}
	nc, err := d.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nc.Close() }()
	if len(prefix) > 0 {
		if _, err := nc.Write(prefix); err != nil {
			t.Fatal(err)
		}
	}
	var offered bool
	c, _, _, err := ssh.NewClientConn(nc, srv.Addr().String(), &ssh.ClientConfig{
		User: "git",
		Auth: []ssh.AuthMethod{ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			offered = true
			return []ssh.Signer{signer}, nil
		})},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test against an in-process server
		Timeout:         5 * time.Second,
	})
	if err == nil {
		_ = c.Close()
		t.Fatal("a key nobody registered was accepted")
	}
	return offered
}

// recordedLog is a log handler that keeps what it is given.
type recordedLog struct {
	mu    sync.Mutex
	lines []recordedLine
}

type recordedLine struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

func (*recordedLog) Enabled(context.Context, slog.Level) bool { return true }

func (l *recordedLog) Handle(_ context.Context, r slog.Record) error {
	line := recordedLine{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool {
		line.attrs[a.Key] = a.Value.String()
		return true
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
	return nil
}

func (l *recordedLog) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *recordedLog) WithGroup(string) slog.Handler      { return l }

// refusals are the connection refusals logged so far, in order.
func (l *recordedLog) refusals() []recordedLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []recordedLine
	for _, line := range l.lines {
		if line.msg == "git ssh connection refused" {
			out = append(out, line)
		}
	}
	return out
}

func proxyV1(src string) []byte {
	return []byte("PROXY TCP4 " + src + " 127.0.0.1 40000 22\r\n")
}

func TestSSHProxyHeaderFromATrustedPeerNamesTheClient(t *testing.T) {
	const budget = 2
	srv, lookups := proxyTestServer(t, budget, []string{"127.0.0.1"})

	// One client behind the proxy spends its own budget...
	for i := range budget {
		offerVia(t, srv, "127.0.0.1", proxyV1("203.0.113.9"))
		if n := lookups.Load(); n != int32(i+1) {
			t.Fatalf("offer %d: %d lookups, want %d", i+1, n, i+1)
		}
	}
	offerVia(t, srv, "127.0.0.1", proxyV1("203.0.113.9"))
	if n := lookups.Load(); n != budget {
		t.Fatalf("an offer past 203.0.113.9's budget cost a lookup: %d lookups", n)
	}
	// ...and not the next client's, though both arrive from the same peer.
	offerVia(t, srv, "127.0.0.1", proxyV1("203.0.113.10"))
	if n := lookups.Load(); n != budget+1 {
		t.Fatalf("a second client behind the same proxy was refused without a lookup: %d lookups, want %d", n, budget+1)
	}
	// v2 names the client too.
	offerVia(t, srv, "127.0.0.1", v2Header(1, 0x11, []byte{198, 51, 100, 7, 127, 0, 0, 1, 0x9c, 0x40, 0, 22}))
	if n := lookups.Load(); n != budget+2 {
		t.Fatalf("a v2 header's client was not looked up on its own budget: %d lookups, want %d", n, budget+2)
	}
}

func TestSSHProxyHeaderFromAnUntrustedPeerIsRefused(t *testing.T) {
	srv, lookups := proxyTestServer(t, 10, []string{"127.0.0.2"})
	rec := &recordedLog{}
	srv.h.log = slog.New(rec)
	if offerVia(t, srv, "127.0.0.1", proxyV1("203.0.113.9")) {
		t.Fatal("a connection from outside the trust list reached authentication")
	}
	if offerVia(t, srv, "127.0.0.1", nil) {
		t.Fatal("a direct connection reached authentication while the listener requires the proxy")
	}
	// A trusted peer that sends no header is refused as well.
	if offerVia(t, srv, "127.0.0.2", nil) {
		t.Fatal("a trusted peer without a PROXY header reached authentication")
	}
	if n := lookups.Load(); n != 0 {
		t.Fatalf("%d key lookups for connections that should have been refused", n)
	}
	// A stranger at the port is a debug line, since scanners would flood
	// anything louder; a listed proxy that sends no usable header is a
	// misconfiguration worth seeing. Each was logged before its connection
	// closed.
	refusals := rec.refusals()
	if len(refusals) != 3 {
		t.Fatalf("logged %d refusals, want 3", len(refusals))
	}
	for _, line := range refusals[:2] {
		if line.level != slog.LevelDebug || line.attrs["reason"] != "peer is not a trusted proxy" || !strings.HasPrefix(line.attrs["peer"], "127.0.0.1:") {
			t.Errorf("a peer outside the trust list: %v %v, want debug 'peer is not a trusted proxy'", line.level, line.attrs)
		}
	}
	if line := refusals[2]; line.level != slog.LevelInfo || !strings.Contains(line.attrs["reason"], "no PROXY protocol header") || !strings.HasPrefix(line.attrs["peer"], "127.0.0.2:") {
		t.Errorf("a trusted proxy with no header: %v %v, want info 'no PROXY protocol header'", line.level, line.attrs)
	}
	// The trusted peer with a header is served.
	if !offerVia(t, srv, "127.0.0.2", proxyV1("203.0.113.9")) || lookups.Load() != 1 {
		t.Fatalf("the trusted proxy's connection was not served (lookups %d)", lookups.Load())
	}
	// A header that names no client (the proxy's own health check) leaves the
	// peer as the client and is served.
	for _, health := range [][]byte{[]byte("PROXY UNKNOWN\r\n"), v2Header(0, 0x00, nil)} {
		before := lookups.Load()
		if !offerVia(t, srv, "127.0.0.2", health) || lookups.Load() != before+1 {
			t.Fatalf("a header naming no client was not served on the peer's own budget (lookups %d → %d)", before, lookups.Load())
		}
	}
}

// Off (the default), a header is never parsed: the budget stays the TCP
// peer's whatever address a header claims.
func TestSSHProxyHeaderIsIgnoredWhenOff(t *testing.T) {
	srv, lookups := proxyTestServer(t, 1, nil)
	offerVia(t, srv, "127.0.0.1", proxyV1("203.0.113.9"))
	offerVia(t, srv, "127.0.0.1", proxyV1("203.0.113.10"))
	if n := lookups.Load(); n != 1 {
		t.Fatalf("with the setting off, a header's address bought a fresh budget: %d lookups, want 1", n)
	}
}
