package gitsrv

// White-box: the SSH listener's per-source budget on public-key offers sits
// in front of the key lookup, so a stranger cycling through keys costs the
// database nothing past the budget (§19, agentry#410). The lookup is the
// boundary faked here; the wire is the real one.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/ratelimit"
)

func TestSSHKeyOffersAreBudgetedPerSourceBeforeTheLookup(t *testing.T) {
	const budget = 3
	cfg := config.Default()
	cfg.Limits.SSHKeyOffersPerMin = budget
	h := &Handler{cfg: cfg, keyOffers: ratelimit.New(time.Hour), log: slog.Default()}
	t.Cleanup(func() { _ = h.keyOffers.Close() })
	srv, err := h.NewSSHServer("127.0.0.1:0", filepath.Join(t.TempDir(), "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	var lookups atomic.Int32
	srv.resolveKey = func(context.Context, string) (*auth.Principal, error) {
		lookups.Add(1)
		return nil, errors.New("unknown key")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })

	// offer connects from the given loopback address with a fresh key
	// nobody registered; the dial must fail either way, and whether it
	// cost a lookup is the test.
	offer := func(from string) {
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
		c, _, _, err := ssh.NewClientConn(nc, srv.Addr().String(), &ssh.ClientConfig{
			User:            "git",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test against an in-process server
			Timeout:         5 * time.Second,
		})
		if err == nil {
			_ = c.Close()
			t.Fatal("a key nobody registered was accepted")
		}
	}

	for i := range budget {
		offer("127.0.0.1")
		if n := lookups.Load(); n != int32(i+1) {
			t.Fatalf("offer %d: %d lookups, want %d (one per offer within the budget)", i+1, n, i+1)
		}
	}
	offer("127.0.0.1")
	if n := lookups.Load(); n != budget {
		t.Fatalf("offer %d past a budget of %d cost a lookup: %d lookups", budget+1, budget, n)
	}
	// The budget is the address's, not the listener's: another source is
	// still looked up.
	offer("127.0.0.2")
	if n := lookups.Load(); n != budget+1 {
		t.Fatalf("an offer from a second address was refused without a lookup: %d lookups, want %d", n, budget+1)
	}
}
