package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestGuard_IsAllowedIP(t *testing.T) {
	g := Guard{} // strict (production)
	cases := []struct {
		ip      string
		allowed bool
	}{
		{"8.8.8.8", true},              // public v4
		{"1.1.1.1", true},              // public v4
		{"2606:4700:4700::1111", true}, // public v6
		{"127.0.0.1", false},           // loopback
		{"::1", false},                 // loopback v6
		{"10.0.0.1", false},            // RFC1918
		{"172.16.5.4", false},          // RFC1918
		{"172.32.0.1", true},           // just outside 172.16/12
		{"192.168.1.1", false},         // RFC1918
		{"169.254.169.254", false},     // link-local / cloud metadata
		{"169.254.1.1", false},         // link-local
		{"fc00::1", false},             // ULA v6
		{"fe80::1", false},             // link-local v6
		{"100.64.0.1", false},          // CGNAT
		{"0.0.0.0", false},             // unspecified
		{"0.1.2.3", false},             // 0.0.0.0/8: Linux routes the whole /8 to lo
		{"0.255.255.255", false},       // 0.0.0.0/8, top of the range
		{"::ffff:0.1.2.3", false},      // v4-mapped 0/8
		{"224.0.0.1", false},           // multicast
		{"::ffff:10.0.0.1", false},     // v4-mapped private
		{"::", false},                  // unspecified v6
		{"2002:7f00:1::1", false},      // 6to4 embedding 127.0.0.1
		{"2002:0a00:1::1", false},      // 6to4 embedding 10.0.0.1
		{"2002:0001:0203::1", false},   // 6to4 embedding 0.1.2.3
		{"2002:0808:0808::1", true},    // 6to4 embedding 8.8.8.8 stays public
		{"64:ff9b::a00:1", false},      // NAT64 well-known prefix embedding 10.0.0.1
		{"64:ff9b::7f00:1", false},     // NAT64 embedding 127.0.0.1
		{"64:ff9b::808:808", true},     // NAT64 embedding 8.8.8.8 stays public
		{"64:ff9b:1::a00:1", false},    // NAT64 local-use prefix (RFC 8215) is never public
		{"::a00:1", false},             // deprecated IPv4-compatible form of 10.0.0.1
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := g.IsAllowedIP(ip); got != c.allowed {
			t.Errorf("IsAllowedIP(%s) = %v, want %v", c.ip, got, c.allowed)
		}
	}
}

func TestGuard_LoopbackSeam(t *testing.T) {
	if (Guard{}).IsAllowedIP(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("strict guard must block loopback")
	}
	if !(Guard{AllowLoopback: true}).IsAllowedIP(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("test seam should allow loopback")
	}
	// Even with loopback allowed, private/metadata stay blocked.
	if (Guard{AllowLoopback: true}).IsAllowedIP(netip.MustParseAddr("169.254.169.254")) {
		t.Fatal("metadata IP must stay blocked even with loopback seam")
	}
}

func TestGuard_DialBlocksNonPublic(t *testing.T) {
	g := Guard{}
	for _, addr := range []string{"10.0.0.1:443", "169.254.169.254:80", "127.0.0.1:443", "[::1]:443"} {
		if _, err := g.dialContext(context.Background(), "tcp", addr); err == nil {
			t.Errorf("dial %s should be blocked", addr)
		}
	}
}

// TestGuard_DialPinsTheResolvedAddress exercises the resolve-then-check-then-pin
// half of dialContext against a resolver the test controls: the "DNS rebinding
// defeated" claim of ARCHITECTURE §9 is that a hostname's answer is checked
// per candidate and the dial goes to the checked literal, never back through
// DNS. A public-looking name that resolves to a private address is refused
// before any connection; padding the answer with one public address does not
// help; and when every candidate clears, the dial reaches the first one.
func TestGuard_DialPinsTheResolvedAddress(t *testing.T) {
	answers := map[string][]netip.Addr{
		"private.example":   {netip.MustParseAddr("10.0.0.1")},
		"padded.example":    {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("169.254.169.254")},
		"zeronet.example":   {netip.MustParseAddr("0.1.2.3")},
		"sixtofour.example": {netip.MustParseAddr("2002:7f00:1::1")},
	}
	g := Guard{LookupNetIP: func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := answers[host]; ok {
			return a, nil
		}
		t.Fatalf("unexpected lookup %q", host)
		return nil, nil
	}}
	for host := range answers {
		_, err := g.dialContext(context.Background(), "tcp", host+":443")
		var blocked *ErrBlockedAddress
		if !errors.As(err, &blocked) {
			t.Errorf("dial %s: err = %v, want ErrBlockedAddress", host, err)
			continue
		}
		if blocked.Host != host {
			t.Errorf("dial %s: blocked host = %q", host, blocked.Host)
		}
	}

	// Every candidate public: the dial goes to the first checked literal. A
	// loopback httptest listener stands in for it through the test seam, and
	// the resolver answers a name the listener never registered — proof the
	// connect used the literal, not a second lookup.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	lis := netip.MustParseAddrPort(ts.Listener.Addr().String())
	pinned := Guard{AllowLoopback: true, LookupNetIP: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{lis.Addr()}, nil
	}}
	conn, err := pinned.dialContext(context.Background(), "tcp", fmt.Sprintf("pinned.example:%d", lis.Port()))
	if err != nil {
		t.Fatalf("dial through the pinned literal: %v", err)
	}
	_ = conn.Close()
}

func TestClient_NoRedirectFollowing(t *testing.T) {
	// A server that 302-redirects. The guarded client must NOT follow it.
	redirected := false
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirected = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer ts.Close()

	client := NewHTTPClient(Guard{AllowLoopback: true}, tlsTrusting(ts))
	resp, err := client.Get(ts.URL + "/start")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (not followed), got %d", resp.StatusCode)
	}
	if redirected {
		t.Fatal("client followed the redirect (T-08 violation)")
	}
}

func TestSign_And_Verify(t *testing.T) {
	secret := []byte("whsec_topsecret")
	body := []byte(`{"event":"version.published","id":"abc"}`)
	now := time.Now()
	header := Sign(secret, body, now)
	if header == "" || header[:2] != "t=" {
		t.Fatalf("bad header format: %q", header)
	}
	if err := Verify(secret, body, header, now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Wrong secret.
	if err := Verify([]byte("other"), body, header, now); err == nil {
		t.Fatal("wrong secret must fail")
	}
	// Tampered body.
	if err := Verify(secret, []byte(`{"event":"x"}`), header, now); err == nil {
		t.Fatal("tampered body must fail")
	}
	// Stale timestamp (outside ±5min).
	if err := Verify(secret, body, header, now.Add(10*time.Minute)); err == nil {
		t.Fatal("stale timestamp must fail")
	}
}

// tlsTrusting returns a TLS config trusting an httptest TLS server's cert.
func tlsTrusting(ts *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
