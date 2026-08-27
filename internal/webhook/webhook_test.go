package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
		{"224.0.0.1", false},           // multicast
		{"::ffff:10.0.0.1", false},     // v4-mapped private
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
