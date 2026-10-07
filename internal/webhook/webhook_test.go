package webhook

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
