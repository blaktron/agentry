package api_test

import (
	"net/http"
	"testing"
)

// requireClearedCookie asserts that among a response's cookies the named
// one is cleared with the attributes it was set with: the path it applies
// to, HttpOnly, SameSite Lax and (when the server is configured for it)
// Secure. A clear that drops them is an empty cookie today and a leak the
// day a value lands in it.
func requireClearedCookie(t *testing.T, cookies []*http.Cookie, name string, secure bool) {
	t.Helper()
	for _, c := range cookies {
		if c.Name != name {
			continue
		}
		if c.Value != "" || c.MaxAge >= 0 {
			t.Fatalf("%s was not cleared: value %q, max-age %d", name, c.Value, c.MaxAge)
		}
		if c.Path != "/" {
			t.Fatalf("%s cleared at path %q, not the path it was set at", name, c.Path)
		}
		if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure != secure {
			t.Fatalf("%s cleared without its attributes: HttpOnly=%v SameSite=%v Secure=%v (want Secure=%v)", name, c.HttpOnly, c.SameSite, c.Secure, secure)
		}
		return
	}
	t.Fatalf("no Set-Cookie clearing %s", name)
}

// requireNoCookie asserts the response issued no cookie of this name: a
// sign-in that did not ask for a remembered browser must not get one, and
// the server sets no remembered-browser cookie of its own.
//
//nolint:unparam // every caller passes the trusted-device cookie
func requireNoCookie(t *testing.T, cookies []*http.Cookie, name string) {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			t.Fatalf("%s was issued when it should not have been (value %q, max-age %d)", name, c.Value, c.MaxAge)
		}
	}
}
