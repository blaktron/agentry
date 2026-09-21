package api_test

import (
	"net/http"
	"testing"
)

// requireClearedCookie asserts that among a response's cookies the named
// one is cleared with the attributes it was set with: HttpOnly, SameSite
// and (when the server is configured for it) Secure. A clear that drops
// them is an empty cookie today and a leak the day a value lands in it
// (agentry#413).
func requireClearedCookie(t *testing.T, cookies []*http.Cookie, name string, secure bool) {
	t.Helper()
	for _, c := range cookies {
		if c.Name != name {
			continue
		}
		if c.Value != "" || c.MaxAge >= 0 {
			t.Fatalf("%s was not cleared: value %q, max-age %d", name, c.Value, c.MaxAge)
		}
		if !c.HttpOnly || c.SameSite == http.SameSiteDefaultMode || c.Secure != secure {
			t.Fatalf("%s cleared without its attributes: HttpOnly=%v SameSite=%v Secure=%v (want Secure=%v)", name, c.HttpOnly, c.SameSite, c.Secure, secure)
		}
		return
	}
	t.Fatalf("no Set-Cookie clearing %s", name)
}
