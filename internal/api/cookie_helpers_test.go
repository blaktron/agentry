package api_test

import (
	"net/http"
	"testing"
)

// requireClearedCookie asserts that among a response's cookies the named
// one is cleared with the attributes it was set with: HttpOnly, SameSite
// and (when the server is configured for it) Secure. A clear that drops
// them is an empty cookie today and a leak the day a value lands in it.
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

// requireClearedCookieAt is requireClearedCookie for the Set-Cookie with this
// exact path and domain: a clear that names another path or domain is, to a
// browser, a different cookie, and clears nothing.
func requireClearedCookieAt(t *testing.T, cookies []*http.Cookie, name, path, domain string, secure bool) {
	t.Helper()
	var at []*http.Cookie
	for _, c := range cookies {
		if c.Name == name && c.Path == path && c.Domain == domain {
			at = append(at, c)
		}
	}
	if len(at) == 0 {
		t.Fatalf("no Set-Cookie clearing %s at Path=%q Domain=%q", name, path, domain)
	}
	requireClearedCookie(t, at, name, secure)
}

// requireSetCookie asserts that among a response's cookies the named one is
// issued with the attributes this server sets every cookie with, and a Max-Age
// equal to wantMaxAge. It returns the cookie so a caller can assert on its
// value too.
//
// This is requireClearedCookie's twin, and the pair is what makes the
// rule checkable: a cookie must be cleared with the attributes it was set
// with, which is only provable if both directions are assertable. Without
// it, a cookie issued without HttpOnly (auth material readable by browser
// JavaScript, which is forbidden) would pass every test in the package.
func requireSetCookie(t *testing.T, cookies []*http.Cookie, name string, wantMaxAge int, secure bool) *http.Cookie {
	t.Helper()
	return requireSetCookieAt(t, cookies, name, "/", "", wantMaxAge, secure)
}

// requireSetCookieAt is requireSetCookie for a cookie scoped to a path and a
// domain. wantDomain "" means host-only.
func requireSetCookieAt(t *testing.T, cookies []*http.Cookie, name, wantPath, wantDomain string, wantMaxAge int, secure bool) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name != name {
			continue
		}
		if c.Value == "" {
			t.Fatalf("%s was issued empty", name)
		}
		if !c.HttpOnly {
			t.Fatalf("%s issued without HttpOnly: readable by browser JavaScript, which is forbidden for auth material", name)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Fatalf("%s issued with SameSite=%v, want Lax", name, c.SameSite)
		}
		if c.Path != wantPath {
			t.Fatalf("%s issued with Path=%q, want %q: it must reach exactly where it is read", name, c.Path, wantPath)
		}
		if c.Domain != wantDomain {
			t.Fatalf("%s issued with Domain=%q, want %q", name, c.Domain, wantDomain)
		}
		if c.Secure != secure {
			t.Fatalf("%s issued with Secure=%v, want %v (the server's cookieSecure setting)", name, c.Secure, secure)
		}
		if c.MaxAge != wantMaxAge {
			t.Fatalf("%s issued with Max-Age=%d, want %d", name, c.MaxAge, wantMaxAge)
		}
		return c
	}
	t.Fatalf("no Set-Cookie issuing %s", name)
	return nil
}

// requireNoCookie asserts the response issued no cookie of this name. It is the
// negative half of requireSetCookie, and the one that proves an opt-in really
// defaults to off: a sign-in that did not ask to be remembered must not be
// remembered anyway, and a sign-in that skipped the second factor must not
// silently extend the trust it used.
//
// The name parameter takes the cookie's name so that all three helpers read as
// one family at the call site. Every caller passes the trusted-device
// cookie.
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
