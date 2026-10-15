package api_test

// Browser mode for an organization's SSO. An org's IdP is a real door on the
// hosted product: the callback sets the session and returns the browser to
// where it was going, and a failure lands on the sign-in page with the
// reason, because a browser cannot read a problem document.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
)

// oidcBrowserEnv builds an organization whose OIDC connection points at a
// test IdP, with the asserting person already an active member.
func oidcBrowserEnv(t *testing.T) (*testEnv, *oidcEndpointIdP, string, *http.Client) {
	t.Helper()
	idp := newOIDCEndpointIdP(t)
	env := newTestEnvWith(t, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
	idp.email = "bro-person-" + env.sfx + "@acme.example"
	owner := env.register("bro-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "broorg" + env.sfx
	env.createOrg(sess, orgH)
	env.verifyOrgDomain(orgH, "acme.example")
	env.seedMembership(orgH, env.registerEmail("bro-person", idp.email), "member", "active")
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
		"enabled": true,
		"config":  map[string]any{"issuer": idp.srv.URL, "clientId": idp.clientID, "clientSecret": "shh"},
	}, nil, http.StatusOK)
	c := *env.srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return env, idp, orgH, &c
}

// startOIDC drives the start and the IdP, returning the callback URL and
// the sealed state cookie the callback needs.
func startOIDC(t *testing.T, env *testEnv, c *http.Client, orgH, next string) (string, *http.Cookie) {
	t.Helper()
	u := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/oidc/start"
	if next != "" {
		u += "?next=" + url.QueryEscape(next)
	}
	startResp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	_ = startResp.Body.Close()
	if startResp.StatusCode != http.StatusFound {
		t.Fatalf("start: got %d want 302", startResp.StatusCode)
	}
	var state *http.Cookie
	for _, ck := range startResp.Cookies() {
		if ck.Name == "agentry_oidc_state" {
			state = ck
		}
	}
	if state == nil {
		t.Fatal("start set no state cookie")
	}
	idpResp, err := c.Get(startResp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = idpResp.Body.Close()
	cb := idpResp.Header.Get("Location")
	if cb == "" {
		t.Fatalf("the IdP did not redirect to the callback (status %d)", idpResp.StatusCode)
	}
	return cb, state
}

func TestOrgOIDCBrowserModeReturnsToNext(t *testing.T) {
	env, _, orgH, c := oidcBrowserEnv(t)

	cb, state := startOIDC(t, env, c, orgH, "/orgs/"+orgH+"/admin")
	req, _ := http.NewRequest(http.MethodGet, cb, nil)
	req.AddCookie(state)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("browser-mode callback: got %d want 303", res.StatusCode)
	}
	if got := res.Header.Get("Location"); got != "/orgs/"+orgH+"/admin" {
		t.Fatalf("returned to %q, want the path the start carried", got)
	}
	var session, csrf string
	for _, ck := range res.Cookies() {
		switch ck.Name {
		case "agentry_session":
			session = ck.Value
		case "agentry_csrf":
			csrf = ck.Value
		}
	}
	if session == "" {
		t.Fatal("browser mode set no session cookie")
	}
	// The browser has no JSON body to read the CSRF token from, so it must
	// come as the cookie the web tier's double-submit reads.
	if csrf == "" {
		t.Fatal("browser mode set no CSRF cookie, so every mutation from the browser would be refused")
	}
	who := env.do(caller{name: "bro", session: session}, http.MethodGet, "/api/v1/user", nil)
	_ = who.Body.Close()
	if who.StatusCode != http.StatusOK {
		t.Fatalf("the browser-mode session: got %d want 200", who.StatusCode)
	}
}

// next is honoured only as a same-origin path. Anything that could send a
// person off this site is dropped and the flow falls back to API mode,
// which answers JSON rather than redirecting anywhere.
func TestOrgOIDCBrowserModeRefusesAnOffsiteNext(t *testing.T) {
	env, _, orgH, c := oidcBrowserEnv(t)

	for _, next := range []string{
		"https://evil.test/steal",
		"//evil.test/steal",
		"/\\evil.test",
		"evil.test",
		"/ok\nSet-Cookie: x=1",
	} {
		t.Run(next, func(t *testing.T) {
			cb, state := startOIDC(t, env, c, orgH, next)
			req, _ := http.NewRequest(http.MethodGet, cb, nil)
			req.AddCookie(state)
			res, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = res.Body.Close() }()
			if res.StatusCode == http.StatusSeeOther {
				t.Fatalf("next %q produced a redirect to %q", next, res.Header.Get("Location"))
			}
			if res.StatusCode != http.StatusOK {
				t.Fatalf("next %q: got %d, want the API-mode 200", next, res.StatusCode)
			}
		})
	}
}

// A failure in browser mode lands on the sign-in page carrying the reason,
// not on a problem document. The state is still pinned: a callback whose
// state does not match the sealed one is refused however it is dressed.
func TestOrgOIDCBrowserModeFailsToTheLoginPage(t *testing.T) {
	env, _, orgH, c := oidcBrowserEnv(t)

	cb, state := startOIDC(t, env, c, orgH, "/orgs/"+orgH+"/admin")
	tampered, err := url.Parse(cb)
	if err != nil {
		t.Fatal(err)
	}
	q := tampered.Query()
	q.Set("state", "not-the-sealed-one")
	tampered.RawQuery = q.Encode()

	req, _ := http.NewRequest(http.MethodGet, tampered.String(), nil)
	req.AddCookie(state)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("a browser-mode failure: got %d want 303 to the sign-in page", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "/login") || !strings.Contains(loc, "error=") {
		t.Fatalf("a browser-mode failure went to %q, want the sign-in page with the reason", loc)
	}
	for _, ck := range res.Cookies() {
		if ck.Name == "agentry_session" && ck.Value != "" {
			t.Fatal("a refused sign-in set a session cookie")
		}
	}
}

// Without next the callback answers JSON exactly as it did before, so an
// API client is unaffected by browser mode existing.
func TestOrgOIDCWithoutNextStillAnswersJSON(t *testing.T) {
	env, _, orgH, c := oidcBrowserEnv(t)

	cb, state := startOIDC(t, env, c, orgH, "")
	req, _ := http.NewRequest(http.MethodGet, cb, nil)
	req.AddCookie(state)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("API mode: got %d want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Fatalf("API mode answered %q", ct)
	}
}

// SAML's own way to carry where the browser was going is RelayState, and
// the IdP hands it back untouched, so it is the least trustworthy field in
// the exchange: a same-origin path is honoured, anything else is dropped
// and the flow falls back to API mode.
func TestSamlAcsBrowserModeUsesRelayState(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("sbro-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "sbroorg" + env.sfx
	env.createOrg(sess, orgH)
	env.verifyOrgDomain(orgH, "acme.example")

	idp := newSAMLTestIdP(t)
	metadataXML, err := samlsp.BuildIDPMetadataXML(idp.entityID, "https://acs-idp.test/sso", idp.certPEM)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/saml", map[string]any{
		"enabled": true,
		"config":  map[string]any{"idpMetadataXml": metadataXML, "emailAttribute": "email"},
	}, nil, http.StatusOK)

	metadataURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/metadata"
	acsURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/acs"
	nameID := "sbro-user-" + env.sfx + "@acme.example"
	env.seedMembership(orgH, env.registerEmail("sbro-member", nameID), "member", "active")

	// A same-origin RelayState: the session is set and the browser goes
	// back where it came from, with the CSRF cookie it will need.
	res := env.postForm(t, acsURL, url.Values{
		"SAMLResponse": {idp.signedResponse(t, metadataURL, acsURL, nameID, false)},
		"RelayState":   {"/orgs/" + orgH + "/admin"},
	})
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("browser-mode ACS: got %d want 303", res.StatusCode)
	}
	if got := res.Header.Get("Location"); got != "/orgs/"+orgH+"/admin" {
		t.Fatalf("returned to %q", got)
	}
	var session, csrf string
	for _, c := range res.Cookies() {
		switch c.Name {
		case "agentry_session":
			session = c.Value
		case "agentry_csrf":
			csrf = c.Value
		}
	}
	if session == "" || csrf == "" {
		t.Fatalf("browser-mode ACS set session=%t csrf=%t, want both", session != "", csrf != "")
	}

	// A failure in browser mode lands on the sign-in page too, not on a
	// problem document: an assertion the registry rejects is a 303
	// carrying the reason, and nothing is signed in.
	bad := env.postForm(t, acsURL, url.Values{
		"SAMLResponse": {idp.signedResponse(t, metadataURL, acsURL, "not-a-member-"+env.sfx+"@acme.example", false)},
		"RelayState":   {"/orgs/" + orgH + "/admin"},
	})
	defer func() { _ = bad.Body.Close() }()
	if bad.StatusCode != http.StatusSeeOther {
		t.Fatalf("a refused assertion in browser mode: got %d want 303", bad.StatusCode)
	}
	if loc := bad.Header.Get("Location"); !strings.Contains(loc, "/login") || !strings.Contains(loc, "error=") {
		t.Fatalf("a refused assertion went to %q, want the sign-in page with the reason", loc)
	}
	for _, c := range bad.Cookies() {
		if c.Name == "agentry_session" && c.Value != "" {
			t.Fatal("a refused assertion set a session cookie")
		}
	}

	// An off-site RelayState is dropped: the assertion still signs the
	// person in, and the answer is the JSON an API caller gets.
	off := env.postForm(t, acsURL, url.Values{
		"SAMLResponse": {idp.signedResponse(t, metadataURL, acsURL, nameID, false)},
		"RelayState":   {"https://evil.test/steal"},
	})
	defer func() { _ = off.Body.Close() }()
	if off.StatusCode != http.StatusOK {
		t.Fatalf("an off-site RelayState: got %d, want the API-mode 200 (Location %q)", off.StatusCode, off.Header.Get("Location"))
	}
}

// The nonce is pinned in browser mode exactly as it is in API mode: the
// sealed state holds the nonce the start generated, and an ID token
// carrying any other one is refused. Browser mode changes how a refusal is
// rendered, never whether one happens.
func TestOrgOIDCBrowserModePinsTheNonce(t *testing.T) {
	env, idp, orgH, c := oidcBrowserEnv(t)

	cb, state := startOIDC(t, env, c, orgH, "/orgs/"+orgH+"/admin")
	parsed, err := url.Parse(cb)
	if err != nil {
		t.Fatal(err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatal("the IdP issued no code")
	}
	// The IdP now mints an ID token for a different sign-in's nonce.
	idp.mu.Lock()
	idp.nonces[code] = "a-nonce-from-another-sign-in"
	idp.mu.Unlock()

	req, _ := http.NewRequest(http.MethodGet, cb, nil)
	req.AddCookie(state)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()

	for _, ck := range res.Cookies() {
		if ck.Name == "agentry_session" && ck.Value != "" {
			t.Fatal("a mismatched nonce established a session")
		}
	}
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("a mismatched nonce in browser mode: got %d want 303 to the sign-in page", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "/login") {
		t.Fatalf("a mismatched nonce went to %q", loc)
	}
}

// The landing is the entry point the product links to, so it is the one
// place that can put the round trip in browser mode: it carries next into
// the OIDC start, and it is shut with the rest while the tier has no SSO.
func TestSsoLandingCarriesNextIntoTheFlow(t *testing.T) {
	env, _, orgH, c := oidcBrowserEnv(t)

	res, err := c.Get(env.srv.URL + "/sso/" + orgH + "?next=" + url.QueryEscape("/orgs/"+orgH+"/admin"))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("the landing: got %d want 302", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "/sso/oidc/start") || !strings.Contains(loc, "next=") {
		t.Fatalf("the landing sent the browser to %q without carrying next", loc)
	}

	// An off-site next is dropped here too, before it reaches the flow.
	res, err = c.Get(env.srv.URL + "/sso/" + orgH + "?next=" + url.QueryEscape("https://evil.test/steal"))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if loc := res.Header.Get("Location"); strings.Contains(loc, "next=") {
		t.Fatalf("the landing carried an off-site next: %q", loc)
	}
}

// A return path long enough to push the sealed state past what a browser
// will store is dropped, so a link cannot deny someone their
// organization's sign-in.
func TestSsoNextIsBounded(t *testing.T) {
	env, _, orgH, c := oidcBrowserEnv(t)

	long := "/" + strings.Repeat("a", 4096)
	cb, state := startOIDC(t, env, c, orgH, long)
	req, _ := http.NewRequest(http.MethodGet, cb, nil)
	req.AddCookie(state)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	// Dropped, so the flow is API mode and still completes: the sign-in
	// works, it simply does not return anywhere.
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an over-long next: got %d, want the sign-in to complete in API mode", res.StatusCode)
	}
}
