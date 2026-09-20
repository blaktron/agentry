package api_test

// Browser mode for an organization's SSO (agentry#365, M13; plan
// organization-subscriptions.md §5.7). An org's IdP is a real door on the
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
func oidcBrowserEnv(t *testing.T) (*testEnv, string, *http.Client) {
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
	return env, orgH, &c
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
	env, orgH, c := oidcBrowserEnv(t)

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
	// come as the cookie the web tier's double-submit reads (agentry#77).
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
	env, orgH, c := oidcBrowserEnv(t)

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
	env, orgH, c := oidcBrowserEnv(t)

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
	env, orgH, c := oidcBrowserEnv(t)

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
