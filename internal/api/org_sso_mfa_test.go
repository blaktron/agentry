package api_test

// An organization's own SSO is second-factor evidence for the public-publish
// gate when its signed assertion says a second factor was used (agentry#705,
// the organization counterpart of agentry#23): a SAML AuthnContextClassRef or
// Entra ID's authnmethodsreferences attribute naming multi-factor, an OIDC
// ID token whose `amr` names a factor. A password-only sign-in stamps nothing.

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
)

func idpMFAStamped(t *testing.T, env *testEnv, email string) bool {
	t.Helper()
	var stamped bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT idp_mfa_at IS NOT NULL FROM users WHERE email = $1`, email).Scan(&stamped); err != nil {
		t.Fatal(err)
	}
	return stamped
}

func TestOrgSAMLSignInRecordsIdPMFA(t *testing.T) {
	for _, tc := range []struct {
		name    string
		context string
		attrs   map[string][]string
		want    bool
	}{
		{"password context", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", nil, false},
		{"REFEDS MFA context", "https://refeds.org/profile/mfa", nil, true},
		{"Entra: password context, multipleauthn in the methods attribute", "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
			map[string][]string{"http://schemas.microsoft.com/claims/authnmethodsreferences": {"http://schemas.microsoft.com/claims/multipleauthn"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			owner := env.register("samlmfa-owner")
			env.verifyEmail(owner)
			sess := env.login(owner)
			orgH := "samlmfa" + env.sfx
			env.createOrg(sess, orgH)
			env.verifyOrgDomain(orgH, "acme.example")
			idp := newSAMLTestIdP(t)
			idp.authnContext, idp.attrs = tc.context, tc.attrs
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

			email := "samlmfa-" + env.sfx + "@acme.example"
			env.seedMembership(orgH, env.registerEmail("samlmfa-member", email), "member", "active")
			res := env.postForm(t, acsURL, url.Values{"SAMLResponse": {idp.signedResponse(t, metadataURL, acsURL, email, false)}})
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("ACS: got %d want 200", res.StatusCode)
			}
			if got := idpMFAStamped(t, env, email); got != tc.want {
				t.Fatalf("idp_mfa_at set = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOrgOIDCSignInRecordsIdPMFA(t *testing.T) {
	for _, tc := range []struct {
		name string
		amr  []string
		want bool
	}{
		{"no amr", nil, false},
		{"password only", []string{"pwd"}, false},
		{"password and mfa", []string{"pwd", "mfa"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newOIDCEndpointIdP(t)
			idp.amr = tc.amr
			env := newTestEnvWith(t, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
			idp.email = "oidcmfa-" + env.sfx + "@acme.example"
			owner := env.register("oidcmfa-owner")
			env.verifyEmail(owner)
			sess := env.login(owner)
			orgH := "oidcmfa" + env.sfx
			env.createOrg(sess, orgH)
			env.verifyOrgDomain(orgH, "acme.example")
			env.seedMembership(orgH, env.registerEmail("oidcmfa-person", idp.email), "member", "active")
			env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
				"enabled": true,
				"config":  map[string]any{"issuer": idp.srv.URL, "clientId": idp.clientID, "clientSecret": "shh"},
			}, nil, http.StatusOK)

			noRedirect := *env.srv.Client()
			noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			start, err := noRedirect.Get(env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/oidc/start")
			if err != nil {
				t.Fatal(err)
			}
			_ = start.Body.Close()
			var state *http.Cookie
			for _, c := range start.Cookies() {
				if c.Name == "agentry_oidc_state" {
					state = c
				}
			}
			visit, err := noRedirect.Get(start.Header.Get("Location"))
			if err != nil || state == nil {
				t.Fatalf("start/authorize: %v (state cookie %v)", err, state != nil)
			}
			_ = visit.Body.Close()
			cb, _ := http.NewRequest(http.MethodGet, visit.Header.Get("Location"), nil)
			cb.AddCookie(state)
			res, err := noRedirect.Do(cb)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("callback: got %d want 200", res.StatusCode)
			}
			if got := idpMFAStamped(t, env, idp.email); got != tc.want {
				t.Fatalf("amr=%v: idp_mfa_at set = %v, want %v", tc.amr, got, tc.want)
			}
		})
	}
}
