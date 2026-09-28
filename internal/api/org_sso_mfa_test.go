package api_test

// An organization's own SSO is second-factor evidence for the public-publish
// gate when its signed assertion says a second factor was used (agentry#705,
// the organization counterpart of agentry#23): a SAML AuthnContextClassRef or
// Entra ID's authnmethodsreferences attribute naming multi-factor, an OIDC
// ID token whose `amr` names a factor. It counts only on a deployment that
// accepts IdP-asserted evidence (auth.requireIdpMFA): an organization's IdP
// is its admins', and the stamp is account-wide, so on a registry whose gate
// asks for native TOTP an organization cannot stand in for it. A password-only
// sign-in, and a refused one, stamp nothing.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
	"github.com/blaktron/agentry/internal/config"
)

const refedsMFA = "https://refeds.org/profile/mfa"

func idpMFAStamped(t *testing.T, env *testEnv, email string) bool {
	t.Helper()
	var stamped bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT idp_mfa_at IS NOT NULL FROM users WHERE email = $1`, email).Scan(&stamped); err != nil {
		t.Fatal(err)
	}
	return stamped
}

// ssoLoginDetail is the sso.login audit row's detail for the account at email.
func ssoLoginDetail(t *testing.T, env *testEnv, email string) map[string]any {
	t.Helper()
	var raw []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT a.detail FROM audit_events a JOIN users u ON a.target_id = u.id
		  WHERE a.action = 'sso.login' AND u.email = $1 ORDER BY a.occurred_at DESC LIMIT 1`, email).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func requireIdPMFA(on bool) func(*config.Config) {
	return func(c *config.Config) { c.Auth.RequireIdPMFA = on }
}

func TestOrgSAMLSignInRecordsIdPMFA(t *testing.T) {
	const password = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	entraMFA := map[string][]string{"http://schemas.microsoft.com/claims/authnmethodsreferences": {"http://schemas.microsoft.com/claims/multipleauthn"}}
	for _, tc := range []struct {
		name      string
		optIn     bool
		context   string
		attrs     map[string][]string
		member    bool
		wantCode  int
		wantStamp bool
	}{
		{"password context", true, password, nil, true, http.StatusOK, false},
		{"REFEDS MFA context", true, refedsMFA, nil, true, http.StatusOK, true},
		{"Entra: password context, multipleauthn in the methods attribute", true, "urn:oasis:names:tc:SAML:2.0:ac:classes:Password", entraMFA, true, http.StatusOK, true},
		{"MFA context on a registry that has not opted in", false, refedsMFA, nil, true, http.StatusOK, false},
		{"MFA context for an account that is not a member", true, refedsMFA, nil, false, http.StatusForbidden, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnvCfg(t, requireIdPMFA(tc.optIn))
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
			person := env.registerEmail("samlmfa-person", email)
			if tc.member {
				env.seedMembership(orgH, person, "member", "active")
			}
			res := env.postForm(t, acsURL, url.Values{"SAMLResponse": {idp.signedResponse(t, metadataURL, acsURL, email, false)}})
			_ = res.Body.Close()
			if res.StatusCode != tc.wantCode {
				t.Fatalf("ACS: got %d want %d", res.StatusCode, tc.wantCode)
			}
			if got := idpMFAStamped(t, env, email); got != tc.wantStamp {
				t.Fatalf("idp_mfa_at set = %v, want %v", got, tc.wantStamp)
			}
			if tc.wantCode == http.StatusOK {
				d := ssoLoginDetail(t, env, email)
				if d["mfaRecorded"] != tc.wantStamp || d["mfaAsserted"] != (tc.context == refedsMFA || tc.attrs != nil) {
					t.Fatalf("sso.login detail = %v", d)
				}
			}
		})
	}
}

func TestOrgOIDCSignInRecordsIdPMFA(t *testing.T) {
	for _, tc := range []struct {
		name      string
		optIn     bool
		amr       []string
		wantStamp bool
	}{
		{"no amr", true, nil, false},
		{"password only", true, []string{"pwd"}, false},
		{"password and mfa", true, []string{"pwd", "mfa"}, true},
		{"password and mfa on a registry that has not opted in", false, []string{"pwd", "mfa"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newOIDCEndpointIdP(t)
			idp.amr = tc.amr
			env := newTestEnvCfg(t, requireIdPMFA(tc.optIn), func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
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

			c := *env.srv.Client()
			c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			cbURL, state := startOIDC(t, env, &c, orgH, "")
			cb, _ := http.NewRequest(http.MethodGet, cbURL, nil)
			cb.AddCookie(state)
			res, err := c.Do(cb)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("callback: got %d want 200", res.StatusCode)
			}
			if got := idpMFAStamped(t, env, idp.email); got != tc.wantStamp {
				t.Fatalf("amr=%v: idp_mfa_at set = %v, want %v", tc.amr, got, tc.wantStamp)
			}
		})
	}
}
