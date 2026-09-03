package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
)

// POST /orgs/{org}/sso/connections/{kind}/test probes a stored connection
// without a sign-in (agentry#50): OIDC discovery, SAML metadata facts.
func TestSsoConnectionProbe(t *testing.T) {
	idp := newOIDCEndpointIdP(t)
	env := newTestEnvWith(t, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
	owner := env.register("probe-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "probeorg" + env.sfx
	env.createOrg(sess, orgH)

	type probe struct {
		Ok       bool              `json:"ok"`
		Kind     string            `json:"kind"`
		Summary  string            `json:"summary"`
		Details  map[string]string `json:"details"`
		Warnings []string          `json:"warnings"`
	}

	// Nothing configured yet: a 200 with ok=false, not an error page.
	var none probe
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/sso/connections/oidc/test", nil, &none, http.StatusOK)
	if none.Ok || !strings.Contains(none.Summary, "no oidc connection") {
		t.Fatalf("unconfigured: %+v", none)
	}

	// OIDC: discovery against the fake issuer succeeds and reports endpoints.
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
		"enabled": false,
		"config":  map[string]any{"issuer": idp.srv.URL, "clientId": idp.clientID, "clientSecret": "shh"},
	}, nil, http.StatusOK)
	var o probe
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/sso/connections/oidc/test", nil, &o, http.StatusOK)
	if !o.Ok || o.Details["issuer"] != idp.srv.URL || o.Details["authorizationEndpoint"] == "" || o.Details["tokenEndpoint"] == "" || !strings.Contains(o.Details["redirectUri"], "/sso/oidc/callback") {
		t.Fatalf("oidc probe: %+v", o)
	}

	// OIDC with an unreachable issuer: ok=false with the reason.
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
		"enabled": false,
		"config":  map[string]any{"issuer": "https://idp.invalid", "clientId": "x", "clientSecret": "shh"},
	}, nil, http.StatusOK)
	var bad probe
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/sso/connections/oidc/test", nil, &bad, http.StatusOK)
	if bad.Ok || !strings.Contains(bad.Summary, "discovery against https://idp.invalid failed") {
		t.Fatalf("unreachable issuer: %+v", bad)
	}

	// SAML: entity id, sign-on URL, certificate facts from stored metadata.
	sidp := newSAMLTestIdP(t)
	metadataXML, err := samlsp.BuildIDPMetadataXML(sidp.entityID, "https://acs-idp.test/sso", sidp.certPEM)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/saml", map[string]any{
		"enabled": false,
		"config":  map[string]any{"idpMetadataXml": metadataXML, "emailAttribute": "email"},
	}, nil, http.StatusOK)
	var sm probe
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/sso/connections/saml/test", nil, &sm, http.StatusOK)
	if !sm.Ok || sm.Details["entityId"] != sidp.entityID || sm.Details["ssoUrl"] != "https://acs-idp.test/sso" || sm.Details["certificates"] != "1" || sm.Details["certExpires"] == "" {
		t.Fatalf("saml probe: %+v", sm)
	}

	// Owner-only: a member cannot probe.
	member := env.register("probe-member")
	env.verifyEmail(member)
	msess := env.login(member)
	env.doJSON(msess, http.MethodPost, "/api/v1/orgs/"+orgH+"/sso/connections/saml/test", nil, nil, http.StatusForbidden)
}
