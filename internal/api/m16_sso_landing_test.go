package api_test

// The §12.4 org SSO landing (`https://…/sso/{org}`) and the SP-initiated SAML
// flow it starts. Until M-16 the SP only consumed assertions: an employee had
// to begin at their IdP's app portal, because agentry never issued an
// AuthnRequest.

import (
	"compress/flate"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	samlsp "github.com/PLACEHOLDER_ORG/agentry/internal/auth/saml"
)

var reAuthnRequestID = regexp.MustCompile(`\bID="([^"]+)"`)

// authnRequestID decodes a redirect-binding SAMLRequest and returns its ID.
func authnRequestID(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	raw := u.Query().Get("SAMLRequest")
	if raw == "" {
		t.Fatalf("redirect carries no SAMLRequest: %s", location)
	}
	deflated, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("SAMLRequest is not base64: %v", err)
	}
	xmlBytes, err := io.ReadAll(flate.NewReader(strings.NewReader(string(deflated))))
	if err != nil {
		t.Fatalf("SAMLRequest is not deflate-compressed: %v", err)
	}
	m := reAuthnRequestID.FindSubmatch(xmlBytes)
	if m == nil {
		t.Fatalf("AuthnRequest has no ID: %s", xmlBytes)
	}
	return string(m[1])
}

// getNoRedirect fetches a URL without following redirects.
func (env *testEnv) getNoRedirect(t *testing.T, path string) *http.Response {
	t.Helper()
	client := *env.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Get(env.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestSSOLandingStartsSPInitiatedSAML(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("spi-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "spiorg" + env.sfx
	env.createOrg(sess, orgH)

	idp := newSAMLTestIdP(t)
	metadataXML, err := samlsp.BuildIDPMetadataXML(idp.entityID, "https://acs-idp.test/sso", idp.certPEM)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/saml", map[string]any{
		"enabled": true,
		"config":  map[string]any{"idpMetadataXml": metadataXML, "emailAttribute": "email"},
	}, nil, http.StatusOK)

	// The landing endpoint redirects to the IdP with a real AuthnRequest.
	res := env.getNoRedirect(t, "/sso/"+orgH)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("/sso/%s: got %d want 302", orgH, res.StatusCode)
	}
	location := res.Header.Get("Location")
	if !strings.HasPrefix(location, "https://acs-idp.test/sso") {
		t.Fatalf("landing redirect goes to %q, not the IdP SSO endpoint", location)
	}
	requestID := authnRequestID(t, location)

	metadataURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/metadata"
	acsURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/acs"
	nameID := "spi-user-" + env.sfx + "@acme.example"

	// An assertion naming a DIFFERENT request is refused, even though it is
	// correctly signed, addressed and in-window: that is the response-stealing
	// case crewjam skips checking whenever IdP-initiated logins are allowed.
	stolen := idp.signedResponseFor(t, metadataURL, acsURL, nameID, "_id_we_never_issued", false)
	bad := env.postForm(t, acsURL, url.Values{"SAMLResponse": {stolen}})
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("assertion with a foreign InResponseTo: got %d want 401", bad.StatusCode)
	}

	// The assertion answering OUR request is accepted.
	good := idp.signedResponseFor(t, metadataURL, acsURL, nameID, requestID, false)
	ok := env.postForm(t, acsURL, url.Values{"SAMLResponse": {good}})
	defer func() { _ = ok.Body.Close() }()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("SP-initiated assertion: got %d want 200", ok.StatusCode)
	}
	session := ""
	for _, c := range ok.Cookies() {
		if c.Name == "agentry_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("SP-initiated login set no session cookie")
	}

	// The request id is single use: replaying the exchange must fail.
	replay := idp.signedResponseFor(t, metadataURL, acsURL, nameID, requestID, false)
	again := env.postForm(t, acsURL, url.Values{"SAMLResponse": {replay}})
	_ = again.Body.Close()
	if again.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reusing a consumed AuthnRequest: got %d want 401", again.StatusCode)
	}

	// IdP-initiated (no InResponseTo at all) stays supported (§12.4).
	idpInit := idp.signedResponse(t, metadataURL, acsURL, nameID, false)
	init := env.postForm(t, acsURL, url.Values{"SAMLResponse": {idpInit}})
	_ = init.Body.Close()
	if init.StatusCode != http.StatusOK {
		t.Fatalf("IdP-initiated assertion: got %d want 200", init.StatusCode)
	}
}

func TestSSOLandingFallsBackToOIDCAndRefusesUnconfigured(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("spi-oid")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "spioorg" + env.sfx
	env.createOrg(sess, orgH)

	// No connection at all: 404, so the landing URL cannot be used to
	// enumerate which orgs have SSO.
	res := env.getNoRedirect(t, "/sso/"+orgH)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("landing with no SSO: got %d want 404", res.StatusCode)
	}

	// An OIDC-only org lands on the OIDC start endpoint.
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
		"enabled": true,
		"config":  map[string]any{"issuer": "https://idp.example", "clientId": "abc"},
	}, nil, http.StatusOK)
	res = env.getNoRedirect(t, "/sso/"+orgH)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("OIDC landing: got %d want 302", res.StatusCode)
	}
	if want := "/api/v1/orgs/" + orgH + "/sso/oidc/start"; res.Header.Get("Location") != want {
		t.Fatalf("OIDC landing redirect = %q, want %q", res.Header.Get("Location"), want)
	}

	// An unknown org is a 404, not a 500.
	res2 := env.getNoRedirect(t, "/sso/nosuchorg"+env.sfx)
	_ = res2.Body.Close()
	if res2.StatusCode != http.StatusNotFound {
		t.Fatalf("landing for an unknown org: got %d want 404", res2.StatusCode)
	}
	// A handle that cannot exist under the §4.2 grammar is rejected too.
	res3 := env.getNoRedirect(t, "/sso/NOT_A_HANDLE")
	_ = res3.Body.Close()
	if res3.StatusCode != http.StatusNotFound {
		t.Fatalf("landing for an invalid handle: got %d want 404", res3.StatusCode)
	}
}
