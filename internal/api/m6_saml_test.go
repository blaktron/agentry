package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/blaktron/agentry/internal/api"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
)

// samlTestIdP is an in-process signing IdP for the ACS endpoint test.
type samlTestIdP struct {
	entityID string
	key      *rsa.PrivateKey
	certDER  []byte
	certPEM  string
}

func newSAMLTestIdP(t *testing.T) *samlTestIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "acs-test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &samlTestIdP{
		entityID: "https://acs-idp.test/metadata", key: key, certDER: der,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

func (k *samlTestIdP) GetKeyPair() (*rsa.PrivateKey, []byte, error) { return k.key, k.certDER, nil }

func (k *samlTestIdP) signedResponse(t *testing.T, audience, recipient, nameID string, tamper bool) string {
	return k.signedResponseFor(t, audience, recipient, nameID, "", tamper)
}

// signedResponseFor additionally sets InResponseTo, marking the assertion as
// the answer to an SP-initiated AuthnRequest (§12.4).
func (k *samlTestIdP) signedResponseFor(t *testing.T, audience, recipient, nameID, inResponseTo string, tamper bool) string {
	t.Helper()
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	resp.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	resp.CreateAttr("ID", "_r"+randHex())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	resp.CreateAttr("Destination", recipient)
	resp.CreateElement("saml:Issuer").SetText(k.entityID)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").
		CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	a.CreateAttr("ID", "_a"+randHex())
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	a.CreateElement("saml:Issuer").SetText(k.entityID)
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nid.SetText(nameID)
	scd := subj.CreateElement("saml:SubjectConfirmation")
	scd.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd.CreateElement("saml:SubjectConfirmationData").CreateAttr("Recipient", recipient)
	scdEl := subj.FindElement("saml:SubjectConfirmation/saml:SubjectConfirmationData")
	scdEl.CreateAttr("NotOnOrAfter", time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339))
	if inResponseTo != "" {
		scdEl.CreateAttr("InResponseTo", inResponseTo)
	}
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	cond.CreateAttr("NotOnOrAfter", time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(audience)
	authn := a.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", time.Now().UTC().Format(time.RFC3339))
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").
		SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")

	ctx := dsig.NewDefaultSigningContext(k)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(a)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	resp.AddChild(signed)
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		out = strings.Replace(out, nameID, "evil@acme.example", 1)
	}
	return base64.StdEncoding.EncodeToString([]byte(out))
}

func randHex() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

// TestSAMLACSEndpoint covers §12.4 as agentry#361 leaves it: a signed
// assertion for an ACTIVE MEMBER establishes an SSO session, a tampered one
// is rejected, and an assertion for someone the organization has not
// admitted is refused rather than provisioning them — the organization's
// SSO recognises its members and is not a door into it (D7, D11).
func TestSAMLACSEndpoint(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("saml-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "samlorg" + env.sfx
	env.createOrg(sess, orgH)

	// The organization has proved it controls the domain the IdP asserts:
	// linking an identity to an existing member's account for the first
	// time needs that proof as well as the membership (T-12, agentry#361).
	env.verifyOrgDomain(orgH, "acme.example")
	idp := newSAMLTestIdP(t)
	metadataXML, err := samlsp.BuildIDPMetadataXML(idp.entityID, "https://acs-idp.test/sso", idp.certPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Configure the SAML connection (owner).
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/saml", map[string]any{
		"enabled": true,
		"config":  map[string]any{"idpMetadataXml": metadataXML, "emailAttribute": "email"},
	}, nil, http.StatusOK)

	metadataURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/metadata"
	acsURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/acs"

	// The SP metadata endpoint is publicly fetchable.
	mres, err := env.srv.Client().Get(metadataURL)
	if err != nil || mres.StatusCode != http.StatusOK {
		t.Fatalf("metadata endpoint: %v %v", err, mres)
	}
	_ = mres.Body.Close()

	// An assertion for someone who is not a member: refused, and nothing is
	// created — no account, no identity, no membership.
	stranger := "sso-stranger-" + env.sfx + "@acme.example"
	strangerResp := env.postForm(t, acsURL, url.Values{"SAMLResponse": {idp.signedResponse(t, metadataURL, acsURL, stranger, false)}})
	strangerBody, _ := io.ReadAll(strangerResp.Body)
	_ = strangerResp.Body.Close()
	if strangerResp.StatusCode != http.StatusForbidden || !strings.Contains(string(strangerBody), "not-a-member") {
		t.Fatalf("assertion for a non-member: got %d %s, want 403 not-a-member", strangerResp.StatusCode, strangerBody)
	}
	var strangers int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE email = $1`, stranger).Scan(&strangers); err != nil {
		t.Fatal(err)
	}
	if strangers != 0 {
		t.Fatalf("the refused assertion created %d account(s)", strangers)
	}

	// Good assertion, for a member the organization admitted → session.
	nameID := "sso-user-" + env.sfx + "@acme.example"
	memberH := env.registerEmail("saml-member", nameID)
	env.seedMembership(orgH, memberH, "member", "active")
	resp := idp.signedResponse(t, metadataURL, acsURL, nameID, false)
	httpResp := env.postForm(t, acsURL, url.Values{"SAMLResponse": {resp}})
	defer func() { _ = httpResp.Body.Close() }()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("ACS good assertion: got %d want 200", httpResp.StatusCode)
	}
	var sessionCookie string
	for _, c := range httpResp.Cookies() {
		if c.Name == "agentry_session" {
			sessionCookie = c.Value
		}
	}
	if sessionCookie == "" {
		t.Fatal("ACS did not set a session cookie")
	}

	// The new SSO session works.
	who := env.do(caller{name: "sso", session: sessionCookie}, http.MethodGet, "/api/v1/user", nil)
	_ = who.Body.Close()
	if who.StatusCode != http.StatusOK {
		t.Fatalf("SSO session GET /user: got %d want 200", who.StatusCode)
	}

	// Tampered assertion → rejected.
	bad := idp.signedResponse(t, metadataURL, acsURL, nameID, true)
	badResp := env.postForm(t, acsURL, url.Values{"SAMLResponse": {bad}})
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ACS tampered assertion: got %d want 401", badResp.StatusCode)
	}
}

func (env *testEnv) postForm(t *testing.T, u string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Do not follow redirects; capture the response directly.
	client := *env.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// signedLogoutRequest mints an IdP-initiated LogoutRequest (POST binding
// shape: enveloped XML signature) for nameID.
func (k *samlTestIdP) signedLogoutRequest(t *testing.T, destination, nameID string) string {
	t.Helper()
	doc := etree.NewDocument()
	req := doc.CreateElement("samlp:LogoutRequest")
	req.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	req.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	req.CreateAttr("ID", "_lr"+randHex())
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	req.CreateAttr("Destination", destination)
	req.CreateElement("saml:Issuer").SetText(k.entityID)
	req.CreateElement("saml:NameID").SetText(nameID)
	ctx := dsig.NewDefaultSigningContext(k)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(req)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	s, _ := out.WriteToString()
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// TestSAMLSingleLogout covers §12.4 SLO (agentry#62): a SAML session
// remembers its NameID; the IdP's signed LogoutRequest revokes it and is
// answered with a LogoutResponse redirect; a registry logout of such a
// session hands the browser the IdP's SLO URL; an unsigned request changes
// nothing.
func TestSAMLSingleLogout(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("slo-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "sloorg" + env.sfx
	env.createOrg(sess, orgH)

	idp := newSAMLTestIdP(t)
	metadataXML, err := samlsp.BuildIDPMetadataXMLWithSLO(idp.entityID, "https://slo-idp.test/sso", "https://slo-idp.test/slo", idp.certPEM)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/saml", map[string]any{
		"enabled": true,
		"config":  map[string]any{"idpMetadataXml": metadataXML, "emailAttribute": "email"},
	}, nil, http.StatusOK)
	metadataURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/metadata"
	acsURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/acs"
	sloURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/slo"

	// SP metadata advertises the SLO endpoint.
	mres, _ := env.srv.Client().Get(metadataURL)
	mb, _ := io.ReadAll(mres.Body)
	_ = mres.Body.Close()
	if !strings.Contains(string(mb), "SingleLogoutService") || !strings.Contains(string(mb), sloURL) {
		t.Fatalf("SP metadata lacks SLO endpoint:\n%s", mb)
	}

	// The person the IdP will assert is already a member: since agentry#361
	// the organization's SSO signs in members and admits nobody.
	sloNameID := "slo-user-" + env.sfx + "@acme.example"
	env.verifyOrgDomain(orgH, "acme.example")
	env.seedMembership(orgH, env.registerEmail("slo-member", sloNameID), "member", "active")

	loginSAML := func(name string) caller {
		nameID := sloNameID
		res := env.postForm(t, acsURL, url.Values{"SAMLResponse": {idp.signedResponse(t, metadataURL, acsURL, nameID, false)}})
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("ACS: got %d", res.StatusCode)
		}
		var body struct {
			CsrfToken string `json:"csrfToken"`
		}
		_ = json.NewDecoder(res.Body).Decode(&body)
		c := caller{name: name, csrf: body.CsrfToken}
		for _, ck := range res.Cookies() {
			if ck.Name == "agentry_session" {
				c.session = ck.Value
			}
		}
		if c.session == "" {
			t.Fatal("no session cookie")
		}
		return c
	}
	nameID := "slo-user-" + env.sfx + "@acme.example"
	ssoCaller := loginSAML("sso")
	if res := env.do(ssoCaller, http.MethodGet, "/api/v1/user", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("SSO session: %d", res.StatusCode)
	}

	// Unsigned LogoutRequest: refused, session intact.
	unsignedDoc := etree.NewDocument()
	u := unsignedDoc.CreateElement("samlp:LogoutRequest")
	u.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	u.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	u.CreateAttr("ID", "_x")
	u.CreateAttr("Version", "2.0")
	u.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	u.CreateElement("saml:Issuer").SetText(idp.entityID)
	u.CreateElement("saml:NameID").SetText(nameID)
	us, _ := unsignedDoc.WriteToString()
	bad := env.postForm(t, sloURL, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(us))}})
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned LogoutRequest: got %d want 401", bad.StatusCode)
	}
	if res := env.do(ssoCaller, http.MethodGet, "/api/v1/user", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("session must survive a refused LogoutRequest: %d", res.StatusCode)
	}

	// Signed IdP-initiated LogoutRequest: session revoked, LogoutResponse redirect.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"SAMLRequest": {idp.signedLogoutRequest(t, sloURL, nameID)}, "RelayState": {"back"}}
	res, err := noRedirect.Post(sloURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "https://slo-idp.test/slo?") || !strings.Contains(res.Header.Get("Location"), "SAMLResponse=") {
		t.Fatalf("SLO: got %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if r := env.do(ssoCaller, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session must be revoked by SLO: got %d want 401", r.StatusCode)
	}

	// SP-initiated: logging out a SAML session returns the IdP's SLO URL.
	sso2 := loginSAML("sso2")
	var out api.LogoutResult
	env.doJSON(sso2, http.MethodPost, "/api/v1/auth/logout", nil, &out, http.StatusOK)
	if !strings.HasPrefix(out.IdpLogoutUrl, "https://slo-idp.test/slo?") || !strings.Contains(out.IdpLogoutUrl, "SAMLRequest=") {
		t.Fatalf("idpLogoutUrl = %q", out.IdpLogoutUrl)
	}
	if r := env.do(sso2, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session must be revoked on logout: %d", r.StatusCode)
	}
	// A native session still logs out with 204.
	if r := env.do(sess, http.MethodPost, "/api/v1/auth/logout", nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("native logout: got %d want 204", r.StatusCode)
	}
}
