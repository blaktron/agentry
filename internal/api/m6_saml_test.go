package api_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	samlsp "github.com/PLACEHOLDER_ORG/agentry/internal/auth/saml"
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
	subj.FindElement("saml:SubjectConfirmation/saml:SubjectConfirmationData").
		CreateAttr("NotOnOrAfter", time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339))
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

// TestSAMLACSEndpoint covers §12.4: a signed assertion POSTed to the ACS
// endpoint establishes an SSO session (JIT), and a tampered one is rejected.
func TestSAMLACSEndpoint(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("saml-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "samlorg" + env.sfx
	env.createOrg(sess, orgH)

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

	// Good assertion → session established.
	nameID := "sso-user-" + env.sfx + "@acme.example"
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
