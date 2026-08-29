package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// testIdP is a self-signed in-process SAML IdP (DEV-009 pattern: no container).
type testIdP struct {
	entityID string
	key      *rsa.PrivateKey
	certDER  []byte
	certPEM  string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return &testIdP{entityID: "https://idp.test/metadata", key: key, certDER: der, certPEM: pemStr}
}

func (k *testIdP) GetKeyPair() (*rsa.PrivateKey, []byte, error) { return k.key, k.certDER, nil }

// assertionOpts tunes a minted response for negative cases.
type assertionOpts struct {
	audience     string
	recipient    string
	notBefore    time.Time
	notOnOrAfter time.Time
	assertionID  string
	sign         bool
	tamper       bool
	// inResponseTo, when set, marks the assertion as answering an
	// SP-initiated AuthnRequest with that id (§12.4).
	inResponseTo string
}

// testSubject is the fixed NameID/email the in-test IdP asserts.
const testSubject = "user@acme.example"

// mintResponse builds a SAML Response with a signed assertion and returns the
// base64 the ACS receives.
func (k *testIdP) mintResponse(t *testing.T, o assertionOpts) string {
	t.Helper()
	nameID, email := testSubject, testSubject
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	resp.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	resp.CreateAttr("ID", "_resp_"+randID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	resp.CreateAttr("Destination", o.recipient)
	resp.CreateElement("saml:Issuer").SetText(k.entityID)
	status := resp.CreateElement("samlp:Status")
	status.CreateElement("samlp:StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("ID", o.assertionID)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	assertion.CreateElement("saml:Issuer").SetText(k.entityID)

	subject := assertion.CreateElement("saml:Subject")
	nid := subject.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nid.SetText(nameID)
	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", o.notOnOrAfter.UTC().Format(time.RFC3339))
	scd.CreateAttr("Recipient", o.recipient)
	if o.inResponseTo != "" {
		scd.CreateAttr("InResponseTo", o.inResponseTo)
	}

	cond := assertion.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", o.notBefore.UTC().Format(time.RFC3339))
	cond.CreateAttr("NotOnOrAfter", o.notOnOrAfter.UTC().Format(time.RFC3339))
	if o.audience != "" {
		ar := cond.CreateElement("saml:AudienceRestriction")
		ar.CreateElement("saml:Audience").SetText(o.audience)
	}
	authn := assertion.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", time.Now().UTC().Format(time.RFC3339))
	ac := authn.CreateElement("saml:AuthnContext")
	ac.CreateElement("saml:AuthnContextClassRef").SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")

	if email != "" {
		as := assertion.CreateElement("saml:AttributeStatement")
		attr := as.CreateElement("saml:Attribute")
		attr.CreateAttr("Name", "email")
		attr.CreateElement("saml:AttributeValue").SetText(email)
	}

	finalAssertion := assertion
	if o.sign {
		ctx := dsig.NewDefaultSigningContext(k)
		// SAML requires exclusive canonicalization: the signed assertion is
		// embedded under <Response>, so inclusive C14N (goxmldsig's default)
		// would fold in the parent's inherited namespaces and break the digest.
		ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		signed, err := ctx.SignEnveloped(assertion)
		if err != nil {
			t.Fatalf("sign assertion: %v", err)
		}
		finalAssertion = signed
	}
	resp.AddChild(finalAssertion)

	out, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	if o.tamper {
		// Flip a character inside the signed digest region to break the sig.
		out = strings.Replace(out, "user@acme.example", "evil@acme.example", 1)
	}
	return base64.StdEncoding.EncodeToString([]byte(out))
}

func randID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

const (
	spMetadataURL = "https://sp.test/api/v1/orgs/acme/sso/saml/metadata"
	spACSURL      = "https://sp.test/api/v1/orgs/acme/sso/saml/acs"
)

func newSPForIdP(t *testing.T, idp *testIdP) *SP {
	t.Helper()
	sp, err := New(Config{
		IDPEntityID:    idp.entityID,
		IDPSSOURL:      "https://idp.test/sso",
		IDPCertPEM:     idp.certPEM,
		SPEntityID:     spMetadataURL,
		EmailAttribute: "email",
	}, spMetadataURL, spACSURL, NewMemoryReplayCache())
	if err != nil {
		t.Fatalf("build SP: %v", err)
	}
	return sp
}

func goodOpts() assertionOpts {
	return assertionOpts{
		audience:     spMetadataURL,
		recipient:    spACSURL,
		notBefore:    time.Now().Add(-time.Minute),
		notOnOrAfter: time.Now().Add(5 * time.Minute),
		assertionID:  "_assert_" + randID(),
		sign:         true,
	}
}

func TestSAML_AcceptsSignedAssertion(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSPForIdP(t, idp)
	resp := idp.mintResponse(t, goodOpts())

	res, err := sp.ParseAndValidate(context.Background(), resp)
	if err != nil {
		t.Fatalf("expected acceptance, got %v", err)
	}
	if res.Email != "user@acme.example" {
		t.Fatalf("email = %q", res.Email)
	}
	if res.Subject != "user@acme.example" {
		t.Fatalf("subject = %q", res.Subject)
	}
}

func TestSAML_RejectsBadSignature(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSPForIdP(t, idp)
	o := goodOpts()
	o.tamper = true
	resp := idp.mintResponse(t, o)
	if _, err := sp.ParseAndValidate(context.Background(), resp); err == nil {
		t.Fatal("tampered assertion must be rejected")
	}
}

func TestSAML_RejectsUnsignedAssertion(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSPForIdP(t, idp)
	o := goodOpts()
	o.sign = false
	resp := idp.mintResponse(t, o)
	if _, err := sp.ParseAndValidate(context.Background(), resp); err == nil {
		t.Fatal("unsigned assertion must be rejected (signed-assertion requirement)")
	}
}

func TestSAML_RejectsWrongAudience(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSPForIdP(t, idp)
	o := goodOpts()
	o.audience = "https://evil.example/metadata"
	resp := idp.mintResponse(t, o)
	if _, err := sp.ParseAndValidate(context.Background(), resp); err == nil {
		t.Fatal("wrong audience must be rejected")
	}
}

func TestSAML_RejectsExpiredNotOnOrAfter(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSPForIdP(t, idp)
	o := goodOpts()
	// Well beyond the ±90s clock skew.
	o.notBefore = time.Now().Add(-30 * time.Minute)
	o.notOnOrAfter = time.Now().Add(-10 * time.Minute)
	resp := idp.mintResponse(t, o)
	if _, err := sp.ParseAndValidate(context.Background(), resp); err == nil {
		t.Fatal("expired assertion must be rejected")
	}
}

func TestSAML_RejectsReplayedAssertionID(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSPForIdP(t, idp)
	o := goodOpts()
	resp := idp.mintResponse(t, o)

	if _, err := sp.ParseAndValidate(context.Background(), resp); err != nil {
		t.Fatalf("first presentation should pass: %v", err)
	}
	// Same assertion ID, freshly minted so timestamps are valid: replay guard
	// must still reject it.
	o2 := o
	resp2 := idp.mintResponse(t, o2)
	if _, err := sp.ParseAndValidate(context.Background(), resp2); err == nil {
		t.Fatal("replayed assertion ID must be rejected")
	}
}
