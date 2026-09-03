package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const spSLOURL = "https://sp.test/api/v1/orgs/acme/sso/saml/slo"

// mintLogoutRequest builds an IdP LogoutRequest; signed=true envelopes an
// XML signature (POST binding shape).
func (k *testIdP) mintLogoutRequest(t *testing.T, nameID, sessionIndex, issuer string, signed bool, issued time.Time) (*etree.Document, string) {
	t.Helper()
	doc := etree.NewDocument()
	req := doc.CreateElement("samlp:LogoutRequest")
	req.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	req.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	id := "_lr" + randID()
	req.CreateAttr("ID", id)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", issued.UTC().Format(time.RFC3339))
	req.CreateAttr("Destination", spSLOURL)
	req.CreateElement("saml:Issuer").SetText(issuer)
	req.CreateElement("saml:NameID").SetText(nameID)
	if sessionIndex != "" {
		req.CreateElement("samlp:SessionIndex").SetText(sessionIndex)
	}
	if !signed {
		return doc, id
	}
	ctx := dsig.NewDefaultSigningContext(k)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signedEl, err := ctx.SignEnveloped(req)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := etree.NewDocument()
	out.SetRoot(signedEl)
	return out, id
}

func docB64(t *testing.T, doc *etree.Document) string {
	t.Helper()
	s, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func newSLOSP(t *testing.T, idp *testIdP) *SP {
	t.Helper()
	metadata, err := BuildIDPMetadataXMLWithSLO(idp.entityID, "https://idp.test/sso", "https://idp.test/slo", idp.certPEM)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := New(Config{IDPMetadataXML: metadata, SPEntityID: spMetadataURL}, spMetadataURL, spACSURL, NewMemoryReplayCache())
	if err != nil {
		t.Fatal(err)
	}
	return sp.WithSLO(spSLOURL)
}

func TestSLO_MetadataAdvertisesEndpointAndIdPSupport(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSLOSP(t, idp)
	xml, err := sp.SPMetadataXML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(xml), "SingleLogoutService") || !strings.Contains(string(xml), spSLOURL) {
		t.Fatalf("metadata lacks the SLO endpoint:\n%s", xml)
	}
	if !sp.IDPSupportsSLO() {
		t.Fatal("IdP metadata with SingleLogoutService must report support")
	}
	plain := newSPForIdP(t, idp)
	if plain.IDPSupportsSLO() {
		t.Fatal("IdP metadata without SingleLogoutService must not report support")
	}
	u, err := sp.LogoutRequestURL("user@acme.example", "rs")
	if err != nil || !strings.HasPrefix(u, "https://idp.test/slo?") || !strings.Contains(u, "SAMLRequest=") {
		t.Fatalf("LogoutRequestURL = %q, %v", u, err)
	}
	if _, err := plain.LogoutRequestURL("user@acme.example", ""); err == nil {
		t.Fatal("no IdP SLO endpoint must be an error")
	}
}

func TestSLO_PostBindingAcceptsSignedRefusesTamperedUnsignedForeignReplayed(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSLOSP(t, idp)
	doc, id := idp.mintLogoutRequest(t, "user@acme.example", "idx-1", idp.entityID, true, time.Now())
	info, err := sp.ParseLogoutRequestPost(docB64(t, doc))
	if err != nil {
		t.Fatalf("signed request rejected: %v", err)
	}
	if info.ID != id || info.NameID != "user@acme.example" || info.SessionIndex != "idx-1" {
		t.Fatalf("info = %+v", info)
	}
	if _, err := sp.ParseLogoutRequestPost(docB64(t, doc)); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replay must be refused: %v", err)
	}
	if u, ok := sp.LogoutResponseURL(id, "rs"); !ok || !strings.HasPrefix(u, "https://idp.test/slo?") || !strings.Contains(u, "SAMLResponse=") {
		t.Fatalf("LogoutResponseURL = %q %v", u, ok)
	}

	tampered, _ := idp.mintLogoutRequest(t, "user@acme.example", "", idp.entityID, true, time.Now())
	s, _ := tampered.WriteToString()
	s = strings.Replace(s, "user@acme.example", "victim@acme.example", 1)
	if _, err := sp.ParseLogoutRequestPost(base64.StdEncoding.EncodeToString([]byte(s))); err == nil {
		t.Fatal("tampered request must be refused")
	}
	unsigned, _ := idp.mintLogoutRequest(t, "user@acme.example", "", idp.entityID, false, time.Now())
	if _, err := sp.ParseLogoutRequestPost(docB64(t, unsigned)); err == nil {
		t.Fatal("unsigned request must be refused")
	}
	other := newTestIdP(t)
	foreign, _ := other.mintLogoutRequest(t, "user@acme.example", "", idp.entityID, true, time.Now())
	if _, err := sp.ParseLogoutRequestPost(docB64(t, foreign)); err == nil {
		t.Fatal("request signed by another key must be refused")
	}
	wrongIssuer, _ := idp.mintLogoutRequest(t, "user@acme.example", "", "https://someone-else.test", true, time.Now())
	if _, err := sp.ParseLogoutRequestPost(docB64(t, wrongIssuer)); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("wrong issuer must be refused: %v", err)
	}
	stale, _ := idp.mintLogoutRequest(t, "user@acme.example", "", idp.entityID, true, time.Now().Add(-time.Hour))
	if _, err := sp.ParseLogoutRequestPost(docB64(t, stale)); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale request must be refused: %v", err)
	}
}

// redirectQuery encodes a LogoutRequest the HTTP-Redirect way (deflate +
// base64 + query signature) with the IdP key, optionally breaking the
// signature.
func (k *testIdP) redirectQuery(t *testing.T, doc *etree.Document, relayState string, breakSig bool) string {
	t.Helper()
	s, _ := doc.WriteToString()
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write([]byte(s))
	_ = fw.Close()
	q := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	q += "&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	digest := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if breakSig {
		sig[0] ^= 0xff
	}
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

func TestSLO_RedirectBindingVerifiesQuerySignature(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSLOSP(t, idp)
	doc, id := idp.mintLogoutRequest(t, "user@acme.example", "idx-2", idp.entityID, false, time.Now())
	info, err := sp.ParseLogoutRequestRedirect(idp.redirectQuery(t, doc, "back", false))
	if err != nil {
		t.Fatalf("signed redirect request rejected: %v", err)
	}
	if info.ID != id || info.SessionIndex != "idx-2" {
		t.Fatalf("info = %+v", info)
	}
	doc2, _ := idp.mintLogoutRequest(t, "user@acme.example", "", idp.entityID, false, time.Now())
	if _, err := sp.ParseLogoutRequestRedirect(idp.redirectQuery(t, doc2, "", true)); err == nil {
		t.Fatal("broken query signature must be refused")
	}
	q := idp.redirectQuery(t, doc2, "", false)
	q = strings.SplitN(q, "&SigAlg=", 2)[0] // strip SigAlg and Signature
	if _, err := sp.ParseLogoutRequestRedirect(q); err == nil || !strings.Contains(err.Error(), "signed") {
		t.Fatalf("unsigned redirect request must be refused: %v", err)
	}
}
