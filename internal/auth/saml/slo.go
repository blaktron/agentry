package saml

// SAML Single Logout (§12.4, agentry#62). Two directions:
//
//   - IdP-initiated: the IdP sends a LogoutRequest naming the NameID (and
//     optionally the SessionIndex) to the SP's SLO endpoint, over the
//     HTTP-POST binding (XML signature inside the message) or the
//     HTTP-Redirect binding (signature over the query string). The SP
//     verifies it against the IdP's signing certificates from its metadata,
//     the caller revokes the matching sessions, and the SP answers with a
//     LogoutResponse to the IdP's SLO endpoint.
//   - SP-initiated: on registry logout the caller sends the browser to the
//     IdP's SLO endpoint with a LogoutRequest; the IdP answers with a
//     LogoutResponse to the SP's SLO endpoint, which the SP validates.
//
// This SP holds no signing key (it receives signed assertions and signs
// nothing, see SPMetadataXML), so the messages IT sends are unsigned; an
// IdP that requires signed SP logout messages will refuse the SP-initiated
// half while the IdP-initiated half — the one that revokes access when a
// directory deprovisions a person — works regardless.

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-SHA1 is a binding-defined SigAlg an IdP may still use
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// sloMaxAge bounds how old a LogoutRequest may be (IssueInstant).
const sloMaxAge = 10 * time.Minute

// LogoutRequestInfo is a validated IdP-initiated LogoutRequest.
type LogoutRequestInfo struct {
	// ID is the request id the LogoutResponse must answer.
	ID string
	// NameID names the principal whose sessions end.
	NameID string
	// SessionIndex, when present, narrows the logout to one IdP session.
	SessionIndex string
}

// WithSLO advertises the SP's Single Logout endpoint (HTTP-POST and
// HTTP-Redirect bindings) in the metadata and enables the SLO methods.
func (sp *SP) WithSLO(sloURL string) *SP {
	u, err := url.Parse(sloURL)
	if err != nil || sloURL == "" {
		return sp
	}
	sp.inner.SloURL = *u
	sp.inner.LogoutBindings = []string{saml.HTTPPostBinding, saml.HTTPRedirectBinding}
	return sp
}

// IDPSupportsSLO reports whether the IdP metadata publishes a Single Logout
// endpoint the SP can send to (Redirect preferred, POST accepted).
func (sp *SP) IDPSupportsSLO() bool {
	return sp.inner.GetSLOBindingLocation(saml.HTTPRedirectBinding) != "" ||
		sp.inner.GetSLOBindingLocation(saml.HTTPPostBinding) != ""
}

// LogoutRequestURL builds the SP-initiated LogoutRequest redirect to the
// IdP for nameID (HTTP-Redirect binding, unsigned — see the package note).
func (sp *SP) LogoutRequestURL(nameID, relayState string) (string, error) {
	if sp.inner.GetSLOBindingLocation(saml.HTTPRedirectBinding) == "" {
		return "", errors.New("saml: IdP publishes no HTTP-Redirect SLO endpoint")
	}
	u, err := sp.inner.MakeRedirectLogoutRequest(nameID, relayState)
	if err != nil {
		return "", fmt.Errorf("saml: build LogoutRequest: %w", err)
	}
	return u.String(), nil
}

// LogoutResponseURL builds the redirect that answers an IdP-initiated
// LogoutRequest (HTTP-Redirect binding, unsigned). ok is false when the
// IdP publishes no Redirect SLO endpoint to answer to.
func (sp *SP) LogoutResponseURL(requestID, relayState string) (string, bool) {
	if sp.inner.GetSLOBindingLocation(saml.HTTPRedirectBinding) == "" {
		return "", false
	}
	u, err := sp.inner.MakeRedirectLogoutResponse(requestID, relayState)
	if err != nil {
		return "", false
	}
	return u.String(), true
}

// ValidateLogoutResponse checks the IdP's answer to an SP-initiated logout
// (either binding); the query string (Redirect) or form body (POST) is
// passed as received.
func (sp *SP) ValidateLogoutResponse(rawQuery, samlResponseForm string) error {
	if samlResponseForm != "" {
		return sp.inner.ValidateLogoutResponseForm(samlResponseForm)
	}
	return sp.inner.ValidateLogoutResponseRedirect(rawQuery)
}

// ParseLogoutRequestPost validates a LogoutRequest delivered by the
// HTTP-POST binding: the base64 XML must carry an enveloped signature by
// one of the IdP's signing certificates.
func (sp *SP) ParseLogoutRequestPost(samlRequestB64 string) (*LogoutRequestInfo, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(samlRequestB64))
	if err != nil {
		return nil, fmt.Errorf("saml: decode SAMLRequest: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("saml: parse LogoutRequest: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "LogoutRequest" {
		return nil, errors.New("saml: not a LogoutRequest")
	}
	certs, err := sp.idpSigningCerts()
	if err != nil {
		return nil, err
	}
	vctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	validated, err := vctx.Validate(root)
	if err != nil {
		return nil, fmt.Errorf("saml: LogoutRequest signature rejected: %w", err)
	}
	return sp.logoutRequestFrom(validated)
}

// ParseLogoutRequestRedirect validates a LogoutRequest delivered by the
// HTTP-Redirect binding: SAMLRequest is deflated+base64 XML and the
// signature covers the query string ("SAMLRequest=…&RelayState=…&SigAlg=…"
// in the encoding the IdP sent).
func (sp *SP) ParseLogoutRequestRedirect(rawQuery string) (*LogoutRequestInfo, error) {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, fmt.Errorf("saml: parse query: %w", err)
	}
	enc := q.Get("SAMLRequest")
	if enc == "" {
		return nil, errors.New("saml: SAMLRequest is required")
	}
	sigB64, sigAlg := q.Get("Signature"), q.Get("SigAlg")
	if sigB64 == "" || sigAlg == "" {
		return nil, errors.New("saml: Redirect-binding LogoutRequest must be signed (Signature and SigAlg)")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("saml: decode Signature: %w", err)
	}
	signed := signedQueryString(rawQuery)
	certs, err := sp.idpSigningCerts()
	if err != nil {
		return nil, err
	}
	if err := verifyQuerySignature(certs, sigAlg, signed, sig); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("saml: decode SAMLRequest: %w", err)
	}
	inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 1<<20))
	if err != nil {
		return nil, fmt.Errorf("saml: inflate SAMLRequest: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(inflated); err != nil {
		return nil, fmt.Errorf("saml: parse LogoutRequest: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "LogoutRequest" {
		return nil, errors.New("saml: not a LogoutRequest")
	}
	return sp.logoutRequestFrom(root)
}

// signedQueryString rebuilds the exact signed portion from the raw query,
// preserving the IdP's percent-encoding (re-encoding it would change the
// bytes the signature covers).
func signedQueryString(rawQuery string) string {
	parts := map[string]string{}
	for _, kv := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		parts[k] = v
	}
	out := "SAMLRequest=" + parts["SAMLRequest"]
	if rs, ok := parts["RelayState"]; ok {
		out += "&RelayState=" + rs
	}
	return out + "&SigAlg=" + parts["SigAlg"]
}

func verifyQuerySignature(certs []*x509.Certificate, sigAlg, signed string, sig []byte) error {
	var h crypto.Hash
	var digest []byte
	switch sigAlg {
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		h = crypto.SHA256
		d := sha256.Sum256([]byte(signed))
		digest = d[:]
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		h = crypto.SHA1
		d := sha1.Sum([]byte(signed)) //nolint:gosec // binding-defined algorithm
		digest = d[:]
	default:
		return fmt.Errorf("saml: unsupported SigAlg %q", sigAlg)
	}
	for _, c := range certs {
		pub, ok := c.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if rsa.VerifyPKCS1v15(pub, h, digest, sig) == nil {
			return nil
		}
	}
	return errors.New("saml: LogoutRequest query signature rejected")
}

// logoutRequestFrom checks the validated element's issuer, destination and
// freshness and extracts the identifiers.
func (sp *SP) logoutRequestFrom(el *etree.Element) (*LogoutRequestInfo, error) {
	issuer := ""
	if is := el.FindElement("./Issuer"); is != nil {
		issuer = strings.TrimSpace(is.Text())
	}
	if issuer == "" || issuer != sp.inner.IDPMetadata.EntityID {
		return nil, fmt.Errorf("saml: LogoutRequest issuer %q is not the connection's IdP", issuer)
	}
	if dest := el.SelectAttrValue("Destination", ""); dest != "" && sp.inner.SloURL.String() != "" && dest != sp.inner.SloURL.String() {
		return nil, fmt.Errorf("saml: LogoutRequest destination %q is not this SP's SLO endpoint", dest)
	}
	if ii := el.SelectAttrValue("IssueInstant", ""); ii != "" {
		t, err := time.Parse(time.RFC3339, ii)
		if err != nil || time.Since(t) > sloMaxAge || time.Until(t) > time.Minute {
			return nil, errors.New("saml: LogoutRequest is stale or from the future")
		}
	}
	if noa := el.SelectAttrValue("NotOnOrAfter", ""); noa != "" {
		if t, err := time.Parse(time.RFC3339, noa); err == nil && !time.Now().Before(t) {
			return nil, errors.New("saml: LogoutRequest has expired")
		}
	}
	info := &LogoutRequestInfo{ID: el.SelectAttrValue("ID", "")}
	if nid := el.FindElement("./NameID"); nid != nil {
		info.NameID = strings.TrimSpace(nid.Text())
	}
	if si := el.FindElement("./SessionIndex"); si != nil {
		info.SessionIndex = strings.TrimSpace(si.Text())
	}
	if info.ID == "" || info.NameID == "" {
		return nil, errors.New("saml: LogoutRequest lacks ID or NameID")
	}
	if sp.replay.SeenBefore("slo:"+info.ID, time.Now().Add(sloMaxAge)) {
		return nil, fmt.Errorf("saml: LogoutRequest %q replayed", info.ID)
	}
	return info, nil
}

// idpSigningCerts reads the IdP's signing certificates from its metadata.
func (sp *SP) idpSigningCerts() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, d := range sp.inner.IDPMetadata.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Data), ""))
				if err != nil {
					continue
				}
				if c, err := x509.ParseCertificate(der); err == nil {
					certs = append(certs, c)
				}
			}
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("saml: IdP metadata carries no signing certificate")
	}
	return certs, nil
}
