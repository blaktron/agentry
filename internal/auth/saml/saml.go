// Package saml implements the SAML 2.0 Service Provider side of enterprise SSO
// (§12.4): SP metadata, and Assertion Consumer Service (ACS) validation with a
// signed-assertion requirement, audience/recipient/NotBefore/NotOnOrAfter
// checks, ±90s clock skew, and an assertion-ID replay cache.
//
// Library choice (Appendix B / DEVIATIONS DEV-008): github.com/crewjam/saml.
// It is the most widely deployed and actively maintained Go SAML library; its
// ServiceProvider.ParseXMLResponse validates signature + audience + recipient
// (SubjectConfirmationData.Recipient) + Conditions timestamps out of the box,
// and exposes MaxClockSkew as an explicit knob — a direct match to the §12.4
// requirement list. Its signature core is russellhaering/goxmldsig v1.4.0
// (>= 1.3.0, so CVE-2022-41912 is patched). russellhaering/gosaml2 was
// evaluated as the alternative (smaller SP-only surface) but lacks the
// built-in recipient check and skew knob and would push more validation into
// our code. We own the replay cache and subject mapping either way.
package saml

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

func init() {
	// §12.4: clock skew ±90s (crewjam default is 180s). MaxIssueDelay is
	// already 90s. These are process-global in crewjam; one value for the app.
	saml.MaxClockSkew = 90 * time.Second
}

// Config is the per-org SAML connection configuration (stored in
// sso_connections.config). Either IDPMetadataXML or the explicit
// IDPEntityID/IDPSSOURL/IDPCertPEM triple must be provided.
type Config struct {
	IDPMetadataXML string `json:"idpMetadataXml,omitempty"`
	IDPEntityID    string `json:"idpEntityId,omitempty"`
	IDPSSOURL      string `json:"idpSsoUrl,omitempty"`
	IDPCertPEM     string `json:"idpCertificatePem,omitempty"`
	// SPEntityID is the audience the IdP asserts (the SP entity id). Defaults
	// to the metadata URL when empty.
	SPEntityID string `json:"spEntityId,omitempty"`
	// EmailAttribute names the assertion attribute carrying the user's email;
	// empty falls back to the NameID (when it looks like an email) or common
	// attribute names.
	EmailAttribute string `json:"emailAttribute,omitempty"`
	// SubjectAttribute names the attribute carrying the stable subject; empty
	// uses the NameID.
	SubjectAttribute string `json:"subjectAttribute,omitempty"`
}

// SP is a configured Service Provider for one org connection.
type SP struct {
	inner    saml.ServiceProvider
	acsURL   url.URL
	cfg      Config
	replay   ReplayCache
	requests RequestTracker
}

// Result is the validated identity extracted from an assertion.
type Result struct {
	// Subject is the stable IdP-asserted identifier (NameID or configured
	// attribute) — the value stored in identities.subject.
	Subject     string
	Email       string
	NameID      string
	AssertionID string
	Attributes  map[string][]string
	// SessionIndex is the IdP's session handle from the AuthnStatement, the
	// key a Single Logout request may name (§12.4, agentry#62).
	SessionIndex string
}

// New builds an SP from config and the SP's own metadata/ACS URLs. replay may
// be nil (a fresh in-memory cache is used).
func New(cfg Config, metadataURL, acsURL string, replay ReplayCache) (*SP, error) {
	mURL, err := url.Parse(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("saml: metadata url: %w", err)
	}
	aURL, err := url.Parse(acsURL)
	if err != nil {
		return nil, fmt.Errorf("saml: acs url: %w", err)
	}
	idp, err := idpMetadata(cfg)
	if err != nil {
		return nil, err
	}
	entityID := cfg.SPEntityID
	if entityID == "" {
		entityID = metadataURL
	}
	if replay == nil {
		replay = NewMemoryReplayCache()
	}
	sp := saml.ServiceProvider{
		EntityID:          entityID,
		MetadataURL:       *mURL,
		AcsURL:            *aURL,
		IDPMetadata:       idp,
		AllowIDPInitiated: true, // IdP-initiated POST to ACS (§12.4)
	}
	return &SP{inner: sp, acsURL: *aURL, cfg: cfg, replay: replay}, nil
}

// WithRequestTracker attaches the store of outstanding AuthnRequest ids and
// returns sp, so a caller can chain it onto New. Without a tracker the SP
// accepts IdP-initiated assertions only: it has no record of any login it
// started, so an InResponseTo it cannot check is refused rather than ignored.
func (sp *SP) WithRequestTracker(rt RequestTracker) *SP {
	sp.requests = rt
	return sp
}

// AuthnRequest starts an SP-initiated login (§12.4). It returns the IdP
// redirect URL and records the request id with the tracker so the eventual
// assertion's InResponseTo can be matched to it.
func (sp *SP) AuthnRequest(relayState string) (string, error) {
	loc := sp.inner.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if loc == "" {
		return "", fmt.Errorf("saml: IdP publishes no HTTP-Redirect SSO endpoint")
	}
	req, err := sp.inner.MakeAuthenticationRequest(loc, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", fmt.Errorf("saml: build AuthnRequest: %w", err)
	}
	u, err := req.Redirect(relayState, &sp.inner)
	if err != nil {
		return "", fmt.Errorf("saml: encode AuthnRequest: %w", err)
	}
	if sp.requests != nil {
		sp.requests.Track(req.ID, time.Now().Add(defaultRequestTTL))
	}
	return u.String(), nil
}

// idpMetadata resolves the IdP EntityDescriptor from config: the provided
// metadata XML, or a synthesized descriptor from the explicit fields.
func idpMetadata(cfg Config) (*saml.EntityDescriptor, error) {
	if strings.TrimSpace(cfg.IDPMetadataXML) != "" {
		ed, err := parseIDPMetadata([]byte(cfg.IDPMetadataXML))
		if err != nil {
			return nil, fmt.Errorf("saml: parse idp metadata: %w", err)
		}
		return ed, nil
	}
	if cfg.IDPEntityID == "" || cfg.IDPCertPEM == "" {
		return nil, fmt.Errorf("saml: config requires idpMetadataXml or idpEntityId+idpCertificatePem")
	}
	xmlStr, err := BuildIDPMetadataXML(cfg.IDPEntityID, cfg.IDPSSOURL, cfg.IDPCertPEM)
	if err != nil {
		return nil, err
	}
	ed, err := parseIDPMetadata([]byte(xmlStr))
	if err != nil {
		return nil, fmt.Errorf("saml: parse synthesized idp metadata: %w", err)
	}
	return ed, nil
}

// SPMetadataXML returns the SP metadata document served at the metadata
// endpoint: an SPSSODescriptor advertising the ACS URL. The SP receives
// signed assertions and signs nothing, so no KeyDescriptor is emitted.
func (sp *SP) SPMetadataXML() ([]byte, error) {
	ed := spMetadata{
		XMLName:    xml.Name{Local: "EntityDescriptor"},
		XMLNS:      "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityID:   sp.inner.EntityID,
		ValidUntil: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
	ed.SPSSODescriptor.XMLNS = "urn:oasis:names:tc:SAML:2.0:metadata"
	ed.SPSSODescriptor.Protocol = "urn:oasis:names:tc:SAML:2.0:protocol"
	ed.SPSSODescriptor.AuthnRequestsSigned = "false"
	ed.SPSSODescriptor.WantAssertionsSigned = "true"
	ed.SPSSODescriptor.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	if slo := sp.inner.SloURL.String(); slo != "" {
		for _, b := range sp.inner.LogoutBindings {
			ed.SPSSODescriptor.SLO = append(ed.SPSSODescriptor.SLO, sloEndpoint{Binding: b, Location: slo})
		}
	}
	ed.SPSSODescriptor.ACS = acsEndpoint{
		Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Location: sp.acsURL.String(),
		Index:    "0",
	}
	body, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal sp metadata: %w", err)
	}
	return append([]byte(xml.Header), body...), nil
}

// ParseAndValidate decodes and validates a base64 SAMLResponse from the ACS
// POST, enforces the assertion-ID replay guard, and extracts the identity.
func (sp *SP) ParseAndValidate(_ context.Context, samlResponseB64 string) (*Result, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(samlResponseB64))
	if err != nil {
		return nil, fmt.Errorf("saml: decode SAMLResponse: %w", err)
	}
	// crewjam validates: signature (assertion must be signed when the response
	// is not), Issuer, Destination/Recipient == ACS URL, audience restriction,
	// Conditions NotBefore/NotOnOrAfter and SubjectConfirmationData expiry with
	// MaxClockSkew. possibleRequestIDs is nil because AllowIDPInitiated makes
	// crewjam skip the InResponseTo check entirely — §12.4 wants BOTH flows,
	// so we do that check ourselves below rather than give up one of them.
	assertion, err := sp.inner.ParseXMLResponse(raw, nil, sp.acsURL)
	if err != nil {
		return nil, fmt.Errorf("saml: assertion rejected: %w", err)
	}

	// InResponseTo: an assertion that names a request must name one THIS
	// server started and has not already consumed. An assertion that names
	// none is IdP-initiated and stays allowed (§12.4). This is what stops a
	// response to someone else's login from being pasted into our ACS.
	if inResponseTo := assertionInResponseTo(assertion); inResponseTo != "" {
		if sp.requests == nil || !sp.requests.Consume(inResponseTo) {
			return nil, fmt.Errorf("saml: InResponseTo %q matches no pending AuthnRequest", inResponseTo)
		}
	}

	// Replay guard on the assertion ID (§12.4, T-12): consume once.
	var exp time.Time
	if assertion.Conditions != nil {
		exp = assertion.Conditions.NotOnOrAfter
	}
	if sp.replay.SeenBefore(assertion.ID, exp) {
		return nil, fmt.Errorf("saml: assertion %q replayed", assertion.ID)
	}

	res := &Result{AssertionID: assertion.ID, Attributes: map[string][]string{}}
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		res.NameID = strings.TrimSpace(assertion.Subject.NameID.Value)
	}
	for _, st := range assertion.AuthnStatements {
		if st.SessionIndex != "" {
			res.SessionIndex = st.SessionIndex
			break
		}
	}
	for _, st := range assertion.AttributeStatements {
		for _, a := range st.Attributes {
			key := a.Name
			for _, v := range a.Values {
				if v.Value != "" {
					res.Attributes[key] = append(res.Attributes[key], v.Value)
				}
			}
		}
	}

	res.Subject = sp.deriveSubject(res)
	res.Email = sp.deriveEmail(res)
	if res.Subject == "" {
		return nil, fmt.Errorf("saml: assertion has no usable subject (NameID/attribute)")
	}
	return res, nil
}

// assertionInResponseTo reads the request id the assertion answers. It is
// taken from SubjectConfirmationData, which is inside the signed assertion —
// the Response-level attribute is not covered by the assertion signature and
// so is not evidence of anything.
func assertionInResponseTo(a *saml.Assertion) string {
	if a == nil || a.Subject == nil {
		return ""
	}
	for _, sc := range a.Subject.SubjectConfirmations {
		if sc.SubjectConfirmationData == nil {
			continue
		}
		if v := strings.TrimSpace(sc.SubjectConfirmationData.InResponseTo); v != "" {
			return v
		}
	}
	return ""
}

func (sp *SP) deriveSubject(res *Result) string {
	if sp.cfg.SubjectAttribute != "" {
		if v := firstAttr(res.Attributes, sp.cfg.SubjectAttribute); v != "" {
			return v
		}
	}
	return res.NameID
}

// commonEmailAttrs are the attribute names IdPs conventionally use for email.
var commonEmailAttrs = []string{
	"email",
	"mail",
	"emailAddress",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	"urn:oid:0.9.2342.19200300.100.1.3",
}

func (sp *SP) deriveEmail(res *Result) string {
	if sp.cfg.EmailAttribute != "" {
		if v := firstAttr(res.Attributes, sp.cfg.EmailAttribute); v != "" {
			return strings.ToLower(v)
		}
	}
	for _, k := range commonEmailAttrs {
		if v := firstAttr(res.Attributes, k); v != "" {
			return strings.ToLower(v)
		}
	}
	if strings.Contains(res.NameID, "@") {
		return strings.ToLower(res.NameID)
	}
	return ""
}

func firstAttr(attrs map[string][]string, key string) string {
	if vs := attrs[key]; len(vs) > 0 {
		return strings.TrimSpace(vs[0])
	}
	return ""
}

// BuildIDPMetadataXML synthesizes a minimal IdP EntityDescriptor from an
// entity id, SSO URL, and a PEM certificate — for connections configured with
// explicit fields rather than a full metadata document. Exported so tests
// (an in-process IdP) can produce metadata for a generated keypair.
func BuildIDPMetadataXML(entityID, ssoURL, certPEM string) (string, error) {
	return BuildIDPMetadataXMLWithSLO(entityID, ssoURL, "", certPEM)
}

// BuildIDPMetadataXMLWithSLO is BuildIDPMetadataXML with an optional
// HTTP-Redirect Single Logout endpoint (§12.4, agentry#62).
func BuildIDPMetadataXMLWithSLO(entityID, ssoURL, sloURL, certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("saml: idp certificate is not valid PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("saml: idp certificate: %w", err)
	}
	b64 := base64.StdEncoding.EncodeToString(block.Bytes)
	var b strings.Builder
	b.WriteString(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="`)
	xmlEsc(&b, entityID)
	b.WriteString(`"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`)
	b.WriteString(`<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>`)
	b.WriteString(b64)
	b.WriteString(`</X509Certificate></X509Data></KeyInfo></KeyDescriptor>`)
	b.WriteString(`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="`)
	xmlEsc(&b, ssoURL)
	b.WriteString(`"/>`)
	if sloURL != "" {
		b.WriteString(`<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="`)
		xmlEsc(&b, sloURL)
		b.WriteString(`"/>`)
	}
	b.WriteString(`</IDPSSODescriptor></EntityDescriptor>`)
	return b.String(), nil
}

// parseIDPMetadata parses IdP metadata that may be wrapped in either an
// <EntityDescriptor> or an <EntitiesDescriptor>. Inlined from crewjam's
// samlsp.ParseMetadata to avoid pulling in samlsp's session/JWT dependencies.
func parseIDPMetadata(data []byte) (*saml.EntityDescriptor, error) {
	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}
	entity := &saml.EntityDescriptor{}
	err := xml.Unmarshal(data, entity)
	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				return &entities.EntityDescriptors[i], nil
			}
		}
		return nil, errors.New("saml: no entity with an IDPSSODescriptor")
	}
	if err != nil {
		return nil, err
	}
	return entity, nil
}

func xmlEsc(b *strings.Builder, s string) {
	_ = xml.EscapeText(escWriter{b}, []byte(s))
}

type escWriter struct{ b *strings.Builder }

func (w escWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

// spMetadata is a minimal SP metadata document (encoding/xml).
type spMetadata struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	XMLNS           string   `xml:"xmlns,attr"`
	EntityID        string   `xml:"entityID,attr"`
	ValidUntil      string   `xml:"validUntil,attr"`
	SPSSODescriptor struct {
		XMLNS                string        `xml:"xmlns,attr"`
		Protocol             string        `xml:"protocolSupportEnumeration,attr"`
		AuthnRequestsSigned  string        `xml:"AuthnRequestsSigned,attr"`
		WantAssertionsSigned string        `xml:"WantAssertionsSigned,attr"`
		SLO                  []sloEndpoint `xml:"SingleLogoutService,omitempty"`
		NameIDFormat         string        `xml:"NameIDFormat"`
		ACS                  acsEndpoint   `xml:"AssertionConsumerService"`
	} `xml:"SPSSODescriptor"`
}

// sloEndpoint advertises the Single Logout endpoint (§12.4, agentry#62).
type sloEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type acsEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    string `xml:"index,attr"`
}

// IDPDescription is what a connection test can say about an IdP from its
// metadata alone (agentry#50): identity, where sign-in goes, and whether
// the signing certificate is about to expire.
type IDPDescription struct {
	EntityID     string
	SSOURLs      []string
	Certificates int
	// EarliestCertExpiry is the soonest NotAfter across the IdP's signing
	// certificates; nil when none parsed.
	EarliestCertExpiry *time.Time
	// ValidUntil is the metadata document's own validity, if declared.
	ValidUntil *time.Time
}

// DescribeIDP parses the configured IdP metadata and summarises it. It
// performs no network access: the metadata is what the operator stored.
func DescribeIDP(cfg Config) (*IDPDescription, error) {
	ed, err := idpMetadata(cfg)
	if err != nil {
		return nil, err
	}
	d := &IDPDescription{EntityID: ed.EntityID}
	if !ed.ValidUntil.IsZero() {
		v := ed.ValidUntil
		d.ValidUntil = &v
	}
	for _, idp := range ed.IDPSSODescriptors {
		for _, sso := range idp.SingleSignOnServices {
			d.SSOURLs = append(d.SSOURLs, sso.Location)
		}
		for _, kd := range idp.KeyDescriptors {
			for _, c := range kd.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Data), ""))
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				d.Certificates++
				if d.EarliestCertExpiry == nil || cert.NotAfter.Before(*d.EarliestCertExpiry) {
					na := cert.NotAfter
					d.EarliestCertExpiry = &na
				}
			}
		}
	}
	if len(d.SSOURLs) == 0 {
		return d, errors.New("saml: idp metadata declares no SingleSignOnService")
	}
	return d, nil
}
