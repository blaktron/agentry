// Package attest is the public attestation format for published versions:
// the in-toto v1 statement, the publish predicate, the DSSE envelope, and
// offline verification. It is what the CLI — and any third-party client —
// needs to verify a release against the registry's well-known signing
// keys; producing signatures stays server-side.
package attest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// PredicateType is the Agentry publish attestation predicate.
const PredicateType = "https://agentry.dev/attestation/publish/v1"

// PayloadType is the DSSE payload type for in-toto statements.
const PayloadType = "application/vnd.in-toto+json"

// RulesetPredicateType is the rule-bundle attestation predicate: the registry
// signs the bundle `validate --rules-update` serves, with the same key that
// signs releases, so a client pins by signature and not only by the digest
// the same server advertised.
const RulesetPredicateType = "https://agentry.dev/attestation/ruleset/v1"

// RulesetPredicate describes the signed bundle.
type RulesetPredicate struct {
	Registry string `json:"registry"`
	Semver   string `json:"semver"`
	SignedAt string `json:"signedAt"`
}

// InTotoStatement is the signed subject (in-toto v1).
type InTotoStatement struct {
	Type          string      `json:"_type"`
	Subject       []Subject   `json:"subject"`
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

// Subject binds the statement to the archive digest.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// PublishPredicate is the publish predicate.
type PublishPredicate struct {
	Registry    string     `json:"registry"`
	Agent       string     `json:"agent"`
	Version     string     `json:"version"`
	CommitSHA   string     `json:"commitSha,omitempty"`
	Source      string     `json:"source"`
	ScanRun     ScanRunRef `json:"scanRun"`
	PolicyVer   int        `json:"policyVersion"`
	PublishedAt string     `json:"publishedAt"`
}

// ScanRunRef records reproducibility fields.
type ScanRunRef struct {
	ID           string `json:"id"`
	RulesetVer   string `json:"rulesetVersion"`
	ReportDigest string `json:"reportDigest"`
	JudgeModel   string `json:"judgeModel,omitempty"`
}

// DSSEEnvelope is the signed wrapper (dsse v1).
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"` // base64 of the statement
	Signatures  []DSSESignature `json:"signatures"`
}

// DSSESignature is one signature over the PAE-encoded payload.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64
}

// VerifyEnvelope checks a DSSE envelope of an in-toto statement against a
// PEM public key; an envelope of any other payload type is refused. Used by
// the CLI (offline), the server's own tests, and third-party verifiers.
//
// The caller chooses the key. A signature's keyid is a label the signer
// attached, not evidence of anything: it is never read here, and a verifier
// must never resolve a key from it (fetching or selecting whatever key an
// envelope names would let the envelope's author pick the key that checks
// it). The key comes from a source the verifier already trusts.
func VerifyEnvelope(env DSSEEnvelope, publicKeyPEM string) (InTotoStatement, error) {
	payload, err := VerifyPayload(env, publicKeyPEM, PayloadType)
	if err != nil {
		return InTotoStatement{}, err
	}
	var stmt InTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return InTotoStatement{}, err
	}
	return stmt, nil
}

// VerifyPayload checks a DSSE envelope of the given payload type against a
// PEM public key and returns the signed payload. The same key may sign
// more than one kind of payload, so the type is checked before anything
// else: the signature covers it, and an envelope of another type is
// refused rather than decoded as this one. The key rule is
// VerifyEnvelope's: the caller chooses the key, never the envelope.
func VerifyPayload(env DSSEEnvelope, publicKeyPEM, payloadType string) ([]byte, error) {
	if env.PayloadType != payloadType {
		return nil, fmt.Errorf("attest: verify: payload type %q, want %q", env.PayloadType, payloadType)
	}
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("attest: verify: bad public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("attest: verify: parse key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("attest: verify: not an ECDSA key")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("attest: verify: payload decode: %w", err)
	}
	pae := PAE(env.PayloadType, payload)
	digest := sha256.Sum256(pae)
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if ecdsa.VerifyASN1(ecPub, digest[:], sig) {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("attest: verify: no valid signature")
}

// PAE is the DSSE Pre-Authentication Encoding.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), payload))
}

// KeyIDFor derives a stable key id from the public key (sha256 of DER).
func KeyIDFor(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16]
}

// BuildStatement assembles the in-toto statement for a published version.
func BuildStatement(registry, agentPath, version, archiveDigest, commitSHA, source string, run ScanRunRef, policyVersion int) InTotoStatement {
	return InTotoStatement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []Subject{{
			Name:   agentPath,
			Digest: map[string]string{"sha256": trimSHA(archiveDigest)},
		}},
		PredicateType: PredicateType,
		Predicate: PublishPredicate{
			Registry: registry, Agent: agentPath, Version: version,
			CommitSHA: commitSHA, Source: source, ScanRun: run,
			PolicyVer: policyVersion, PublishedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}
}

// BuildRulesetStatement assembles the in-toto statement for a rule bundle:
// subject "ruleset" with the bundle's content digest.
func BuildRulesetStatement(registry, semver, bundleDigest string) InTotoStatement {
	return InTotoStatement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []Subject{{
			Name:   "ruleset",
			Digest: map[string]string{"sha256": trimSHA(bundleDigest)},
		}},
		PredicateType: RulesetPredicateType,
		Predicate: RulesetPredicate{
			Registry: registry, Semver: semver, SignedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}
}

func trimSHA(d string) string {
	if len(d) > 7 && d[:7] == "sha256:" {
		return d[7:]
	}
	return d
}
