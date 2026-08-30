// Package attest is the public attestation format for published versions
// (§8.8, D-16): the in-toto v1 statement, the publish predicate, the DSSE
// envelope, and offline verification. It is what the CLI — and any
// third-party client — needs to verify a release against the registry's
// well-known signing keys; producing signatures stays server-side.
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

// PredicateType is the Agentry publish attestation predicate (§8.8).
const PredicateType = "https://agentry.dev/attestation/publish/v1"

// PayloadType is the DSSE payload type for in-toto statements.
const PayloadType = "application/vnd.in-toto+json"

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

// PublishPredicate is the §8.8 predicate.
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

// ScanRunRef records reproducibility fields (§8.8).
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

// VerifyEnvelope checks a DSSE envelope against a PEM public key. Used by the
// CLI (offline), the server's own tests, and third-party verifiers.
func VerifyEnvelope(env DSSEEnvelope, publicKeyPEM string) (InTotoStatement, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return InTotoStatement{}, fmt.Errorf("attest: verify: bad public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return InTotoStatement{}, fmt.Errorf("attest: verify: parse key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return InTotoStatement{}, fmt.Errorf("attest: verify: not an ECDSA key")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return InTotoStatement{}, fmt.Errorf("attest: verify: payload decode: %w", err)
	}
	pae := PAE(env.PayloadType, payload)
	digest := sha256.Sum256(pae)
	ok = false
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if ecdsa.VerifyASN1(ecPub, digest[:], sig) {
			ok = true
			break
		}
	}
	if !ok {
		return InTotoStatement{}, fmt.Errorf("attest: verify: no valid signature")
	}
	var stmt InTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return InTotoStatement{}, err
	}
	return stmt, nil
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

func trimSHA(d string) string {
	if len(d) > 7 && d[:7] == "sha256:" {
		return d[7:]
	}
	return d
}
