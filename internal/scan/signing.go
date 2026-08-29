package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Provenance & signing (§8.8, D-16). On → published the pipeline builds an
// in-toto Statement, wraps it in a DSSE envelope, and signs with an ECDSA
// P-256 key (KMS on SaaS; file/HSM self-host). The public key is served at a
// well-known endpoint and the CLI verifies offline.

// PredicateType is the Agentry publish attestation predicate (§8.8).
const PredicateType = "https://agentry.dev/attestation/publish/v1"

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

const dssePayloadType = "application/vnd.in-toto+json"

// Signer produces DSSE envelopes. KMS/HSM implement the same interface; the
// file signer is the self-host/dev default (D-16).
type Signer interface {
	// Sign signs a statement, returning the DSSE envelope.
	Sign(stmt InTotoStatement) (DSSEEnvelope, error)
	// KeyID identifies the signing key.
	KeyID() string
	// PublicKeyPEM returns the verification key for the well-known endpoint.
	PublicKeyPEM() string
}

// FileSigner signs with a local ECDSA P-256 key.
type FileSigner struct {
	priv  *ecdsa.PrivateKey
	keyID string
}

// NewFileSigner loads (or, in dev with keyPath=="", generates) a P-256 key.
func NewFileSigner(keyPath string, devMode bool) (*FileSigner, error) {
	var priv *ecdsa.PrivateKey
	if keyPath != "" {
		pemBytes, err := os.ReadFile(keyPath) //nolint:gosec // operator-configured path
		if err != nil {
			return nil, fmt.Errorf("scan: read signing key: %w", err)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("scan: signing key: not PEM")
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("scan: parse signing key: %w", err)
		}
		priv = k
	} else {
		if !devMode {
			return nil, fmt.Errorf("scan: file signer requires a key path outside dev mode")
		}
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = k
	}
	return &FileSigner{priv: priv, keyID: keyIDFor(&priv.PublicKey)}, nil
}

// KeyID implements Signer.
func (s *FileSigner) KeyID() string { return s.keyID }

// PublicKeyPEM implements Signer.
func (s *FileSigner) PublicKeyPEM() string {
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// Sign implements Signer: DSSE PAE over the in-toto statement.
func (s *FileSigner) Sign(stmt InTotoStatement) (DSSEEnvelope, error) {
	payload, err := json.Marshal(stmt)
	if err != nil {
		return DSSEEnvelope{}, err
	}
	pae := dssePAE(dssePayloadType, payload)
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		return DSSEEnvelope{}, fmt.Errorf("scan: sign: %w", err)
	}
	return DSSEEnvelope{
		PayloadType: dssePayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []DSSESignature{{KeyID: s.keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// VerifyEnvelope checks a DSSE envelope against a PEM public key. Used by the
// CLI (offline) and tests.
func VerifyEnvelope(env DSSEEnvelope, publicKeyPEM string) (InTotoStatement, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return InTotoStatement{}, fmt.Errorf("scan: verify: bad public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return InTotoStatement{}, fmt.Errorf("scan: verify: parse key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return InTotoStatement{}, fmt.Errorf("scan: verify: not an ECDSA key")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return InTotoStatement{}, fmt.Errorf("scan: verify: payload decode: %w", err)
	}
	pae := dssePAE(env.PayloadType, payload)
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
		return InTotoStatement{}, fmt.Errorf("scan: verify: no valid signature")
	}
	var stmt InTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return InTotoStatement{}, err
	}
	return stmt, nil
}

// dssePAE is the DSSE Pre-Authentication Encoding.
func dssePAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), payload))
}

// keyIDFor derives a stable key id from the public key (sha256 of DER).
func keyIDFor(pub *ecdsa.PublicKey) string {
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

// SignerOptions selects and configures the signer (D-16: none|file|kms).
type SignerOptions struct {
	Kind string // none | file | kms
	// KeyFile is the file signer's PEM private key.
	KeyFile string
	// KMSKeyARN identifies the KMS key (kms kind).
	KMSKeyARN string
	// KMSRegion overrides the ambient region for the KMS client.
	KMSRegion string
	// DevMode allows the ephemeral in-memory key.
	DevMode bool
}

// NewSigner builds the configured signer (D-16: none|file|kms).
func NewSigner(ctx context.Context, opt SignerOptions) (Signer, error) {
	switch opt.Kind {
	case "file":
		return NewFileSigner(opt.KeyFile, opt.DevMode)
	case "none":
		if opt.DevMode {
			return NewFileSigner("", true) // ephemeral dev key
		}
		return nil, fmt.Errorf("scan: signing.kind none not allowed outside dev")
	case "kms":
		return NewKMSSigner(ctx, KMSOptions{KeyARN: opt.KMSKeyARN, Region: opt.KMSRegion})
	default:
		return nil, fmt.Errorf("scan: unknown signer kind %q", opt.Kind)
	}
}
