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

	"github.com/blaktron/agentry/pkg/attest"
)

// Provenance & signing (§8.8, D-16). On → published the pipeline builds an
// in-toto Statement, wraps it in a DSSE envelope, and signs with an ECDSA
// P-256 key (KMS on SaaS; file/HSM self-host). The public key is served at a
// well-known endpoint and the CLI verifies offline.
//
// The attestation FORMAT — statement, predicate, envelope, verification — is
// the public pkg/attest package (the CLI and third parties consume it). The
// aliases below keep this package's historical names working; producing
// signatures (the Signer implementations) stays server-internal.

// Aliases for the promoted public attestation API (pkg/attest).
type (
	InTotoStatement  = attest.InTotoStatement
	Subject          = attest.Subject
	PublishPredicate = attest.PublishPredicate
	ScanRunRef       = attest.ScanRunRef
	DSSEEnvelope     = attest.DSSEEnvelope
	DSSESignature    = attest.DSSESignature
)

// PredicateType is the Agentry publish attestation predicate (§8.8).
const PredicateType = attest.PredicateType

// VerifyEnvelope and BuildStatement live in pkg/attest; re-exported for the
// server-side call sites and tests that predate the promotion.
var (
	VerifyEnvelope = attest.VerifyEnvelope
	BuildStatement = attest.BuildStatement
)

// Signer produces DSSE envelopes. KMS/HSM implement the same interface; the
// file signer is the self-host/dev default (D-16).
type Signer interface {
	// Sign signs a statement, returning the DSSE envelope.
	Sign(stmt InTotoStatement) (DSSEEnvelope, error)
	// SignPayload signs an already-encoded DSSE payload and returns the one
	// signature. Sign is a marshal plus this; the re-attestation sweep uses
	// it directly, because a countersignature must cover the payload bytes
	// the envelope already holds — a re-marshalled statement could differ by
	// a byte and every old signature would stop verifying (agentry#350).
	SignPayload(payloadType string, payload []byte) (DSSESignature, error)
	// KeyID identifies the signing key.
	KeyID() string
	// PublicKeyPEM returns the verification key for the well-known endpoint.
	PublicKeyPEM() string
}

// SigningAlgorithm is the one algorithm §8.8 fixes; every key the registry
// publishes or records carries it.
const SigningAlgorithm = "ecdsa-p256-sha256"

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
	return &FileSigner{priv: priv, keyID: attest.KeyIDFor(&priv.PublicKey)}, nil
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
	sig, err := s.SignPayload(attest.PayloadType, payload)
	if err != nil {
		return DSSEEnvelope{}, err
	}
	return DSSEEnvelope{
		PayloadType: attest.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []DSSESignature{sig},
	}, nil
}

// SignPayload implements Signer.
func (s *FileSigner) SignPayload(payloadType string, payload []byte) (DSSESignature, error) {
	pae := attest.PAE(payloadType, payload)
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		return DSSESignature{}, fmt.Errorf("scan: sign: %w", err)
	}
	return DSSESignature{KeyID: s.keyID, Sig: base64.StdEncoding.EncodeToString(sig)}, nil
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
