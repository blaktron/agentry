package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAPI is the slice of the KMS client KMSSigner uses. Two calls, so the
// tests can substitute an in-process fake and never reach AWS (DEV-029).
type KMSAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// KMSOptions configures the KMS signer.
type KMSOptions struct {
	// KeyARN is the key id/ARN/alias to sign with.
	KeyARN string
	// Region overrides the ambient region.
	Region string
}

// KMSSigner signs DSSE envelopes with a KMS-held ECDSA P-256 key (D-16, §8.8).
// The private key never leaves KMS; only kms:Sign is called, and only from the
// worker role — which is what makes the T-09 "KMS Sign anomaly" alarm
// meaningful, since any other caller is by definition unexpected.
type KMSSigner struct {
	api    KMSAPI
	keyARN string
	// pubPEM is fetched once at construction. Caching it keeps the
	// well-known endpoint off the KMS API path, so a scrape of
	// signing-keys.json cannot be turned into KMS request volume — and it
	// makes the T-09 signal purely about signing.
	pubPEM string
	keyID  string
}

// NewKMSSigner builds a signer over the ambient AWS credential chain and
// verifies up front that the key is usable: an attestation key that cannot be
// read is a deployment fault, and it should surface at startup rather than on
// the first publish.
func NewKMSSigner(ctx context.Context, opt KMSOptions) (*KMSSigner, error) {
	if opt.KeyARN == "" {
		return nil, errors.New("scan: signing.kmsKeyARN is required for the kms signer")
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{}
	if opt.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(opt.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("scan: aws config: %w", err)
	}
	return NewKMSSignerWithAPI(ctx, kms.NewFromConfig(cfg), opt.KeyARN)
}

// NewKMSSignerWithAPI builds a signer over an existing client (tests, and
// callers holding a configured kms.Client).
func NewKMSSignerWithAPI(ctx context.Context, api KMSAPI, keyARN string) (*KMSSigner, error) {
	s := &KMSSigner{api: api, keyARN: keyARN}
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyARN)})
	if err != nil {
		return nil, fmt.Errorf("scan: kms get public key: %w", err)
	}
	if out.KeySpec != "" && out.KeySpec != kmstypes.KeySpecEccNistP256 {
		// §8.8 fixes the algorithm at ECDSA P-256; a key of another spec
		// would produce envelopes the CLI cannot verify.
		return nil, fmt.Errorf("scan: kms key spec is %s, want %s", out.KeySpec, kmstypes.KeySpecEccNistP256)
	}
	if len(out.PublicKey) == 0 {
		return nil, errors.New("scan: kms returned an empty public key")
	}
	pub, err := parseECDSAPublicKeyDER(out.PublicKey)
	if err != nil {
		return nil, err
	}
	s.pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: out.PublicKey}))
	// Same derivation as the file signer, so a key id identifies the key
	// material rather than the backend that happens to hold it. Rotating from
	// file to KMS with the same key would keep the id stable, and the CLI's
	// TOFU pin (§8.8) would not see a discontinuity where there is none.
	s.keyID = keyIDFor(pub)
	return s, nil
}

// KeyID implements Signer.
func (s *KMSSigner) KeyID() string { return s.keyID }

// PublicKeyPEM implements Signer.
func (s *KMSSigner) PublicKeyPEM() string { return s.pubPEM }

// Sign implements Signer: DSSE PAE over the in-toto statement, hashed locally
// and signed by KMS as a digest. Sending the digest rather than the message
// keeps the payload out of CloudTrail and off the wire, and is the only option
// once a statement exceeds the 4 KB raw-message limit.
func (s *KMSSigner) Sign(stmt InTotoStatement) (DSSEEnvelope, error) {
	payload, err := json.Marshal(stmt)
	if err != nil {
		return DSSEEnvelope{}, err
	}
	pae := dssePAE(dssePayloadType, payload)
	digest := sha256.Sum256(pae)

	out, err := s.api.Sign(context.Background(), &kms.SignInput{
		KeyId:            aws.String(s.keyARN),
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return DSSEEnvelope{}, fmt.Errorf("scan: kms sign: %w", err)
	}
	if len(out.Signature) == 0 {
		return DSSEEnvelope{}, errors.New("scan: kms returned an empty signature")
	}
	// KMS returns a DER-encoded ASN.1 ECDSA signature — byte-identical in
	// form to ecdsa.SignASN1 — so VerifyEnvelope and the CLI verify a KMS
	// envelope and a file envelope by exactly the same code path.
	return DSSEEnvelope{
		PayloadType: dssePayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []DSSESignature{{
			KeyID: s.keyID,
			Sig:   base64.StdEncoding.EncodeToString(out.Signature),
		}},
	}, nil
}

// parseECDSAPublicKeyDER decodes a PKIX/SPKI DER public key and insists it is
// ECDSA.
func parseECDSAPublicKeyDER(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("scan: parse kms public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("scan: kms public key is %T, want ECDSA", pub)
	}
	return ec, nil
}
