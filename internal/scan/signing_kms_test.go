package scan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/blaktron/agentry/pkg/attest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// fakeKMS signs locally with a generated P-256 key, reproducing the two
// behaviours that matter: a DER SPKI public key, and a DER ASN.1 signature
// over a caller-supplied digest. Live AWS is untested here.
type fakeKMS struct {
	priv     *ecdsa.PrivateKey
	keySpec  kmstypes.KeySpec
	signs    int
	lastIn   *kms.SignInput
	pubErr   error
	signErr  error
	emptyPub bool
	emptySig bool
	// rsaKey answers with an RSA public key, garbage with bytes that are no
	// public key at all, and pubCalls counts the GetPublicKey calls.
	rsaKey   bool
	garbage  bool
	pubCalls int
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &fakeKMS{priv: k, keySpec: kmstypes.KeySpecEccNistP256}
}

func (f *fakeKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.pubCalls++
	if f.pubErr != nil {
		return nil, f.pubErr
	}
	if f.emptyPub {
		return &kms.GetPublicKeyOutput{KeySpec: f.keySpec}, nil
	}
	if f.garbage {
		return &kms.GetPublicKeyOutput{PublicKey: []byte("not a public key"), KeySpec: f.keySpec}, nil
	}
	if f.rsaKey {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
		if err != nil {
			return nil, err
		}
		return &kms.GetPublicKeyOutput{PublicKey: der, KeySpec: f.keySpec}, nil
	}
	der, err := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeySpec: f.keySpec}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signs++
	f.lastIn = in
	if f.signErr != nil {
		return nil, f.signErr
	}
	if f.emptySig {
		return &kms.SignOutput{}, nil
	}
	sig, err := ecdsa.SignASN1(rand.Reader, f.priv, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

var _ KMSAPI = (*fakeKMS)(nil)
var _ Signer = (*KMSSigner)(nil)

func testStatement() InTotoStatement {
	return BuildStatement("registry.example", "acme/widget", "1.0.0",
		"sha256:abc123", "deadbeef", "git",
		ScanRunRef{ID: "run-1", RulesetVer: "1.2.3", ReportDigest: "sha256:def"}, 1)
}

// The whole point of the KMS branch: an envelope it produces verifies through
// the same VerifyEnvelope the CLI uses offline.
func TestKMSSignerProducesAVerifiableEnvelope(t *testing.T) {
	f := newFakeKMS(t)
	s, err := NewKMSSignerWithAPI(t.Context(), f, "arn:aws:kms:us-east-1:1:key/abc")
	if err != nil {
		t.Fatalf("NewKMSSignerWithAPI: %v", err)
	}

	env, err := s.Sign(testStatement())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	stmt, err := VerifyEnvelope(env, s.PublicKeyPEM())
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if len(stmt.Subject) != 1 || stmt.Subject[0].Name != "acme/widget" {
		t.Errorf("round-tripped statement subject = %+v", stmt.Subject)
	}
	if env.Signatures[0].KeyID != s.KeyID() {
		t.Errorf("envelope keyid %q != signer key id %q", env.Signatures[0].KeyID, s.KeyID())
	}
	// What KMS was asked to sign is the digest of the DSSE encoding of the
	// payload the envelope carries.
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(attest.PAE(env.PayloadType, payload)); !bytes.Equal(f.lastIn.Message, want[:]) {
		t.Errorf("KMS signed %x, want the digest of the PAE of the payload (%x)", f.lastIn.Message, want)
	}
	if env.PayloadType != attest.PayloadType {
		t.Errorf("payload type = %q", env.PayloadType)
	}
}

// ECDSA P-256/SHA-256 is fixed, and the digest must be sent as a digest —
// not as a raw message, which would put the payload in CloudTrail and break
// past KMS's 4 KB raw limit.
func TestKMSSignerUsesDigestSigningWithP256(t *testing.T) {
	f := newFakeKMS(t)
	s, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn")
	if err != nil {
		t.Fatalf("NewKMSSignerWithAPI: %v", err)
	}
	if _, err := s.Sign(testStatement()); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if f.lastIn.MessageType != kmstypes.MessageTypeDigest {
		t.Errorf("MessageType = %v, want DIGEST", f.lastIn.MessageType)
	}
	if f.lastIn.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 {
		t.Errorf("SigningAlgorithm = %v, want ECDSA_SHA_256", f.lastIn.SigningAlgorithm)
	}
	if len(f.lastIn.Message) != 32 {
		t.Errorf("Message length = %d, want a 32-byte sha256 digest", len(f.lastIn.Message))
	}
	if *f.lastIn.KeyId != "key-arn" {
		t.Errorf("KeyId = %q", *f.lastIn.KeyId)
	}
}

// The public key is fetched once, so scraping signing-keys.json cannot be
// turned into KMS request volume (and cannot muddy the KMS Sign signal).
func TestKMSSignerCachesThePublicKey(t *testing.T) {
	f := newFakeKMS(t)
	s, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn")
	if err != nil {
		t.Fatalf("NewKMSSignerWithAPI: %v", err)
	}
	first := s.PublicKeyPEM()
	for range 5 {
		if s.PublicKeyPEM() != first {
			t.Fatal("PublicKeyPEM is not stable")
		}
	}
	if !strings.Contains(first, "BEGIN PUBLIC KEY") {
		t.Errorf("PublicKeyPEM is not PEM:\n%s", first)
	}
	if f.signs != 0 {
		t.Errorf("reading the public key called kms:Sign %d times", f.signs)
	}
	if f.pubCalls != 1 {
		t.Errorf("the public key was fetched %d times, want once at construction", f.pubCalls)
	}
	if _, err := s.Sign(testStatement()); err != nil {
		t.Fatal(err)
	}
	if f.pubCalls != 1 {
		t.Errorf("signing fetched the public key again (%d fetches)", f.pubCalls)
	}
}

// A KMS key id derived from key material, not from the ARN: rotating the same
// key between backends must not look like a new key to the CLI's TOFU pin.
func TestKMSKeyIDMatchesTheFileSignerDerivation(t *testing.T) {
	f := newFakeKMS(t)
	s, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn")
	if err != nil {
		t.Fatalf("NewKMSSignerWithAPI: %v", err)
	}
	if want := attest.KeyIDFor(&f.priv.PublicKey); s.KeyID() != want {
		t.Errorf("KeyID = %q, want %q", s.KeyID(), want)
	}
}

func TestNewKMSSignerRejectsBadKeys(t *testing.T) {
	t.Run("empty arn", func(t *testing.T) {
		if _, err := NewKMSSigner(t.Context(), KMSOptions{}); err == nil {
			t.Error("accepted an empty key ARN")
		} else if !strings.Contains(err.Error(), "signing.kmsKeyARN is required") {
			t.Errorf("err = %v, want the missing key ARN named before any AWS call", err)
		}
	})
	t.Run("wrong key spec", func(t *testing.T) {
		f := newFakeKMS(t)
		f.keySpec = kmstypes.KeySpecRsa4096
		_, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn")
		if err == nil || !strings.Contains(err.Error(), "key spec is RSA_4096, want ECC_NIST_P256") {
			t.Errorf("err = %v, want a key-spec refusal naming both specs", err)
		}
	})
	t.Run("unreadable key fails at construction", func(t *testing.T) {
		f := newFakeKMS(t)
		f.pubErr = errors.New("AccessDenied")
		if _, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn"); err == nil {
			t.Error("an unreadable attestation key was accepted at startup")
		}
	})
	t.Run("empty public key", func(t *testing.T) {
		f := newFakeKMS(t)
		f.emptyPub = true
		if _, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn"); err == nil || !strings.Contains(err.Error(), "empty public key") {
			t.Errorf("err = %v, want the empty public key refused as such", err)
		}
	})
	t.Run("a public key that is not ECDSA", func(t *testing.T) {
		f := newFakeKMS(t)
		f.rsaKey = true
		f.keySpec = ""
		if _, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn"); err == nil || !strings.Contains(err.Error(), "want ECDSA") {
			t.Errorf("err = %v, want an RSA public key refused as not ECDSA", err)
		}
	})
	t.Run("a public key that does not parse", func(t *testing.T) {
		f := newFakeKMS(t)
		f.garbage = true
		if _, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn"); err == nil || !strings.Contains(err.Error(), "parse kms public key") {
			t.Errorf("err = %v, want the unparseable public key refused", err)
		}
	})
	t.Run("an unreadable key names the cause", func(t *testing.T) {
		f := newFakeKMS(t)
		f.pubErr = errors.New("AccessDenied")
		if _, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn"); err == nil || !strings.Contains(err.Error(), "kms get public key: AccessDenied") {
			t.Errorf("err = %v, want the cause named", err)
		}
	})
}

func TestKMSSignerSurfacesSigningFailures(t *testing.T) {
	t.Run("api error", func(t *testing.T) {
		f := newFakeKMS(t)
		s, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn")
		if err != nil {
			t.Fatalf("NewKMSSignerWithAPI: %v", err)
		}
		f.signErr = errors.New("KMSInternalException")
		if env, err := s.Sign(testStatement()); err == nil || !strings.Contains(err.Error(), "kms sign: KMSInternalException") {
			t.Errorf("a KMS failure gave %+v, %v; want it refused with the cause", env, err)
		}
	})
	t.Run("empty signature", func(t *testing.T) {
		f := newFakeKMS(t)
		s, err := NewKMSSignerWithAPI(t.Context(), f, "key-arn")
		if err != nil {
			t.Fatalf("NewKMSSignerWithAPI: %v", err)
		}
		f.emptySig = true
		if env, err := s.Sign(testStatement()); err == nil || !strings.Contains(err.Error(), "empty signature") {
			t.Errorf("an empty signature gave %+v, %v; want it refused", env, err)
		}
	})
}

func TestNewSignerDispatch(t *testing.T) {
	t.Run("kms without an arn", func(t *testing.T) {
		_, err := NewSigner(t.Context(), SignerOptions{Kind: "kms"})
		if err == nil {
			t.Fatal("kms signer built with no key ARN")
		}
		if strings.Contains(err.Error(), "not yet wired") {
			t.Errorf("kms is still stubbed out: %v", err)
		}
	})
	t.Run("file in dev", func(t *testing.T) {
		s, err := NewSigner(t.Context(), SignerOptions{Kind: "none", DevMode: true})
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		if s.KeyID() == "" {
			t.Error("dev signer has no key id")
		}
	})
	t.Run("file with a key file", func(t *testing.T) {
		path, k := writeKeyFile(t)
		s, err := NewSigner(t.Context(), SignerOptions{Kind: "file", KeyFile: path})
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		if s.KeyID() != attest.KeyIDFor(&k.PublicKey) {
			t.Errorf("key id %q is not the key file's", s.KeyID())
		}
	})
	t.Run("file without a key file outside dev", func(t *testing.T) {
		if _, err := NewSigner(t.Context(), SignerOptions{Kind: "file"}); err == nil {
			t.Error("a file signer with no key file was built outside dev mode")
		}
	})
	t.Run("file without a key file in dev", func(t *testing.T) {
		s, err := NewSigner(t.Context(), SignerOptions{Kind: "file", DevMode: true})
		if err != nil || s.KeyID() == "" {
			t.Errorf("a dev file signer with no key file: %v", err)
		}
	})
	t.Run("none outside dev", func(t *testing.T) {
		if _, err := NewSigner(t.Context(), SignerOptions{Kind: "none"}); err == nil {
			t.Error("signing.kind none was allowed outside dev")
		}
	})
	t.Run("unknown kind", func(t *testing.T) {
		if _, err := NewSigner(t.Context(), SignerOptions{Kind: "hsm"}); err == nil {
			t.Error("unknown signer kind accepted")
		}
	})
}
