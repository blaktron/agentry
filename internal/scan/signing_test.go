package scan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/attest"
)

// TestAttestationRoundTrip pins that a signed DSSE envelope verifies offline
// against the served public key, and tampering breaks verification (this is
// what the CLI's `verify` does).
func TestAttestationRoundTrip(t *testing.T) {
	signer, err := NewFileSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	stmt := BuildStatement(
		"https://agentry.example", "acme/incident-summarizer", "1.4.2",
		"sha256:abcd1234", "deadbeef", "git-tag",
		ScanRunRef{ID: "run-1", RulesetVer: "0.1.0", ReportDigest: "sha256:report", JudgeModel: "static"},
		1,
	)
	env, err := signer.Sign(stmt)
	if err != nil {
		t.Fatal(err)
	}

	got, err := VerifyEnvelope(env, signer.PublicKeyPEM())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(got.Subject) != 1 || got.Subject[0].Digest["sha256"] != "abcd1234" {
		t.Fatalf("subject digest mismatch: %+v", got.Subject)
	}
	if got.PredicateType != PredicateType {
		t.Fatalf("predicate type: %s", got.PredicateType)
	}

	// Tamper with the payload → verification fails.
	env.Payload = env.Payload[:len(env.Payload)-4] + "AAAA"
	if _, err := VerifyEnvelope(env, signer.PublicKeyPEM()); err == nil {
		t.Fatal("tampered envelope must fail verification")
	}

	// Wrong key → verification fails.
	other, _ := NewFileSigner("", true)
	env2, _ := signer.Sign(stmt)
	if _, err := VerifyEnvelope(env2, other.PublicKeyPEM()); err == nil {
		t.Fatal("verification under the wrong key must fail")
	}

	// The payload is standard base64: a statement whose encoding has "+" or
	// "/" in it verifies as well.
	odd := BuildStatement("https://agentry.example", "acme/??????????", "1.0.0", "sha256:abcd", "", "upload", ScanRunRef{ID: "run-2"}, 1)
	oddEnv, err := signer.Sign(odd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.ContainsAny(oddEnv.Payload, "+/") {
		t.Fatalf("setup: payload %q has neither + nor /", oddEnv.Payload)
	}
	if _, err := VerifyEnvelope(oddEnv, signer.PublicKeyPEM()); err != nil {
		t.Fatalf("an envelope whose payload encodes with + or /: %v", err)
	}

	// The published key is a PKIX PEM public key, and the algorithm the
	// registry records for it is the one it signs with.
	block, _ := pem.Decode([]byte(signer.PublicKeyPEM()))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("PublicKeyPEM = %q, want a PUBLIC KEY block", signer.PublicKeyPEM())
	}
	if SigningAlgorithm != "ecdsa-p256-sha256" {
		t.Fatalf("SigningAlgorithm = %q", SigningAlgorithm)
	}
}

// writeKeyFile stores a freshly generated P-256 private key as the PEM a
// file signer loads, and returns its path and the key.
func writeKeyFile(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, k
}

// A file signer loaded from a key file is that key: its id is derived from
// it and its envelopes verify under its public part. Outside dev mode a
// signer has to come from a key file that holds an EC private key.
func TestFileSignerLoadsItsKeyFromAFile(t *testing.T) {
	path, k := writeKeyFile(t)
	for _, dev := range []bool{false, true} {
		s, err := NewFileSigner(path, dev)
		if err != nil {
			t.Fatalf("NewFileSigner(key file, dev %v): %v", dev, err)
		}
		if s.KeyID() != attest.KeyIDFor(&k.PublicKey) {
			t.Fatalf("key id %q is not the key file's (%q)", s.KeyID(), attest.KeyIDFor(&k.PublicKey))
		}
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if want := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); s.PublicKeyPEM() != want {
			t.Fatalf("PublicKeyPEM = %q, want the key file's public part", s.PublicKeyPEM())
		}
		env, err := s.Sign(BuildStatement("r", "a/b", "1.0.0", "sha256:ab", "", "upload", ScanRunRef{ID: "x"}, 1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyEnvelope(env, s.PublicKeyPEM()); err != nil {
			t.Fatalf("an envelope signed with the key file does not verify: %v", err)
		}
		if env.Signatures[0].KeyID != s.KeyID() {
			t.Fatalf("signature key id %q, want %q", env.Signatures[0].KeyID, s.KeyID())
		}
	}
	// Two loads of one file are one key.
	a, _ := NewFileSigner(path, false)
	b, _ := NewFileSigner(path, false)
	if a.KeyID() != b.KeyID() {
		t.Fatal("one key file produced two key ids")
	}

	notPEM := filepath.Join(t.TempDir(), "notpem")
	if err := os.WriteFile(notPEM, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongKind := filepath.Join(t.TempDir(), "wrongkind")
	if err := os.WriteFile(wrongKind, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")}), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path string
		dev  bool
	}{
		"no key path outside dev mode":    {"", false},
		"a missing file":                  {filepath.Join(t.TempDir(), "missing.pem"), false},
		"a missing file in dev mode":      {filepath.Join(t.TempDir(), "missing.pem"), true},
		"a file that is not PEM":          {notPEM, false},
		"a file that is not PEM, in dev":  {notPEM, true},
		"a PEM block that is not EC":      {wrongKind, false},
		"a PEM block that is not EC, dev": {wrongKind, true},
	} {
		if s, err := NewFileSigner(tc.path, tc.dev); err == nil {
			t.Errorf("%s: a signer was built (%s)", name, s.KeyID())
		}
	}
	// Dev mode with no path is an ephemeral key, a different one each time.
	e1, err := NewFileSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := NewFileSigner("", true)
	if e1.KeyID() == "" || e1.KeyID() == e2.KeyID() {
		t.Fatalf("ephemeral dev keys: %q and %q, want two distinct ids", e1.KeyID(), e2.KeyID())
	}
}

func TestNoneProviderForcesReview(t *testing.T) {
	if !(NoneProvider{}).RequiresHumanReview() {
		t.Fatal("none provider must force review")
	}
	if (StaticProvider{}).RequiresHumanReview() {
		t.Fatal("static provider must not force review by itself")
	}
}
