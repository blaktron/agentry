package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// Round trip of the DSSE/in-toto construction this package verifies: PAE
// over the payload, ASN.1 ECDSA P-256 over its SHA-256, PEM public key.
// scripts/dev/attest-fixture + cosign in CI prove the same bytes verify
// with a third-party tool.
func TestEnvelopeRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	stmt := BuildStatement("https://r.example", "ns/agent", "1.2.3", "sha256:abc", "", "cli-upload", ScanRunRef{ID: "run"}, 1)
	payload, _ := json.Marshal(stmt)
	sum := sha256.Sum256(PAE(PayloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	env := DSSEEnvelope{
		PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []DSSESignature{{KeyID: KeyIDFor(&key.PublicKey), Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	got, err := VerifyEnvelope(env, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject[0].Digest["sha256"] != "abc" || got.PredicateType != PredicateType {
		t.Fatalf("statement = %+v", got)
	}
	// A different key does not verify.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	oder, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if _, err := VerifyEnvelope(env, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: oder}))); err == nil {
		t.Fatal("envelope verified with the wrong key")
	}
	// A tampered payload does not verify.
	env.Payload = base64.StdEncoding.EncodeToString(append(payload, ' '))
	if _, err := VerifyEnvelope(env, pub); err == nil {
		t.Fatal("tampered envelope verified")
	}
}
