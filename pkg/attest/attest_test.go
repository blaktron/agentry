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
	"strings"
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
	// The payload type is signed with the payload: the same signature over
	// a relabelled envelope does not verify.
	relabelled := env
	relabelled.PayloadType = "application/json"
	if _, err := VerifyEnvelope(relabelled, pub); err == nil {
		t.Fatal("an envelope with another payload type verified")
	}
	// Any one valid signature verifies, after one that does not decode or
	// does not match; none valid does not.
	good := env.Signatures[0]
	junk := DSSESignature{KeyID: "x", Sig: "not base64!"}
	wrong := DSSESignature{KeyID: "y", Sig: base64.StdEncoding.EncodeToString([]byte("not a signature"))}
	env.Signatures = []DSSESignature{junk, wrong, good}
	if _, err := VerifyEnvelope(env, pub); err != nil {
		t.Fatalf("a valid signature after two invalid ones: %v", err)
	}
	env.Signatures = []DSSESignature{junk, wrong}
	if _, err := VerifyEnvelope(env, pub); err == nil || !strings.Contains(err.Error(), "no valid signature") {
		t.Fatalf("no valid signature: err = %v", err)
	}
	env.Signatures = []DSSESignature{good}
	// A tampered payload does not verify.
	env.Payload = base64.StdEncoding.EncodeToString(append(payload, ' '))
	if _, err := VerifyEnvelope(env, pub); err == nil {
		t.Fatal("tampered envelope verified")
	}
	// PAE is the DSSE specification's encoding, byte for byte: a
	// round trip alone would pass with any encoding both sides share,
	// and a third party verifies against the specification's.
	if got, want := string(PAE("http://example.com/HelloWorld", []byte("hello world"))), "DSSEv1 29 http://example.com/HelloWorld 11 hello world"; got != want {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
}
