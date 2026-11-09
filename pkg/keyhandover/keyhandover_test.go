package keyhandover

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/pkg/attest"
	"github.com/blaktron/agentry/pkg/managedsettings"
)

const reg = "https://registry.example"

type testKey struct {
	priv *ecdsa.PrivateKey
	Key
}

func newKey(t *testing.T) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return testKey{priv: priv, Key: Key{KeyID: attest.KeyIDFor(&priv.PublicKey), Algorithm: Algorithm, PublicKeyPEM: pemText}}
}

func (k testKey) sign(t *testing.T, payloadType string, payload []byte) attest.DSSESignature {
	t.Helper()
	digest := sha256.Sum256(attest.PAE(payloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return attest.DSSESignature{KeyID: k.KeyID, Sig: base64.StdEncoding.EncodeToString(sig)}
}

// handover is from's signed statement handing over to to.
func handover(t *testing.T, registry string, from, to testKey) Envelope {
	t.Helper()
	payload, err := Seal(Handover{Schema: Schema, Registry: registry, From: from.KeyID, To: to.Key, At: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return Wrap(payload, from.sign(t, PayloadType, payload))
}

func ids(hs []Handover) string {
	var out []string
	for _, h := range hs {
		out = append(out, h.To.KeyID)
	}
	return strings.Join(out, ",")
}

func TestFollowAdoptsOneAndTwoLinksInOrder(t *testing.T) {
	a, b, c := newKey(t), newKey(t), newKey(t)
	// Served out of order: the walk still adopts b before c.
	chain := Chain{Registry: reg, Handovers: []Envelope{handover(t, reg, b, c), handover(t, reg, a, b)}}

	got, err := Follow(reg, []Key{a.Key}, chain, nil)
	if err != nil || ids(got) != b.KeyID+","+c.KeyID {
		t.Fatalf("from a: %q %v", ids(got), err)
	}
	got, err = Follow(reg+"/", []Key{b.Key}, chain, nil)
	if err != nil || ids(got) != c.KeyID {
		t.Fatalf("from b: %q %v", ids(got), err)
	}
	got, err = Follow(reg, []Key{c.Key}, chain, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("from the newest key: %q %v", ids(got), err)
	}
}

func TestFollowPassesOverWhatNoTrustedKeySigned(t *testing.T) {
	a, b, c, x := newKey(t), newKey(t), newKey(t), newKey(t)

	// A link signed by a key this client never trusted proves nothing.
	got, _ := Follow(reg, []Key{a.Key}, Chain{Registry: reg, Handovers: []Envelope{handover(t, reg, x, c)}}, nil)
	if len(got) != 0 {
		t.Fatalf("a handover from an untrusted key was adopted: %q", ids(got))
	}

	// A broken link: the second statement is signed by a key that is not
	// the first one's successor, so the chain stops at b.
	got, _ = Follow(reg, []Key{a.Key}, Chain{Registry: reg, Handovers: []Envelope{handover(t, reg, a, b), handover(t, reg, x, c)}}, nil)
	if ids(got) != b.KeyID {
		t.Fatalf("a broken chain: %q", ids(got))
	}

	// A statement whose payload was changed after signing.
	env := handover(t, reg, a, b)
	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	env.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), b.KeyID, c.KeyID, 1)))
	got, _ = Follow(reg, []Key{a.Key}, Chain{Registry: reg, Handovers: []Envelope{env}}, nil)
	if len(got) != 0 {
		t.Fatalf("a tampered handover was adopted: %q", ids(got))
	}
}

func TestFollowRefusesAnotherRegistrysHandover(t *testing.T) {
	a, b := newKey(t), newKey(t)
	if _, err := Follow(reg, []Key{a.Key}, Chain{Registry: "https://other.example", Handovers: []Envelope{handover(t, reg, a, b)}}, nil); err == nil {
		t.Fatal("another registry's chain was walked")
	}
	got, err := Follow(reg, []Key{a.Key}, Chain{Registry: reg, Handovers: []Envelope{handover(t, "https://other.example", a, b)}}, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("a handover for another registry was adopted: %q %v", ids(got), err)
	}
}

func TestOpenRefusesAStatementThatDoesNotMatchItsKeys(t *testing.T) {
	a, b, c := newKey(t), newKey(t), newKey(t)

	// The statement names an incoming key id that is not its key's.
	h := Handover{Schema: Schema, Registry: reg, From: a.KeyID, To: Key{KeyID: c.KeyID, Algorithm: Algorithm, PublicKeyPEM: b.PublicKeyPEM}, At: time.Now()}
	if _, err := Seal(h); err == nil {
		t.Fatal("a statement naming one key and carrying another was sealed")
	}

	// Signed by a, but naming b as the outgoing key.
	payload := []byte(`{"schema":"` + Schema + `","registry":"` + reg + `","from":"` + b.KeyID + `","to":{"keyId":"` + c.KeyID + `","algorithm":"` + Algorithm + `","publicKeyPem":` + jsonString(c.PublicKeyPEM) + `},"at":"2026-11-09T12:00:00Z"}`)
	if _, err := Open(Wrap(payload, a.sign(t, PayloadType, payload)), a.PublicKeyPEM); err == nil {
		t.Fatal("a statement naming another outgoing key was opened")
	}
	if _, err := Open(handover(t, reg, a, b), b.PublicKeyPEM); err == nil {
		t.Fatal("a handover verified with a key that did not sign it")
	}
}

func TestPayloadTypesAreKeptApart(t *testing.T) {
	a, b := newKey(t), newKey(t)
	env := handover(t, reg, a, b)
	if _, err := attest.VerifyEnvelope(env, a.PublicKeyPEM); err == nil {
		t.Fatal("a handover verified as an attestation")
	}
	if _, err := managedsettings.Open(env, a.PublicKeyPEM); err == nil {
		t.Fatal("a handover opened as a managed settings document")
	}

	// The same payload bytes signed as another type do not open as a handover.
	payload, _ := Seal(Handover{Schema: Schema, Registry: reg, From: a.KeyID, To: b.Key, At: time.Now()})
	other := Envelope{PayloadType: attest.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: []attest.DSSESignature{a.sign(t, attest.PayloadType, payload)}}
	if _, err := Open(other, a.PublicKeyPEM); err == nil {
		t.Fatal("an envelope of another payload type opened as a handover")
	}
	relabelled := other
	relabelled.PayloadType = PayloadType
	if _, err := Open(relabelled, a.PublicKeyPEM); err == nil {
		t.Fatal("a signature over another payload type verified once the type was relabelled")
	}
}

func jsonString(s string) string {
	b := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
	return `"` + b + `"`
}
