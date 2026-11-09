package managedsettings

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
	"time"

	"github.com/blaktron/agentry/pkg/attest"
)

type testKey struct {
	priv *ecdsa.PrivateKey
	pem  string
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
	return testKey{priv: priv, pem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
}

func (k testKey) sign(t *testing.T, payloadType string, payload []byte) attest.DSSESignature {
	t.Helper()
	digest := sha256.Sum256(attest.PAE(payloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return attest.DSSESignature{KeyID: "test", Sig: base64.StdEncoding.EncodeToString(sig)}
}

func str(v string) json.RawMessage { b, _ := json.Marshal(v); return b }

func validDoc() Document {
	return Document{
		Schema:   Schema,
		Registry: "https://registry.example",
		Org:      "acme",
		Version:  3,
		IssuedAt: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC),
		Settings: map[string]Setting{UnsafeMode: {Value: str(UnsafeModeForbidden), Locked: true}},
	}
}

func TestOpenRoundTrip(t *testing.T) {
	k := newKey(t)
	payload, err := Seal(validDoc())
	if err != nil {
		t.Fatal(err)
	}
	env := Wrap(payload, k.sign(t, PayloadType, payload))
	got, err := Open(env, k.pem)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := got.Settings[UnsafeMode]
	if s.String() != UnsafeModeForbidden || !s.Locked || got.Org != "acme" || got.Version != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestOpenRefusesAnotherKey(t *testing.T) {
	k, other := newKey(t), newKey(t)
	payload, _ := Seal(validDoc())
	if _, err := Open(Wrap(payload, k.sign(t, PayloadType, payload)), other.pem); err == nil {
		t.Fatal("a document signed by another key opened")
	}
}

func TestOpenRefusesAnotherPayloadType(t *testing.T) {
	k := newKey(t)
	payload, _ := Seal(validDoc())
	// Signed as an in-toto statement and relabelled: the type check
	// refuses it before the signature is read.
	env := Wrap(payload, k.sign(t, attest.PayloadType, payload))
	env.PayloadType = attest.PayloadType
	if _, err := Open(env, k.pem); err == nil || !strings.Contains(err.Error(), "payload type") {
		t.Fatalf("Open = %v, want a payload type refusal", err)
	}
	// Signed as an attestation but labelled as a document: PAE covers the
	// type, so the signature does not verify.
	env = Wrap(payload, k.sign(t, attest.PayloadType, payload))
	if _, err := Open(env, k.pem); err == nil {
		t.Fatal("a signature over another payload type verified")
	}
}

func TestAttestationVerifierRefusesADocument(t *testing.T) {
	k := newKey(t)
	payload, _ := Seal(validDoc())
	env := Wrap(payload, k.sign(t, PayloadType, payload))
	if _, err := attest.VerifyEnvelope(env, k.pem); err == nil {
		t.Fatal("a managed settings document verified as an attestation")
	}
}

func TestOpenRefusesTamperedPayload(t *testing.T) {
	k := newKey(t)
	payload, _ := Seal(validDoc())
	env := Wrap(payload, k.sign(t, PayloadType, payload))
	d := validDoc()
	d.Settings[UnsafeMode] = Setting{Value: str(UnsafeModeAllowed), Locked: true}
	edited, _ := json.Marshal(d)
	env.Payload = base64.StdEncoding.EncodeToString(edited)
	if _, err := Open(env, k.pem); err == nil {
		t.Fatal("an edited payload opened")
	}
}

func TestOpenRefusesUnknownFieldsAndRows(t *testing.T) {
	k := newKey(t)
	for name, payload := range map[string]string{
		"unknown field": `{"schema":"managed-settings/1","registry":"r","org":"o","version":1,"issuedAt":"2026-11-08T12:00:00Z","settings":{},"extra":1}`,
		"bad value":     `{"schema":"managed-settings/1","registry":"r","org":"o","version":1,"issuedAt":"2026-11-08T12:00:00Z","settings":{"run.unsafeMode":{"value":"on","locked":true}}}`,
		"other schema":  `{"schema":"managed-settings/2","registry":"r","org":"o","version":1,"issuedAt":"2026-11-08T12:00:00Z","settings":{}}`,
		"trailing data": `{"schema":"managed-settings/1","registry":"r","org":"o","version":1,"issuedAt":"2026-11-08T12:00:00Z","settings":{}} {}`,
	} {
		env := Wrap([]byte(payload), k.sign(t, PayloadType, []byte(payload)))
		if _, err := Open(env, k.pem); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestValidateRefusesMissingBinding(t *testing.T) {
	for name, edit := range map[string]func(*Document){
		"registry": func(d *Document) { d.Registry = "" },
		"org":      func(d *Document) { d.Org = "" },
		"version":  func(d *Document) { d.Version = 0 },
		"issuedAt": func(d *Document) { d.IssuedAt = time.Time{} },
	} {
		d := validDoc()
		edit(&d)
		if _, err := Seal(d); err == nil {
			t.Errorf("Seal accepted a document with no %s", name)
		}
	}
}

// TestNoRowTurnsAnythingOn holds the catalogue to its rule: a row's values
// only narrow, so no value may switch a capability on. A choice's first
// value is the open one and none names an "on" state; a set lists only
// what a member could already use; a cap is a limit, never a floor.
func TestNoRowTurnsAnythingOn(t *testing.T) {
	for _, r := range Catalogue() {
		switch r.Kind {
		case KindChoice:
			if len(r.Values) < 2 {
				t.Errorf("%s: a choice needs an open value and at least one narrower one", r.ID)
			}
		case KindSet:
			if len(r.Values) < 2 {
				t.Errorf("%s: a set needs at least two members to narrow", r.ID)
			}
		case KindCap:
			if r.Max <= 0 {
				t.Errorf("%s: a cap needs a largest value", r.ID)
			}
		case KindModel:
			if len(r.Values) < 2 {
				t.Errorf("%s: a model row needs providers to choose among", r.ID)
			}
		case KindSource:
			if len(r.Values) < 2 || r.Values[0] != SourceMember {
				t.Errorf("%s: a source row starts from the member's own and narrows from there", r.ID)
			}
		case KindSources, KindMinimumVersion:
		default:
			t.Errorf("%s: kind %q", r.ID, r.Kind)
		}
		for _, v := range r.Values {
			switch strings.ToLower(v) {
			case "on", "enabled", "true", "required-on", "forced":
				t.Errorf("%s: value %q would switch something on", r.ID, v)
			}
		}
		if r.Summary == "" {
			t.Errorf("%s: no summary", r.ID)
		}
	}
}

// TestEveryRowTakesOnlyItsValues is the table over every row and value
// class: what each kind accepts, what it refuses, and that a row which is
// only ever locked refuses a default.
func TestEveryRowTakesOnlyItsValues(t *testing.T) {
	set := func(v string, locked bool) Setting { return Setting{Value: json.RawMessage(v), Locked: locked} }
	accepted := map[Kind][]string{
		KindSet:            {`["local"]`, `["local","hosted"]`},
		KindCap:            {`1`, `600`},
		KindSources:        {`{"scope":"any"}`, `{"scope":"organization-and-built-ins"}`, `{"scope":"organization-and-built-ins","namespaces":["acme","tools-1"]}`},
		KindMinimumVersion: {`"0.7.38"`, `"1.0.0"`},
		KindModel:          {`{"provider":"anthropic","model":"claude-sonnet-5-5"}`, `{"provider":"custom","model":"llama-4:70b"}`},
	}
	refused := map[Kind][]string{
		KindChoice:         {`"on"`, `"enabled"`, `""`, `true`, `["allowed"]`, `null`},
		KindSet:            {`[]`, `["everywhere"]`, `["local","local"]`, `"local"`, `null`, `["local"] 1`},
		KindCap:            {`0`, `-5`, `"600"`, `1e12`, `null`, `true`},
		KindSources:        {`{"scope":"everywhere"}`, `{"scope":"any","namespaces":["acme"]}`, `{"scope":"organization-and-built-ins","namespaces":["Bad Name"]}`, `{"scope":"any","extra":1}`, `"any"`, `null`},
		KindMinimumVersion: {`"v0.7.38"`, `"0.7"`, `"0.7.38-dev.1"`, `0.7`, `null`},
		KindModel:          {`{"provider":"acme","model":"m"}`, `{"provider":"anthropic","model":""}`, `{"provider":"anthropic","model":"a b"}`, `{"provider":"anthropic"}`, `{"provider":"anthropic","model":"m","key":"k"}`, `"anthropic"`, `null`},
		KindSource:         {`{"source":"everyone"}`, `{"source":"member","key":{"id":"k1","rev":1}}`, `{"source":"member","provider":"brave"}`, `"member"`, `null`, `{"source":"member","extra":1}`},
	}
	for _, r := range Catalogue() {
		good := accepted[r.Kind]
		if r.Kind == KindChoice {
			for _, v := range r.Values {
				good = append(good, `"`+v+`"`)
			}
		}
		if r.Kind == KindSet {
			good = []string{`["` + r.Values[0] + `"]`, `["` + strings.Join(r.Values, `","`) + `"]`}
			if r.AllowEmpty {
				good = append(good, `[]`)
			}
		}
		if r.Kind == KindSource {
			for _, v := range r.Values {
				switch {
				case v != SourceOrganizationKey:
					good = append(good, `{"source":"`+v+`"}`)
				case r.Delivers && len(r.Providers) > 0:
					good = append(good, `{"source":"organization-key","provider":"`+r.Providers[0]+`","key":{"id":"key-1","rev":3}}`)
				case r.Delivers:
					good = append(good, `{"source":"organization-key","key":{"id":"key-1","rev":3}}`)
				default:
					good = append(good, `{"source":"organization-key"}`)
				}
			}
		}
		if len(good) == 0 {
			t.Errorf("%s: no accepted value in the table for kind %s", r.ID, r.Kind)
		}
		for _, v := range good {
			if err := r.Check(set(v, true)); err != nil {
				t.Errorf("%s: locked %s refused: %v", r.ID, v, err)
			}
			err := r.Check(set(v, false))
			if r.LockOnly && err == nil {
				t.Errorf("%s: a default %s was accepted for a row that is only ever locked", r.ID, v)
			}
			if !r.LockOnly && err != nil {
				t.Errorf("%s: default %s refused: %v", r.ID, v, err)
			}
		}
		for _, v := range refused[r.Kind] {
			if r.AllowEmpty && v == `[]` {
				continue
			}
			if err := r.Check(set(v, true)); err == nil {
				t.Errorf("%s: %s was accepted", r.ID, v)
			}
		}
		if r.Kind == KindCap {
			if r.Integer {
				if err := r.Check(set(`1.5`, true)); err == nil {
					t.Errorf("%s: a fraction was accepted for a whole-number cap", r.ID)
				}
			}
			over, _ := json.Marshal(r.Max + 1)
			if err := r.Check(set(string(over), true)); err == nil {
				t.Errorf("%s: %s, above the largest cap, was accepted", r.ID, over)
			}
		}
	}
}

// TestOpenKeepsRowsANewerRegistryAdded: a client opens a document with a
// row its catalogue does not know, and Unknown names it with its lock, so
// the client can refuse to run rather than drop a lock it cannot enforce.
// A registry never signs such a row itself.
func TestOpenKeepsRowsANewerRegistryAdded(t *testing.T) {
	k := newKey(t)
	payload := []byte(`{"schema":"managed-settings/1","registry":"r","org":"o","version":1,"issuedAt":"2026-11-08T12:00:00Z","settings":{"run.unsafeMode":{"value":"forbidden","locked":true},"run.later":{"value":"x","locked":true},"run.laterDefault":{"value":"y","locked":false}}}`)
	d, err := Open(Wrap(payload, k.sign(t, PayloadType, payload)), k.pem)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := d.Unknown()
	want := []UnknownSetting{{ID: "run.later", Locked: true}, {ID: "run.laterDefault", Locked: false}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Unknown = %+v, want %+v", got, want)
	}
	if _, err := Seal(d); err == nil {
		t.Fatal("Seal signed a row off the catalogue")
	}
}
