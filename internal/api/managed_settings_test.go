package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/pkg/attest"
	"github.com/blaktron/agentry/pkg/managedsettings"
)

const (
	managedSettingsPath = "/api/v1/user/managed-settings"
	testRegistryURL     = "https://registry.example"
)

func forbidUnsafe() map[string]managedsettings.Setting {
	return map[string]managedsettings.Setting{
		managedsettings.UnsafeMode: {Value: json.RawMessage(`"forbidden"`), Locked: true},
	}
}

func withRegistryURL(c *config.Config) { c.BaseURL = testRegistryURL + "/" }

// servingEnvelope answers every caller with the envelope e points at once
// it is set, and nil before.
func servingEnvelope(e **managedsettings.Envelope) func(*api.Server) {
	return func(s *api.Server) {
		s.SetManagedSettings("test", func(context.Context, uuid.UUID) (*managedsettings.Envelope, error) {
			return *e, nil
		})
	}
}

func getManagedSettings(t *testing.T, env *testEnv, who caller) (*http.Response, managedsettings.Envelope) {
	t.Helper()
	res := env.do(who, http.MethodGet, managedSettingsPath, nil)
	var out managedsettings.Envelope
	if res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	_ = res.Body.Close()
	return res, out
}

// getFrom asks another server than the env's own, on the env's database,
// as who.
func getFrom(t *testing.T, env *testEnv, s *api.Server, who caller) int {
	t.Helper()
	srv := httptest.NewServer(api.NewHandler(s))
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+managedSettingsPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	env.authenticate(req, who)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

func TestManagedSettingsWithoutExtensionIsNoContent(t *testing.T) {
	env := newTestEnv(t)
	res, _ := getManagedSettings(t, env, env.login(env.register("ms-none")))
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", res.StatusCode)
	}
}

func TestManagedSettingsNeedsASignedInCaller(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetManagedSettings("test", func(context.Context, uuid.UUID) (*managedsettings.Envelope, error) {
			t.Error("the source was asked for an anonymous caller")
			return nil, nil
		})
	})
	res, _ := getManagedSettings(t, env, anonymous)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
}

func TestManagedSettingsNilAnswerIsNoContent(t *testing.T) {
	var none *managedsettings.Envelope
	env := newTestEnvWith(t, servingEnvelope(&none))
	res, _ := getManagedSettings(t, env, env.login(env.register("ms-nil")))
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", res.StatusCode)
	}
}

func TestManagedSettingsSourceErrorIsInternal(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetManagedSettings("test", func(context.Context, uuid.UUID) (*managedsettings.Envelope, error) {
			return nil, errors.New("down")
		})
	})
	res, _ := getManagedSettings(t, env, env.login(env.register("ms-err")))
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", res.StatusCode)
	}
}

// TestManagedSettingsSignedAndServed is the route's whole promise: the key
// holder's signer binds the settings to this registry and the
// organization, and the route serves the stored envelope as it is, which
// opens with a key the registry advertises.
func TestManagedSettingsSignedAndServed(t *testing.T) {
	var stored *managedsettings.Envelope
	var signer api.ManagedSettingsSigner
	env := newTestEnvCfg(t, withRegistryURL, servingEnvelope(&stored), func(s *api.Server) { signer = s.ManagedSettingsSigner() })
	if signer == nil {
		t.Fatal("a server with a signing key and a base URL has no managed settings signer")
	}
	signed, err := signer.Sign("acme", 7, forbidUnsafe())
	if err != nil {
		t.Fatal(err)
	}
	stored = &signed

	res, got := getManagedSettings(t, env, env.login(env.register("ms-signed")))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", res.StatusCode)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", res.Header.Get("Cache-Control"))
	}
	if got.Payload != signed.Payload {
		t.Fatal("the route did not serve the stored envelope as it was")
	}
	var doc managedsettings.Document
	opened := false
	for _, k := range env.allSigningKeys(t) {
		if d, err := managedsettings.Open(got, k.PublicKey); err == nil {
			doc, opened = d, true
			break
		}
	}
	if !opened {
		t.Fatal("the envelope verified against no advertised key")
	}
	if doc.Registry != testRegistryURL || doc.Org != "acme" || doc.Version != 7 || doc.IssuedAt.IsZero() {
		t.Errorf("document %+v", doc)
	}
	if s := doc.Settings[managedsettings.UnsafeMode]; s.String() != managedsettings.UnsafeModeForbidden || !s.Locked {
		t.Errorf("unsafe mode %+v", s)
	}
	if signer.KeyID() == "" || got.Signatures[0].KeyID != signer.KeyID() {
		t.Errorf("signature key id %q, signer %q", got.Signatures[0].KeyID, signer.KeyID())
	}
}

// TestManagedSettingsBoundToTheCaller: a document signed for some members
// of an organization is served to an account it names and never to another,
// so the registry never hands a member a document their client would
// refuse.
func TestManagedSettingsBoundToTheCaller(t *testing.T) {
	var stored *managedsettings.Envelope
	var signer api.ManagedSettingsSigner
	env := newTestEnvCfg(t, withRegistryURL, servingEnvelope(&stored), func(s *api.Server) { signer = s.ManagedSettingsSigner() })
	member, other := env.register("ms-bound"), env.register("ms-other")
	signed, err := signer.SignFor("acme", 7, forbidUnsafe(), []string{env.userID(member)})
	if err != nil {
		t.Fatal(err)
	}
	stored = &signed

	res, got := getManagedSettings(t, env, env.login(member))
	if res.StatusCode != http.StatusOK || got.Payload != signed.Payload {
		t.Fatalf("the member it names: status %d", res.StatusCode)
	}
	var doc managedsettings.Document
	for _, k := range env.allSigningKeys(t) {
		if d, err := managedsettings.Open(got, k.PublicKey); err == nil {
			doc = d
			break
		}
	}
	if doc.Schema != managedsettings.SchemaMembers || doc.For(env.userID(member)) != nil || doc.For(env.userID(other)) == nil {
		t.Fatalf("document %+v is not bound to the member alone", doc)
	}
	if res, _ := getManagedSettings(t, env, env.login(other)); res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("another account: status %d, want 503", res.StatusCode)
	}
}

// TestManagedSettingsKeylessRoleServesWhatTheKeyHolderSigned is the split
// deployment: the worker holds the key and signs, the api holds none and
// serves the stored envelope, checking it against the key the record
// advertises.
func TestManagedSettingsKeylessRoleServesWhatTheKeyHolderSigned(t *testing.T) {
	var signer api.ManagedSettingsSigner
	env := newTestEnvCfg(t, withRegistryURL, func(s *api.Server) { signer = s.ManagedSettingsSigner() })
	signed, err := signer.Sign("acme", 2, forbidUnsafe())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	withRegistryURL(&cfg)
	keyless := api.New(cfg, env.st, nil, api.WithoutSigningKey())
	if keyless.ManagedSettingsSigner() != nil {
		t.Fatal("a server without a signing key has a managed settings signer")
	}
	stored := &signed
	servingEnvelope(&stored)(keyless)
	if got := getFrom(t, env, keyless, env.login(env.register("ms-keyless"))); got != http.StatusOK {
		t.Fatalf("status %d, want 200", got)
	}
}

// TestManagedSettingsRefusesWhatItCannotVerify: the route never serves an
// envelope a client would refuse: one signed by a key the registry does
// not advertise, or one whose payload was changed after signing.
func TestManagedSettingsRefusesWhatItCannotVerify(t *testing.T) {
	var stored *managedsettings.Envelope
	var signer api.ManagedSettingsSigner
	env := newTestEnvCfg(t, withRegistryURL, servingEnvelope(&stored), func(s *api.Server) { signer = s.ManagedSettingsSigner() })
	who := env.login(env.register("ms-unverified"))

	foreign := foreignEnvelope(t, testRegistryURL)
	stored = &foreign
	if res, _ := getManagedSettings(t, env, who); res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("foreign key: status %d, want 503", res.StatusCode)
	}

	signed, err := signer.Sign("acme", 1, forbidUnsafe())
	if err != nil {
		t.Fatal(err)
	}
	tampered := signed
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(`{"schema":"managed-settings/1","registry":"https://registry.example","org":"acme","version":1,"issuedAt":"2026-11-08T12:00:00Z","settings":{}}`))
	stored = &tampered
	if res, _ := getManagedSettings(t, env, who); res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("tampered payload: status %d, want 503", res.StatusCode)
	}
}

// TestManagedSettingsRefusesAnotherRegistrysDocument: the same key and
// database, a registry at another address: what it signed is not served
// here.
func TestManagedSettingsRefusesAnotherRegistrysDocument(t *testing.T) {
	var signer api.ManagedSettingsSigner
	env := newTestEnvCfg(t, func(c *config.Config) { c.BaseURL = "https://elsewhere.example" }, func(s *api.Server) { signer = s.ManagedSettingsSigner() })
	signed, err := signer.Sign("acme", 1, forbidUnsafe())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	withRegistryURL(&cfg)
	here := api.New(cfg, env.st, nil, api.WithoutSigningKey())
	stored := &signed
	servingEnvelope(&stored)(here)
	if got := getFrom(t, env, here, env.login(env.register("ms-elsewhere"))); got != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", got)
	}
}

func foreignEnvelope(t *testing.T, registry string) managedsettings.Envelope {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := managedsettings.Seal(managedsettings.Document{
		Schema: managedsettings.Schema, Registry: registry, Org: "acme", Version: 1,
		IssuedAt: time.Now().UTC(), Settings: forbidUnsafe(),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(attest.PAE(managedsettings.PayloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return managedsettings.Wrap(payload, attest.DSSESignature{KeyID: "foreign", Sig: base64.StdEncoding.EncodeToString(sig)})
}

func TestManagedSettingsSignerRefusesContentOffTheCatalogue(t *testing.T) {
	var signer api.ManagedSettingsSigner
	newTestEnvCfg(t, withRegistryURL, func(s *api.Server) { signer = s.ManagedSettingsSigner() })
	if _, err := signer.Sign("acme", 1, map[string]managedsettings.Setting{
		managedsettings.UnsafeMode: {Value: json.RawMessage(`"on"`), Locked: true},
	}); err == nil {
		t.Fatal("the signer signed a value off the catalogue")
	}
	if _, err := signer.Sign("acme", 1, map[string]managedsettings.Setting{
		"run.somethingElse": {Value: json.RawMessage(`"x"`), Locked: true},
	}); err == nil {
		t.Fatal("the signer signed a row off the catalogue")
	}
}

func TestManagedSettingsWithoutBaseURL(t *testing.T) {
	var stored *managedsettings.Envelope
	var signer api.ManagedSettingsSigner
	env := newTestEnvWith(t, servingEnvelope(&stored), func(s *api.Server) { signer = s.ManagedSettingsSigner() })
	if signer != nil {
		t.Fatal("a server with no base URL has a managed settings signer")
	}
	foreign := foreignEnvelope(t, testRegistryURL)
	stored = &foreign
	res, _ := getManagedSettings(t, env, env.login(env.register("ms-unbound")))
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", res.StatusCode)
	}
}

func TestSetManagedSettingsTwicePanics(t *testing.T) {
	srvObj := api.New(testConfig(), nil, nil, api.WithoutSigningKey())
	src := func(context.Context, uuid.UUID) (*managedsettings.Envelope, error) { return nil, nil }
	srvObj.SetManagedSettings("first", src)
	defer func() {
		if recover() == nil {
			t.Fatal("a second managed settings extension did not panic")
		}
	}()
	srvObj.SetManagedSettings("second", src)
}
