package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
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

func withManagedSettings(src api.ManagedSettingsSource) func(*api.Server) {
	return func(s *api.Server) { s.SetManagedSettings("test", src) }
}

func TestManagedSettingsWithoutExtensionIsNoContent(t *testing.T) {
	env := newTestEnv(t)
	who := env.login(env.register("ms-none"))
	res := env.do(who, http.MethodGet, managedSettingsPath, nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", res.StatusCode)
	}
}

func TestManagedSettingsNeedsASignedInCaller(t *testing.T) {
	env := newTestEnvWith(t, withManagedSettings(func(context.Context, uuid.UUID) (*api.ManagedSettingsContent, error) {
		t.Error("the source was asked for an anonymous caller")
		return nil, nil
	}))
	res := env.do(anonymous, http.MethodGet, managedSettingsPath, nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
}

func TestManagedSettingsNilAnswerIsNoContent(t *testing.T) {
	env := newTestEnvWith(t, withManagedSettings(func(context.Context, uuid.UUID) (*api.ManagedSettingsContent, error) {
		return nil, nil
	}))
	who := env.login(env.register("ms-nil"))
	res := env.do(who, http.MethodGet, managedSettingsPath, nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", res.StatusCode)
	}
}

// TestManagedSettingsSignedAndBound is the route's whole promise: the
// extension's settings come back in an envelope that verifies against
// the key the registry advertises, bound by the core to this registry and
// to the caller, and the extension is asked about the caller alone.
func TestManagedSettingsSignedAndBound(t *testing.T) {
	var asked uuid.UUID
	env := newTestEnvCfg(t, func(c *config.Config) { c.BaseURL = testRegistryURL + "/" },
		withManagedSettings(func(_ context.Context, user uuid.UUID) (*api.ManagedSettingsContent, error) {
			asked = user
			return &api.ManagedSettingsContent{Org: "acme", Version: 7, Settings: forbidUnsafe()}, nil
		}))
	handle := env.register("ms-signed")
	who := env.login(handle)
	res := env.do(who, http.MethodGet, managedSettingsPath, nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", got)
	}
	var envelope managedsettings.Envelope
	if err := json.NewDecoder(res.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}

	var doc managedsettings.Document
	opened := false
	for _, k := range env.signingKeys(t) {
		if k.Status == "retired" {
			continue
		}
		d, err := managedsettings.Open(envelope, k.PublicKey)
		if err == nil {
			doc, opened = d, true
			break
		}
	}
	if !opened {
		t.Fatal("the envelope verified against no advertised key")
	}
	id := env.userID(handle)
	if doc.Account != id || asked.String() != id {
		t.Errorf("account %q, asked %s, want %s", doc.Account, asked, id)
	}
	if doc.Registry != testRegistryURL {
		t.Errorf("registry %q, want %q", doc.Registry, testRegistryURL)
	}
	if doc.Org != "acme" || doc.Version != 7 || doc.IssuedAt.IsZero() {
		t.Errorf("document %+v", doc)
	}
	if s := doc.Settings[managedsettings.UnsafeMode]; s.String() != managedsettings.UnsafeModeForbidden || !s.Locked {
		t.Errorf("unsafe mode %+v", s)
	}
}

func TestManagedSettingsRefusesContentOffTheCatalogue(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) { c.BaseURL = testRegistryURL }, withManagedSettings(func(context.Context, uuid.UUID) (*api.ManagedSettingsContent, error) {
		return &api.ManagedSettingsContent{Org: "acme", Version: 1, Settings: map[string]managedsettings.Setting{
			managedsettings.UnsafeMode: {Value: json.RawMessage(`"on"`), Locked: true},
		}}, nil
	}))
	who := env.login(env.register("ms-bad"))
	res := env.do(who, http.MethodGet, managedSettingsPath, nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500: the core signs nothing off the catalogue", res.StatusCode)
	}
}

func TestManagedSettingsSourceErrorIsInternal(t *testing.T) {
	env := newTestEnvWith(t, withManagedSettings(func(context.Context, uuid.UUID) (*api.ManagedSettingsContent, error) {
		return nil, errors.New("down")
	}))
	who := env.login(env.register("ms-err"))
	res := env.do(who, http.MethodGet, managedSettingsPath, nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", res.StatusCode)
	}
}

// TestManagedSettingsWithoutSigningKeyIsUnavailable: a registry that
// cannot sign serves no document at all, rather than an unsigned one.
func TestManagedSettingsWithoutSigningKeyIsUnavailable(t *testing.T) {
	env := newTestEnv(t)
	handle := env.register("ms-keyless")
	who := env.login(handle)
	cfg := testConfig()
	cfg.BaseURL = testRegistryURL
	srvObj := api.New(cfg, env.st, nil, api.WithoutSigningKey())
	srvObj.SetManagedSettings("test", func(context.Context, uuid.UUID) (*api.ManagedSettingsContent, error) {
		return &api.ManagedSettingsContent{Org: "acme", Version: 1, Settings: forbidUnsafe()}, nil
	})
	srv := httptest.NewServer(api.NewHandler(srvObj))
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
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", res.StatusCode)
	}
}

func TestSetManagedSettingsTwicePanics(t *testing.T) {
	srvObj := api.New(testConfig(), nil, nil, api.WithoutSigningKey())
	src := func(context.Context, uuid.UUID) (*api.ManagedSettingsContent, error) { return nil, nil }
	srvObj.SetManagedSettings("first", src)
	defer func() {
		if recover() == nil {
			t.Fatal("a second managed settings extension did not panic")
		}
	}()
	srvObj.SetManagedSettings("second", src)
}

func TestManagedSettingsWithoutBaseURLIsUnavailable(t *testing.T) {
	env := newTestEnvWith(t, withManagedSettings(func(context.Context, uuid.UUID) (*api.ManagedSettingsContent, error) {
		return &api.ManagedSettingsContent{Org: "acme", Version: 1, Settings: forbidUnsafe()}, nil
	}))
	who := env.login(env.register("ms-unbound"))
	res := env.do(who, http.MethodGet, managedSettingsPath, nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", res.StatusCode)
	}
}
