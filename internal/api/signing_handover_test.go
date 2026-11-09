package api_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/pkg/keyhandover"
)

func (env *testEnv) signingKeyHandovers(t *testing.T) keyhandover.Chain {
	t.Helper()
	res := env.do(anonymous, http.MethodGet, "/.well-known/agentry/signing-key-handovers.json", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("signing-key-handovers.json: status %d", res.StatusCode)
	}
	if got := res.Header.Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("signing-key-handovers.json: Cache-Control %q, want public, max-age=300", got)
	}
	var out keyhandover.Chain
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// A start on a new file key that keeps the outgoing key as the previous
// one serves the outgoing key's handover to it, which a client that pinned
// the outgoing key walks to the new one. Before any rotation the chain is
// empty, not missing.
func TestARotationWithThePreviousKeyServesItsHandover(t *testing.T) {
	dir := t.TempDir()
	keyA, pubA := writeSigningKey(t, filepath.Join(dir, "a.pem"))
	keyB, pubB := writeSigningKey(t, filepath.Join(dir, "b.pem"))

	envA := newTestEnvCfg(t, func(c *config.Config) {
		c.BaseURL = "https://registry.example"
		c.Signing.Kind = "file"
		c.Signing.KeyFile = keyA
	})
	if got := envA.signingKeyHandovers(t); len(got.Handovers) != 0 {
		t.Fatalf("handovers before any rotation: %+v", got)
	}
	idA, _ := keyhandover.KeyID(pubA)
	idB, _ := keyhandover.KeyID(pubB)

	envB := newTestEnvCfg(t, func(c *config.Config) {
		c.BaseURL = "https://registry.example"
		c.Signing.Kind = "file"
		c.Signing.KeyFile = keyB
		c.Signing.PreviousKeyFile = keyA
	})
	chain := envB.signingKeyHandovers(t)
	if len(chain.Handovers) != 1 {
		t.Fatalf("handovers after the rotation: %d, want 1", len(chain.Handovers))
	}
	got, err := keyhandover.Follow(chain.Registry, []keyhandover.Key{{KeyID: idA, PublicKeyPEM: pubA}}, chain, nil)
	if err != nil || len(got) != 1 || got[0].From != idA || got[0].To.KeyID != idB || got[0].To.PublicKeyPEM != pubB {
		t.Fatalf("a client that pinned A walks the chain to %+v %v, want B", got, err)
	}
}
