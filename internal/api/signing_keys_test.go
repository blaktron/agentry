package api_test

// §8.8: "Verification key discovery: GET /.well-known/agentry/
// signing-keys.json (key id, alg, PEM, validity window). … key rotation =
// overlapping validity windows."
//
// The document served keyId/algorithm/PEM only, and only ever one key — so an
// overlapping-window rotation could not be expressed at all: there was no way
// to say "both of these are legitimate, here is when each applies".

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

type publishedKey struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKeyPem"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	Status    string `json:"status"`
	RetiredAt string `json:"retiredAt"`
}

// signingKeys returns the keys the configuration describes: the active one
// and the operator's additional keys. Retired keys the registry itself
// signed with earlier (agentry#350) are left out — the shared test database
// accumulates one per server the package has started that published
// something — and read through allSigningKeys by the test that is about them.
func (env *testEnv) signingKeys(t *testing.T) []publishedKey {
	t.Helper()
	var keys []publishedKey
	for _, k := range env.allSigningKeys(t) {
		if k.Status == "retired" {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

func (env *testEnv) allSigningKeys(t *testing.T) []publishedKey {
	t.Helper()
	res := env.do(anonymous, http.MethodGet, "/.well-known/agentry/signing-keys.json", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("signing-keys.json: status %d", res.StatusCode)
	}
	var out struct {
		Keys []publishedKey `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.Keys
}

// generatePublicKeyPEM makes a throwaway P-256 verification key.
func generatePublicKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// A key with no configured window publishes no window — silence is the honest
// description of a deployment that has never rotated, and an invented window
// would be a claim nobody made.
func TestSigningKeysOmitAnUnsetWindow(t *testing.T) {
	env := newTestEnv(t)
	keys := env.signingKeys(t)
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want the single active key", len(keys))
	}
	if keys[0].KeyID == "" || keys[0].PublicKey == "" {
		t.Errorf("key is incomplete: %+v", keys[0])
	}
	if keys[0].Algorithm != "ecdsa-p256-sha256" {
		t.Errorf("algorithm = %q", keys[0].Algorithm)
	}
	if keys[0].NotBefore != "" || keys[0].NotAfter != "" {
		t.Errorf("an unconfigured key published a window: %+v", keys[0])
	}
	if keys[0].Status != "active" || keys[0].RetiredAt != "" {
		t.Errorf("the signing key is not published as active: %+v", keys[0])
	}
}

func TestSigningKeysCarryTheActiveKeyWindow(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Signing.NotBefore = "2026-01-01T00:00:00Z"
		c.Signing.NotAfter = "2027-01-01T00:00:00Z"
	})
	keys := env.signingKeys(t)
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].NotBefore != "2026-01-01T00:00:00Z" || keys[0].NotAfter != "2027-01-01T00:00:00Z" {
		t.Errorf("window not published: %+v", keys[0])
	}
}

// The rotation §8.8 describes: the outgoing key stays listed with a notAfter
// while the incoming key signs, so attestations from both are verifiable.
func TestSigningKeysPublishOverlappingWindowsDuringRotation(t *testing.T) {
	outgoingPEM := generatePublicKeyPEM(t)
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Signing.NotBefore = "2026-06-01T00:00:00Z"
		c.Signing.AdditionalKeys = []config.VerificationKey{{
			KeyID:        "outgoing-key",
			PublicKeyPEM: outgoingPEM,
			NotBefore:    "2025-01-01T00:00:00Z",
			// Overlaps the incoming key's notBefore by three months.
			NotAfter: "2026-09-01T00:00:00Z",
		}}
	})

	keys := env.signingKeys(t)
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want the active key plus the outgoing one", len(keys))
	}
	// The active signer comes first; clients that take the head of the list
	// keep verifying against the key currently in use.
	if keys[0].NotBefore != "2026-06-01T00:00:00Z" {
		t.Errorf("first entry is not the active key: %+v", keys[0])
	}
	old := keys[1]
	if old.KeyID != "outgoing-key" {
		t.Fatalf("second entry = %+v, want the outgoing key", old)
	}
	if old.PublicKey != outgoingPEM {
		t.Error("the outgoing key's PEM was not published verbatim")
	}
	if old.NotAfter != "2026-09-01T00:00:00Z" {
		t.Errorf("outgoing notAfter = %q", old.NotAfter)
	}
	// The windows must actually overlap, or the rotation has a gap in which
	// nothing verifies.
	if old.NotAfter <= keys[0].NotBefore {
		t.Errorf("windows do not overlap: outgoing ends %s, incoming starts %s",
			old.NotAfter, keys[0].NotBefore)
	}
	// An additional key with no algorithm takes the default rather than
	// publishing an empty one.
	if old.Algorithm != "ecdsa-p256-sha256" {
		t.Errorf("outgoing algorithm = %q, want the default", old.Algorithm)
	}
	// The registry never signed with a configured verification key, so it
	// claims no status for it.
	if old.Status != "" {
		t.Errorf("a configured verification-only key carries status %q", old.Status)
	}
}

func TestSigningKeysReadAKeyFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.pub.pem")
	body := generatePublicKeyPEM(t)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Signing.AdditionalKeys = []config.VerificationKey{
			{KeyID: "from-file", PublicKeyFile: path, NotAfter: "2027-01-01T00:00:00Z"},
		}
	})
	keys := env.signingKeys(t)
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if keys[1].PublicKey != body {
		t.Errorf("file-backed key body = %q", keys[1].PublicKey)
	}
}

// An unreadable additional key must not take the whole document down: serving
// the keys that ARE valid keeps existing clients verifying, where a 500 would
// break all of them at once over one operator typo.
func TestSigningKeysSkipAnUnreadableAdditionalKey(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Signing.AdditionalKeys = []config.VerificationKey{
			{KeyID: "missing", PublicKeyFile: filepath.Join(t.TempDir(), "nope.pem")},
		}
	})
	keys := env.signingKeys(t)
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want only the active one", len(keys))
	}
	if keys[0].KeyID == "missing" {
		t.Error("the unreadable key was published anyway")
	}
}
