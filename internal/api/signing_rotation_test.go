package api_test

// A rotation must not orphan the attestations the outgoing key signed: a
// well-known set that named only the current key would make a client
// pinning afterwards refuse everything published before it. The registry
// keeps every key it signed with, advertises the retired ones, and
// countersigns existing attestations with the new key.

import (
	"context"
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

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/pkg/attest"
)

// writeSigningKey writes a fresh P-256 private key as a signing key file and
// returns its path with the matching verification PEM.
func writeSigningKey(t *testing.T, path string) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return path, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func (env *testEnv) attestation(t *testing.T, c caller, ns, name string) attest.DSSEEnvelope {
	t.Helper()
	res := env.do(c, http.MethodGet, "/api/v1/agents/"+ns+"/"+name+"/versions/1.0.0/attestation", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("attestation: status %d", res.StatusCode)
	}
	if cc := res.Header.Get("Cache-Control"); cc == "" || cc == "public, max-age=31536000, immutable" {
		// A rotation changes the envelope; a year-long immutable cache would
		// keep serving the pre-rotation bytes a fresh client cannot verify.
		t.Errorf("attestation Cache-Control = %q, must not be immutable", cc)
	}
	var envlp attest.DSSEEnvelope
	if err := json.NewDecoder(res.Body).Decode(&envlp); err != nil {
		t.Fatal(err)
	}
	return envlp
}

func TestRotationAdvertisesTheRetiredKeyAndCountersigns(t *testing.T) {
	// Key A is a file key: the server that publishes signs with it, and its
	// public part is what the registry must keep once A is gone.
	keyPath, pubA := writeSigningKey(t, filepath.Join(t.TempDir(), "a.pem"))
	envA := newTestEnvCfg(t, func(c *config.Config) {
		c.Signing.Kind = "file"
		c.Signing.KeyFile = keyPath
	})
	user := envA.register("rot-usr")
	envA.verifyEmail(user)
	sess := envA.login(user)
	envA.publishUnder(t, sess, user, "rotated")
	activeA := envA.signingKeys(t)[0]
	if activeA.PublicKey != pubA || activeA.Status != "active" {
		t.Fatalf("server A's active key = %+v, want key A", activeA)
	}
	published := envA.attestation(t, sess, user, "rotated")
	if len(published.Signatures) != 1 || published.Signatures[0].KeyID != activeA.KeyID {
		t.Fatalf("published envelope signatures = %+v, want one by %s", published.Signatures, activeA.KeyID)
	}

	// Rotation: a server over the same database on a fresh key. Key A's
	// private part is nowhere (the dev-mode ephemeral case, or a lost file).
	var srvB *api.Server
	envB := newTestEnvWith(t, func(s *api.Server) { srvB = s })
	keysB := envB.allSigningKeys(t)
	if keysB[0].Status != "active" || keysB[0].KeyID == activeA.KeyID {
		t.Fatalf("server B's first key = %+v, want its own active key", keysB[0])
	}
	var retiredA *publishedKey
	for i := range keysB {
		if keysB[i].KeyID == activeA.KeyID {
			retiredA = &keysB[i]
		}
	}
	if retiredA == nil {
		t.Fatalf("key A is not advertised after the rotation: %+v", keysB)
	}
	if retiredA.Status != "retired" || retiredA.RetiredAt == "" || retiredA.PublicKey != pubA {
		t.Errorf("key A advertised as %+v, want status retired with a date and its PEM", *retiredA)
	}
	// A client that pinned A keeps verifying the release as published.
	if _, err := attest.VerifyEnvelope(published, retiredA.PublicKey); err != nil {
		t.Errorf("the published envelope does not verify under the advertised retired key: %v", err)
	}

	// The sweep the new key's registration enqueued, run here directly
	// (the api tests have no worker draining the queue).
	sum, err := srvB.Pipeline().ReattestSweepWithSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The shared test database carries other packages' rows, some of them
	// deliberately unsignable, so only this release's outcome is asserted.
	if sum.Signed < 1 || sum.KeyID != keysB[0].KeyID {
		t.Fatalf("sweep = %+v, want at least the rotated release signed by %s", sum, keysB[0].KeyID)
	}

	// The fresh client: pins only B, fetches the attestation, verifies.
	after := envB.attestation(t, sess, user, "rotated")
	if after.Payload != published.Payload {
		t.Fatal("the sweep rewrote the statement")
	}
	if _, err := attest.VerifyEnvelope(after, keysB[0].PublicKey); err != nil {
		t.Errorf("a client pinning only the new key cannot verify a release published before the rotation: %v", err)
	}
	if _, err := attest.VerifyEnvelope(after, pubA); err != nil {
		t.Errorf("the original signature no longer verifies: %v", err)
	}
	// A release published after the rotation is signed by B alone; a
	// restart on B enqueues nothing more (covered in internal/scan).
	envB.publishUnder(t, sess, user, "after-rotation")
	fresh := envB.attestation(t, sess, user, "after-rotation")
	if len(fresh.Signatures) != 1 || fresh.Signatures[0].KeyID != keysB[0].KeyID {
		t.Errorf("a release published after the rotation has signatures %+v, want one by %s", fresh.Signatures, keysB[0].KeyID)
	}
}
