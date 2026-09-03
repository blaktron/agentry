package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/blaktron/agentry/internal/api"
)

func testPublicKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " me@laptop"
}

// SSH keys (agentry#70): a session registers, lists and removes keys; a
// malformed key and a duplicate are refused with the field named; a PAT
// may list but neither add nor remove (D-22 for keys); another user's key
// is not removable.
func TestSSHKeysLifecycle(t *testing.T) {
	env := newTestEnv(t)
	u := env.register("sshk")
	env.verifyEmail(u)
	sess := env.login(u)

	line := testPublicKeyLine(t)
	var created api.SshKey
	env.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "laptop", "publicKey": line}, &created, http.StatusCreated)
	if created.KeyType != "ssh-ed25519" || !strings.HasPrefix(created.Fingerprint, "SHA256:") || created.Title != "laptop" {
		t.Fatalf("created = %+v", created)
	}
	var list []api.SshKey
	env.doJSON(sess, http.MethodGet, "/api/v1/user/ssh-keys", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].Id != created.Id {
		t.Fatalf("list = %+v", list)
	}

	// Duplicate and malformed.
	res := env.do(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "again", "publicKey": line})
	if res.StatusCode != http.StatusUnprocessableEntity && res.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate: got %d", res.StatusCode)
	}
	res = env.do(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "bad", "publicKey": "not a key"})
	if res.StatusCode != http.StatusUnprocessableEntity && res.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed: got %d", res.StatusCode)
	}

	// A PAT lists but cannot add or remove.
	_, pat := env.mintPAT(sess, "sshk-pat", "user:profile")
	patCaller := caller{name: "pat", pat: pat}
	if r := env.do(patCaller, http.MethodGet, "/api/v1/user/ssh-keys", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("pat list: %d", r.StatusCode)
	}
	if r := env.do(patCaller, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "x", "publicKey": testPublicKeyLine(t)}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("pat add: got %d want 403", r.StatusCode)
	}

	// Another user cannot remove it; the owner can; then it is gone.
	other := env.register("sshk2")
	env.verifyEmail(other)
	if r := env.do(env.login(other), http.MethodDelete, "/api/v1/user/ssh-keys/"+created.Id.String(), nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("other's remove: got %d want 404", r.StatusCode)
	}
	if r := env.do(sess, http.MethodDelete, "/api/v1/user/ssh-keys/"+created.Id.String(), nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("remove: got %d want 204", r.StatusCode)
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/ssh-keys", nil, &list, http.StatusOK)
	if len(list) != 0 {
		t.Fatalf("after remove: %+v", list)
	}
	// The same key can be registered again after removal.
	env.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "laptop again", "publicKey": line}, &created, http.StatusCreated)
}
