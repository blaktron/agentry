package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
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

// dsaKeyLine is a well-formed DSA public key, which the registry refuses by
// its type.
const dsaKeyLine = "ssh-dss AAAAB3NzaC1kc3MAAACBAKdyBPC8q9kolG8Pc/V+C/uXOQFVh3ju9QvUVeHgQlqOWiGl+CdEfUvdvKpNEYN9t2q6NzmnMQ//vuoxlSTsWtafcMf0v/XPkBSIL9RFkxa03aYZq38+jZBhxsuHZjlrAZnmzyqvwIYBbslg24KnUIMqR9X+XSNHeQb1N6F8M9f3AAAAFQCCLZQLur60BiV9rTmqlLgYaGTmzQAAAIB7/ttrLxGezVdEkUS1xu0aqYlzxNefVoS/14kG4wIC66kZIUq09fDhWmq4uLwGlX4V/lekJ3WhVneXqlNu4tlQ8QijhMyzO4vNxJYK3OkL02j5DnEmafcm0XiyuDD2liyuxcreJj8qlHI9nwFWcu76Phu3OpX25T3LMlc5ps17MQAAAIBVcvOPcouVy4SnbHKqIoGxq526E5mtQuZ76zoXWn8tSxoQ7FcVa2RwtXlKkS7gEsbgt/n3sKb0GvR0XXhAYdB8i0N4HWIHwVQRrpLHOcbBf2wzbeQ5hzxwv8B+x9o9LhbeW3kzWEOuwQJaQwFXEjUno0sRjrVNbnNCXoJj17DYEg== me@laptop"

// fieldRefusalOf reads a refused request: its status and the field errors it
// names.
func fieldRefusalOf(t *testing.T, res *http.Response) (int, []api.FieldError) {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	var body struct {
		Errors []api.FieldError `json:"errors"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("refusal body: %v (%s)", err, raw)
	}
	return res.StatusCode, body.Errors
}

// SSH keys: a session registers, lists and removes keys; a
// malformed key and a duplicate are refused with the field named; a PAT
// may list but neither add nor remove; another user's key
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
	if list[0].LastUsedAt != nil {
		t.Fatalf("a key never used lists a last use: %v", list[0].LastUsedAt)
	}
	// The key is kept in its canonical form, without the comment, and its
	// fingerprint is the one ssh computes.
	var stored string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT public_key FROM user_ssh_keys WHERE id = $1`, created.Id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if fields := strings.Fields(line); stored != fields[0]+" "+fields[1] {
		t.Fatalf("stored key %q, want %q", stored, fields[0]+" "+fields[1])
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if created.Fingerprint != ssh.FingerprintSHA256(parsed) {
		t.Fatalf("fingerprint %q, want %q", created.Fingerprint, ssh.FingerprintSHA256(parsed))
	}
	// A key that has been used says when.
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE user_ssh_keys SET last_used_at = now() - interval '1 hour' WHERE id = $1`, created.Id); err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/ssh-keys", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].LastUsedAt == nil {
		t.Fatalf("a used key lists no last use: %+v", list)
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
	// Each refusal is a 422 that names the field and says what to fix.
	for _, c := range []struct {
		name string
		body map[string]any
		want api.FieldError
	}{
		{"a duplicate", map[string]any{"title": "again", "publicKey": line}, api.FieldError{Field: "publicKey", Message: "This key is already registered."}},
		{"a malformed key", map[string]any{"title": "bad", "publicKey": "not a key"}, api.FieldError{Field: "publicKey", Message: "Must be an OpenSSH public key line."}},
		{"a DSA key", map[string]any{"title": "dsa", "publicKey": dsaKeyLine}, api.FieldError{Field: "publicKey", Message: "This server does not accept DSA keys."}},
		{"a blank title", map[string]any{"title": "   ", "publicKey": testPublicKeyLine(t)}, api.FieldError{Field: "title", Message: "Must be 1-120 characters."}},
		{"a 121-character title", map[string]any{"title": strings.Repeat("t", 121), "publicKey": testPublicKeyLine(t)}, api.FieldError{Field: "title", Message: "Must be 1-120 characters."}},
	} {
		code, fields := fieldRefusalOf(t, env.do(sess, http.MethodPost, "/api/v1/user/ssh-keys", c.body))
		if code != http.StatusUnprocessableEntity || len(fields) != 1 || fields[0] != c.want {
			t.Errorf("%s: %d %+v, want 422 %+v", c.name, code, fields, c.want)
		}
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
	if r := env.do(patCaller, http.MethodDelete, "/api/v1/user/ssh-keys/"+created.Id.String(), nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("pat remove: got %d want 403", r.StatusCode)
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/ssh-keys", nil, &list, http.StatusOK)
	if len(list) != 1 {
		t.Fatalf("a key a token tried to remove: %+v, want it listed", list)
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
	// Both acts are audited, the add with the key's fingerprint and type, and
	// the refused removals leave no row.
	var added, removed int
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT
		count(*) FILTER (WHERE a.action = 'ssh_key.add' AND a.target_id = $2 AND a.detail->>'fingerprint' = $3 AND a.detail->>'keyType' = 'ssh-ed25519'),
		count(*) FILTER (WHERE a.action = 'ssh_key.remove' AND a.target_id = $2)
		FROM audit_events a JOIN handles h ON h.id = a.actor_id WHERE h.handle = $1`, u, created.Id, created.Fingerprint).Scan(&added, &removed); err != nil {
		t.Fatal(err)
	}
	if added != 1 || removed != 1 {
		t.Fatalf("audit rows for the key: %d add, %d remove, want one each", added, removed)
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/ssh-keys", nil, &list, http.StatusOK)
	if len(list) != 0 {
		t.Fatalf("after remove: %+v", list)
	}
	// The same key can be registered again after removal.
	env.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "laptop again", "publicKey": line}, &created, http.StatusCreated)

	// A title is trimmed and may be 120 characters long.
	var titled api.SshKey
	env.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "  padded  ", "publicKey": testPublicKeyLine(t)}, &titled, http.StatusCreated)
	if titled.Title != "padded" {
		t.Fatalf("title %q, want it trimmed", titled.Title)
	}
	long := strings.Repeat("t", 120)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": long, "publicKey": testPublicKeyLine(t)}, &titled, http.StatusCreated)
	if titled.Title != long {
		t.Fatalf("a 120-character title came back as %q", titled.Title)
	}
	// The bound counts characters, not bytes: 120 two-byte letters are
	// taken, 121 are not.
	wide := strings.Repeat("\u00e9", 120)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": wide, "publicKey": testPublicKeyLine(t)}, &titled, http.StatusCreated)
	if titled.Title != wide {
		t.Fatalf("a 120-character title of two-byte letters came back as %q", titled.Title)
	}
	if code, fields := fieldRefusalOf(t, env.do(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": wide + "\u00e9", "publicKey": testPublicKeyLine(t)})); code != http.StatusUnprocessableEntity || len(fields) != 1 || fields[0] != (api.FieldError{Field: "title", Message: "Must be 1-120 characters."}) {
		t.Fatalf("a 121-character title of two-byte letters: %d %v, want 422 on title", code, fields)
	}
}

// noSSHKeys is a person's subscription without SSH keys (tierResolver lays
// its tier over organization subjects only).
type noSSHKeys struct{ entitlements.Resolver }

func (r noSSHKeys) Features(ctx context.Context, s entitlements.Subject) (entitlements.Features, error) {
	f, err := r.Resolver.Features(ctx, s)
	if s.Kind != entitlements.NamespaceOrg {
		f.SSHKeys = false
	}
	return f, err
}

// Adding a key is a feature the subscription may not include:
// off, the add is 403 feature-not-included and writes
// nothing; a key already held stays listed, removable and in force; an
// entitlement that cannot be resolved refuses rather than admits.
func TestSSHKeyAddIsGatedOnTheSubscription(t *testing.T) {
	env := newTestEnv(t)
	u := env.register("sshtier")
	env.verifyEmail(u)
	sess := env.login(u)

	var held api.SshKey
	env.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "held", "publicKey": testPublicKeyLine(t)}, &held, http.StatusCreated)

	env.setEntitlements(noSSHKeys{entitlements.NewConfigResolver(config.Default().Limits)})
	code, slug, _ := problemOf(t, env.do(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "new", "publicKey": testPublicKeyLine(t)}))
	if code != http.StatusForbidden || slug != "feature-not-included" {
		t.Fatalf("add without the feature: %d %s, want 403 feature-not-included", code, slug)
	}
	var list []api.SshKey
	env.doJSON(sess, http.MethodGet, "/api/v1/user/ssh-keys", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].Id != held.Id {
		t.Fatalf("list without the feature = %+v, want only the held key", list)
	}
	var adds int
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events a JOIN handles h ON h.id = a.actor_id WHERE a.action = 'ssh_key.add' AND h.handle = $1`, u).Scan(&adds); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if adds != 1 {
		t.Fatalf("ssh_key.add events = %d, want 1 (the refused add writes none)", adds)
	}

	env.setEntitlements(brokenTierResolver())
	outage := env.do(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "outage", "publicKey": testPublicKeyLine(t)})
	_ = outage.Body.Close()
	if outage.StatusCode == http.StatusCreated {
		t.Fatalf("add during an entitlement outage: got 201, want a refusal")
	}
	if outage.StatusCode != http.StatusInternalServerError {
		t.Fatalf("add during an entitlement outage: got %d, want 500 (the plan could not be read)", outage.StatusCode)
	}

	env.setEntitlements(noSSHKeys{entitlements.NewConfigResolver(config.Default().Limits)})
	if r := env.do(sess, http.MethodDelete, "/api/v1/user/ssh-keys/"+held.Id.String(), nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("remove without the feature: got %d want 204", r.StatusCode)
	}
}
