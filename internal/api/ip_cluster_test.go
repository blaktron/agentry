package api_test

// A submission records the keyed submitting-address hash —
// month-prefixed, never the address — on the shared insert path the upload
// and git-tag routes both use.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/config"
)

// clusterHash is the hash a deployment whose cluster key derives from
// sealingKey records for ip in the month of now: an HMAC of the address under
// a key derived from the secret and the month, behind the month's prefix.
func clusterHash(sealingKey, ip string, now time.Time) string {
	month := now.UTC().Format("2006-01")
	km := hmac.New(sha256.New, []byte("ip-cluster:"+sealingKey))
	km.Write([]byte("agentry-ip-cluster:" + month))
	h := hmac.New(sha256.New, km.Sum(nil))
	h.Write([]byte(ip))
	return month + ":" + hex.EncodeToString(h.Sum(nil))[:32]
}

// submittedHash publishes a fresh agent through the upload route with the
// given request headers and returns the submitter hash its version recorded.
func submittedHash(t *testing.T, env *testEnv, user string, sess caller, pat, name string, headers map[string]string) *string {
	t.Helper()
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": name, "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	if status, body := env.uploadVersionCLIWithHeaders(user, name, pat, map[string]string{
		"agent.yaml": skillYAML(user, name, "1.0.0"),
		"README.md":  "# " + name + "\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}, headers); status != http.StatusAccepted {
		t.Fatalf("submit %s: %d %s", name, status, body)
	}
	var hash *string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT v.submitter_ip_hash FROM agent_versions v JOIN agents a ON a.id = v.agent_id
		 JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = $2`, user, name).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestSubmissionRecordsIPClusterHash(t *testing.T) {
	// One trusted hop so a forwarded address counts; loopback itself
	// records nothing (the operator's own host).
	env := newTestEnvCfg(t, func(c *config.Config) { c.HTTP.TrustedProxies = 1; c.Auth.SealingKey = imageProxySealingKey })
	user := env.register("ipc")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "clustered", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	if status, body := env.uploadVersionCLIWithHeaders(user, "clustered", pat, map[string]string{
		"agent.yaml": skillYAML(user, "clustered", "1.0.0"),
		"README.md":  "# clustered\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}, map[string]string{"X-Forwarded-For": "203.0.113.9"}); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	var hash *string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT v.submitter_ip_hash FROM agent_versions v JOIN agents a ON a.id = v.agent_id
		 JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'clustered'`, user).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == nil || !strings.HasPrefix(*hash, time.Now().UTC().Format("2006-01")+":") {
		t.Fatalf("submitter_ip_hash = %v, want a month-prefixed keyed hash", hash)
	}
	if strings.Contains(*hash, "203.0.113.9") {
		t.Fatal("the address was stored, not a hash")
	}
	// From the server's own host nothing is recorded.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "local", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	if status, body := env.uploadVersionCLI(user, "local", pat, map[string]string{
		"agent.yaml": skillYAML(user, "local", "1.0.0"),
		"README.md":  "# local\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}); status != http.StatusAccepted {
		t.Fatalf("submit local: %d %s", status, body)
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT v.submitter_ip_hash FROM agent_versions v JOIN agents a ON a.id = v.agent_id
		 JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'local'`, user).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash != nil {
		t.Fatalf("loopback submission recorded a hash: %v", *hash)
	}

	// The value is the keyed, month-rotated hash of the address and nothing
	// else: it is the same for the same address and differs for another.
	before := time.Now()
	same := submittedHash(t, env, user, sess, pat, "samehost", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	other := submittedHash(t, env, user, sess, pat, "otherhost", map[string]string{"X-Forwarded-For": "203.0.113.10"})
	after := time.Now()
	valid := func(got *string, ip string) bool {
		return got != nil && (*got == clusterHash(imageProxySealingKey, ip, before) || *got == clusterHash(imageProxySealingKey, ip, after))
	}
	if !valid(same, "203.0.113.9") {
		t.Fatalf("hash of 203.0.113.9 = %v, want %s", same, clusterHash(imageProxySealingKey, "203.0.113.9", before))
	}
	if !valid(other, "203.0.113.10") {
		t.Fatalf("hash of 203.0.113.10 = %v, want %s", other, clusterHash(imageProxySealingKey, "203.0.113.10", before))
	}
	if first := submittedHash(t, env, user, sess, pat, "firsthost", map[string]string{"X-Forwarded-For": "203.0.113.9"}); first == nil || same == nil || *first != *same {
		t.Fatalf("one address hashed two ways: %v and %v", first, same)
	}

	// Addresses that are the server's own host record nothing, however they
	// arrive.
	for i, ip := range []string{"::1", "127.0.0.2", "0.0.0.0", "::"} {
		if got := submittedHash(t, env, user, sess, pat, "own"+string(rune('a'+i)), map[string]string{"X-Forwarded-For": ip}); got != nil {
			t.Errorf("a submission forwarded from %s recorded %q", ip, *got)
		}
	}

	// A server with no trusted hop believes no forwarded address: the peer
	// is the server's own host.
	direct := newTestEnvCfg(t, func(c *config.Config) { c.Auth.SealingKey = imageProxySealingKey })
	directUser := direct.register("ipcdirect")
	direct.verifyEmail(directUser)
	directSess := direct.login(directUser)
	_, directPAT := direct.mintPAT(directSess, "pub", "agent:publish", "agent:read")
	if got := submittedHash(t, direct, directUser, directSess, directPAT, "forged", map[string]string{"X-Forwarded-For": "203.0.113.9"}); got != nil {
		t.Errorf("an untrusted X-Forwarded-For recorded %q", *got)
	}

	// A dev-mode server with no sealing key still records, under its fixed
	// development key.
	dev := newTestEnvCfg(t, func(c *config.Config) { c.HTTP.TrustedProxies = 1 })
	devUser := dev.register("ipcdev")
	dev.verifyEmail(devUser)
	devSess := dev.login(devUser)
	_, devPAT := dev.mintPAT(devSess, "pub", "agent:publish", "agent:read")
	before = time.Now()
	got := submittedHash(t, dev, devUser, devSess, devPAT, "devkey", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	after = time.Now()
	if got == nil || (*got != clusterHash("dev-insecure", "203.0.113.9", before) && *got != clusterHash("dev-insecure", "203.0.113.9", after)) {
		t.Fatalf("dev-mode hash = %v, want %s", got, clusterHash("dev-insecure", "203.0.113.9", before))
	}
}
