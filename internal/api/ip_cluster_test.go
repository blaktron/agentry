package api_test

// A submission records the keyed submitting-address hash (agentry#27) —
// month-prefixed, never the address — on the shared insert path the upload
// and git-tag routes both use.

import (
	"context"
	"github.com/blaktron/agentry/internal/config"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSubmissionRecordsIPClusterHash(t *testing.T) {
	// One trusted hop so a forwarded address counts; loopback itself
	// records nothing (the operator's own host).
	env := newTestEnvCfg(t, func(c *config.Config) { c.HTTP.TrustedProxies = 1 })
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
}
