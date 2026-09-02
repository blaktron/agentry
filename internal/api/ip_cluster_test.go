package api_test

// A submission records the keyed submitting-address hash (agentry#27) —
// month-prefixed, never the address — on the shared insert path the upload
// and git-tag routes both use.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSubmissionRecordsIPClusterHash(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("ipc")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "clustered", "kind": "skill", "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	if status, body := env.uploadVersionCLI(user, "clustered", pat, map[string]string{
		"agent.yaml": skillYAML(user, "clustered", "1.0.0"),
		"README.md":  "# clustered\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}); status != http.StatusAccepted {
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
	if strings.Contains(*hash, "127.0.0.1") || strings.Contains(*hash, "::1") {
		t.Fatal("the address was stored, not a hash")
	}
}
