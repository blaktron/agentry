package api_test

// M8 / §12.7 account-erasure flow: PII is purged, credentials die, published
// content is yanked rather than deleted (so installed copies keep verifying),
// and the audit trail keeps an opaque actor id.

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/knowledge"
)

func TestAccountErasureFlow(t *testing.T) {
	env := newTestEnv(t)

	user := env.register("gdpr")
	env.verifyEmail(user)
	sess := env.login(user)
	_, _ = env.st.Pool().Exec(context.Background(),
		`UPDATE users SET created_at = now() - interval '30 days' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, user)

	// Publish something so the chooser has content to act on.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "doomed", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	status, body := env.uploadVersionCLI(user, "doomed", pat, map[string]string{
		"agent.yaml": skillYAML(user, "doomed", "1.0.0"),
		"README.md":  "# doomed\nA well-behaved agent.\n",
		"SKILL.md":   "Summarize politely and cite sources.\n",
		"LICENSE":    "Apache-2.0\n",
	})
	if status != http.StatusAccepted {
		t.Fatalf("publish: %d %s", status, body)
	}
	env.waitStatus(user, "doomed", "1.0.0", "published")

	// A knowledge pack (agentry#593) goes with the account.
	uid := env.selfID(sess)
	kn := seedKnowledge(t, env, knowledge.User(uuid.MustParse(uid)))

	// A PAT cannot erase the account (session-only).
	res := env.do(caller{name: "pat", pat: pat}, http.MethodPost, "/api/v1/user/delete", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("PAT erasure must 403, got %d", res.StatusCode)
	}

	// Erase.
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete?publishedContent=yank", nil, nil, http.StatusNoContent)

	// The session is dead.
	res = env.do(sess, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after erasure must 401, got %d", res.StatusCode)
	}
	// The PAT is dead.
	res = env.do(caller{name: "pat", pat: pat}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PAT after erasure must 401, got %d", res.StatusCode)
	}

	ctx := context.Background()
	assertKnowledgeGone(t, env, kn)
	// PII is gone; the row survives, pseudonymized.
	var email, displayName, state string
	var pwHash *string
	var tombstone []byte
	err := env.st.Pool().QueryRow(ctx,
		`SELECT email::text, display_name, state, password_hash, deleted_tombstone
		 FROM users WHERE deleted_tombstone IS NOT NULL AND email LIKE 'deleted+%' ORDER BY updated_at DESC LIMIT 1`,
	).Scan(&email, &displayName, &state, &pwHash, &tombstone)
	if err != nil {
		t.Fatalf("pseudonymized row not found: %v", err)
	}
	if state != "deleted" || displayName != "deleted user" || pwHash != nil {
		t.Fatalf("PII not purged: state=%s name=%s pwHash=%v", state, displayName, pwHash)
	}
	if len(tombstone) == 0 {
		t.Fatal("no tombstone recorded")
	}
	// The tombstone must NOT contain the original address.
	if containsBytes(tombstone, user+"@example.test") {
		t.Fatalf("tombstone leaks the email address: %s", tombstone)
	}

	// The handle is retired and reserved, not recycled.
	var reserved bool
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT reserved FROM handles WHERE handle LIKE 'del-%' ORDER BY created_at DESC LIMIT 1`).Scan(&reserved); err != nil {
		t.Fatalf("retired handle not found: %v", err)
	}
	if !reserved {
		t.Fatal("retired handle must be reserved against impersonation")
	}

	// Published content was YANKED, not deleted (§5.5, §12.7): the row and
	// its archive digest survive so installed copies still verify.
	var vStatus, digest string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT av.status, coalesce(av.archive_digest,'') FROM agent_versions av
		 JOIN agents a ON a.id = av.agent_id WHERE a.name = 'doomed'`).Scan(&vStatus, &digest); err != nil {
		t.Fatalf("version row missing after erasure: %v", err)
	}
	if vStatus != "yanked" {
		t.Fatalf("published version status = %s, want yanked", vStatus)
	}
	if digest == "" {
		t.Fatal("archive digest was cleared — installed copies could no longer verify")
	}

	// The audit trail records the erasure with an opaque actor id.
	var n int64
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'user.delete'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no user.delete audit event")
	}
	// No extension erases anything here, so the detail names none
	// (agentry#638).
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'user.delete' AND target_id = $1 AND detail ? 'extensions'`, uid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("user.delete detail names extensions with none registered")
	}
}

func containsBytes(haystack []byte, needle string) bool {
	return len(needle) > 0 && len(haystack) > 0 &&
		stringIndex(string(haystack), needle) >= 0
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
