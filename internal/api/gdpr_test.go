package api_test

// Account-erasure flow: PII is purged, credentials die, published
// content is yanked rather than deleted (so installed copies keep verifying),
// and the audit trail keeps an opaque actor id.

import (
	"context"
	"net/http"
	"strings"
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

	// A knowledge pack goes with the account.
	uid := env.selfID(sess)
	kn := seedKnowledge(t, env, knowledge.User(uuid.MustParse(uid)))

	// So does everything else it holds: a remembered browser, an unused
	// desktop code, an activation link, a report design, a Writing Voice and
	// a seat in an organization with another admin.
	for _, q := range []string{
		`INSERT INTO trusted_devices (id, user_id, token_sha256, expires_at) VALUES (gen_random_uuid(), $1, decode(md5(random()::text), 'hex'), now() + interval '30 days')`,
		`INSERT INTO desktop_grants (id, user_id, code_sha256, state_sha256, scopes, name, expires_at)
		 VALUES (gen_random_uuid(), $1, decode(md5(random()::text), 'hex'), '\x02', '{agent:read}', 'desktop', now() + interval '60 seconds')`,
		`INSERT INTO email_verifications (token_sha256, user_id, expires_at) VALUES (decode(md5(random()::text), 'hex'), $1, now() + interval '1 day')`,
		`INSERT INTO user_report_settings (user_id, design) VALUES ($1, '{}')`,
		`INSERT INTO voices (user_id, wrapper_kind, wrapper_recipient, wrapped_key) VALUES ($1, 'test', 'test', '\x00')`,
	} {
		if _, err := env.st.Pool().Exec(context.Background(), q, uid); err != nil {
			t.Fatal(err)
		}
	}
	founder := env.register("gdpr-founder")
	env.verifyEmail(founder)
	seatOrg := "gdprseat" + env.sfx
	env.createOrg(env.login(founder), seatOrg)
	env.joinOrg(env.login(founder), seatOrg, user)

	// A PAT cannot erase the account (session-only).
	res := env.do(caller{name: "pat", pat: pat}, http.MethodPost, "/api/v1/user/delete", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("PAT erasure must 403, got %d", res.StatusCode)
	}

	// Erase.
	res = env.do(sess, http.MethodPost, "/api/v1/user/delete?publishedContent=yank", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("erasure: got %d, want 204", res.StatusCode)
	}
	if !sessionCookieCleared(res) {
		t.Fatal("the erasure left the browser holding its session cookie")
	}

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
	var tombstone []byte
	err := env.st.Pool().QueryRow(ctx,
		`SELECT email::text, display_name, state, deleted_tombstone
		 FROM users WHERE deleted_tombstone IS NOT NULL AND email LIKE 'deleted+%' ORDER BY updated_at DESC LIMIT 1`,
	).Scan(&email, &displayName, &state, &tombstone)
	if err != nil {
		t.Fatalf("pseudonymized row not found: %v", err)
	}
	if state != "deleted" || displayName != "deleted user" {
		t.Fatalf("PII not purged: state=%s name=%s", state, displayName)
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
	// This account's own row: the whole id in its retired handle (a prefix
	// could collide with another erasure), the scrubbed address, the reason
	// in its tombstone, and nothing else of it left.
	var ownHandle, ownEmail, ownReason string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT h.handle, u.email::text, u.deleted_tombstone->>'reason' FROM users u JOIN handles h ON h.id = u.id WHERE u.id = $1`, uid).Scan(&ownHandle, &ownEmail, &ownReason); err != nil {
		t.Fatal(err)
	}
	if ownHandle != "del-"+strings.ReplaceAll(uid, "-", "") || ownEmail != "deleted+"+uid+"@invalid.invalid" || ownReason != "user-requested erasure" {
		t.Fatalf("the erased account: handle %q, address %q, tombstone reason %q", ownHandle, ownEmail, ownReason)
	}
	for what, q := range map[string]string{
		"remembered browsers":  `SELECT count(*) FROM trusted_devices WHERE user_id = $1`,
		"unused desktop codes": `SELECT count(*) FROM desktop_grants WHERE user_id = $1 AND consumed_at IS NULL`,
		"activation links":     `SELECT count(*) FROM email_verifications WHERE user_id = $1`,
		"report designs":       `SELECT count(*) FROM user_report_settings WHERE user_id = $1`,
		"Writing Voices":       `SELECT count(*) FROM voices WHERE user_id = $1`,
		"seats":                `SELECT count(*) FROM memberships WHERE user_id = $1`,
		"live sessions":        `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`,
		"live tokens":          `SELECT count(*) FROM pats WHERE user_id = $1 AND revoked_at IS NULL`,
	} {
		var left int
		if err := env.st.Pool().QueryRow(ctx, q, uid).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Errorf("%d %s left after the erasure", left, what)
		}
	}

	// Published content was YANKED, not deleted: the row and
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
	// The row says what the erasure did.
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'user.delete' AND target_id = $1 AND detail->>'publishedContent' = 'yank'
		  AND detail->>'publishedVersions' = '1' AND detail->>'versionsYanked' = '1' AND detail->>'desktopCodes' = '1' AND (detail->>'knowledgeObjects')::int >= 1`, uid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("user.delete rows saying one published version yanked, one desktop code and the knowledge objects erased: %d, want 1", n)
	}
	// No extension erases anything here, so the detail names none.
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
