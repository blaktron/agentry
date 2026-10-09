package api_test

// POST /user/clear-data (agentry#498): the account's credentials, installs
// and settings go, the account stays. Seeds one of each class, clears, and
// checks each is gone while the caller's session, the QuickAgents, the
// memberships and the stars survive; the audit row carries the counts and
// extensions hear user.data_cleared once.

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/pkg/reportdesign"
)

func TestClearCurrentUserData(t *testing.T) {
	var mu sync.Mutex
	var seen []api.Event
	env := newTestEnvWith(t, func(s *api.Server) {
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "user.data_cleared" {
				mu.Lock()
				seen = append(seen, ev)
				mu.Unlock()
			}
		})
	})
	ctx := context.Background()

	// An author with a published QuickAgent, so there is something to install.
	authorH := env.register("cd-author")
	env.verifyEmail(authorH)
	author := env.login(authorH)
	env.doJSON(author, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": authorH, "name": "keeper", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.publishVersions(t, author, authorH, "keeper", []versionFiles{
		{"1.0.0", installCapsFiles(authorH, "keeper", "1.0.0", []string{"api.example"}, nil)},
	})

	// The person who clears: one of every class the clear touches, and one of
	// every class it must leave alone.
	h := env.register("cd-person")
	env.verifyEmail(h)
	sess := env.login(h)
	other := env.login(h) // a second browser
	uid := env.selfID(sess)
	_, pat := env.mintPAT(sess, "cd-pat", "agent:read")
	_, _ = env.mintPAT(sess, "cd-pat-2", "repo:read")
	env.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "laptop", "publicKey": testPublicKeyLine(t)}, nil, http.StatusCreated)
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO trusted_devices (id, user_id, token_sha256, expires_at) VALUES (gen_random_uuid(), $1, decode(md5(random()::text), 'hex'), now() + interval '30 days')`, uid); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := env.putInstall(t, sess, authorH+"/keeper", map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
		t.Fatalf("install: %d", code)
	}
	env.doJSON(sess, http.MethodPatch, "/api/v1/user", map[string]any{"displayName": "Clear Me"}, nil, http.StatusOK)
	env.doJSON(sess, http.MethodPut, "/api/v1/user/notifications", map[string]any{
		"email": map[string]any{"dependencyAlerts": false, "quarantine": false, "reviewDecisions": false, "advisories": false, "orgInvites": false},
		"web":   map[string]any{"dependencyAlerts": false},
	}, nil, http.StatusOK)
	classic, _ := reportdesign.BuiltinDocument("classic")
	env.doJSON(sess, http.MethodPut, "/api/v1/user/report-settings", map[string]any{"design": json.RawMessage(classic)}, nil, http.StatusOK)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": h, "name": "mine", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.publishVersions(t, sess, h, "mine", []versionFiles{
		{"1.0.0", installCapsFiles(h, "mine", "1.0.0", []string{"api.example"}, nil)},
	})
	orgID := env.createOrg(sess, "cd-org"+env.sfxDigits())
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO desktop_grants (id, user_id, code_sha256, state_sha256, scopes, name, expires_at)
		 VALUES (gen_random_uuid(), $1, decode(md5(random()::text), 'hex'), '\x02', '{agent:read}', 'desktop', now() + interval '60 seconds')`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO stars (user_id, agent_id) SELECT $1, id FROM agents WHERE name = 'keeper' AND namespace_id = (SELECT id FROM handles WHERE handle = $2)`, uid, authorH); err != nil {
		t.Fatal(err)
	}

	// A knowledge pack (agentry#593): the clear takes it, the key that
	// opens it and its sealed tree.
	kn := seedKnowledge(t, env, knowledge.User(uuid.MustParse(uid)))

	var liveTokens int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM pats WHERE user_id = $1 AND revoked_at IS NULL`, uid).Scan(&liveTokens); err != nil || liveTokens < 2 {
		t.Fatalf("live tokens before clearing: %d (%v)", liveTokens, err)
	}

	// A token cannot clear (session only).
	res := env.do(caller{name: "pat", pat: pat}, http.MethodPost, "/api/v1/user/clear-data", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("PAT clear must 403, got %d", res.StatusCode)
	}

	env.doJSON(sess, http.MethodPost, "/api/v1/user/clear-data", nil, nil, http.StatusNoContent)

	// The caller stays signed in; the other browser and the token do not.
	if r := env.do(sess, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("the caller's session after clearing: %d, want 200", r.StatusCode)
	}
	if r := env.do(other, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("another session after clearing: %d, want 401", r.StatusCode)
	}
	if r := env.do(caller{name: "pat", pat: pat}, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a PAT after clearing: %d, want 401", r.StatusCode)
	}

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := env.st.Pool().QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	for what, n := range map[string]int{
		"live PATs":                count(`SELECT count(*) FROM pats WHERE user_id = $1 AND revoked_at IS NULL`, uid),
		"live SSH keys":            count(`SELECT count(*) FROM user_ssh_keys WHERE user_id = $1 AND revoked_at IS NULL`, uid),
		"trusted devices":          count(`SELECT count(*) FROM trusted_devices WHERE user_id = $1`, uid),
		"account installs":         count(`SELECT count(*) FROM account_installs WHERE user_id = $1`, uid),
		"notification settings":    count(`SELECT count(*) FROM user_notification_settings WHERE user_id = $1`, uid),
		"report settings":          count(`SELECT count(*) FROM user_report_settings WHERE user_id = $1`, uid),
		"unconsumed desktop codes": count(`SELECT count(*) FROM desktop_grants WHERE user_id = $1 AND consumed_at IS NULL`, uid),
	} {
		if n != 0 {
			t.Errorf("%s after clearing: %d, want 0", what, n)
		}
	}
	assertKnowledgeGone(t, env, kn)
	var name string
	if err := env.st.Pool().QueryRow(ctx, `SELECT display_name FROM users WHERE id = $1`, uid).Scan(&name); err != nil || name != "" {
		t.Errorf("display name after clearing: %q (%v), want empty", name, err)
	}

	// What must survive.
	if n := count(`SELECT count(*) FROM agents WHERE namespace_id = $1`, uid); n != 1 {
		t.Errorf("QuickAgents after clearing: %d, want 1", n)
	}
	if n := count(`SELECT count(*) FROM stars WHERE user_id = $1`, uid); n != 1 {
		t.Errorf("stars after clearing: %d, want 1", n)
	}
	if n := count(`SELECT count(*) FROM agent_versions v JOIN agents a ON a.id = v.agent_id WHERE a.namespace_id = $1 AND v.status = 'published'`, uid); n != 1 {
		t.Errorf("published versions after clearing: %d, want 1", n)
	}
	if n := count(`SELECT count(*) FROM memberships WHERE user_id = $1 AND org_id = $2`, uid, orgID); n != 1 {
		t.Errorf("the organization membership after clearing: %d, want 1", n)
	}
	if n := count(`SELECT count(*) FROM users WHERE id = $1 AND state = 'active' AND deleted_tombstone IS NULL`, uid); n != 1 {
		t.Error("the account is no longer active after clearing")
	}

	// One audit row with the counts.
	var detail []byte
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT detail FROM audit_events WHERE action = 'user.data_clear' AND target_id = $1`, uid).Scan(&detail); err != nil {
		t.Fatalf("audit user.data_clear: %v", err)
	}
	var d map[string]any
	_ = json.Unmarshal(detail, &d)
	if d["tokens"] != float64(liveTokens) || d["sshKeys"] != float64(1) || d["trustedDevices"] != float64(1) || d["desktopCodes"] != float64(1) || d["otherSessions"] != float64(1) || d["installs"] != float64(1) || d["notificationSettingsReset"] != true || d["reportSettingsReset"] != true {
		t.Errorf("audit detail = %s", detail)
	}
	// No extension erases anything here, so the detail names none
	// (agentry#638).
	if _, ok := d["extensions"]; ok {
		t.Errorf("audit detail names extensions with none registered: %s", detail)
	}

	// Extensions heard it once, for this user (fireEvent is synchronous).
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0].UserID.String() != uid {
		t.Fatalf("user.data_cleared: %+v, want one event for %s", seen, uid)
	}
}
