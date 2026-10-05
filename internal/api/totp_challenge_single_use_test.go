package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
)

// The second leg of a 2FA social login is single use (agentry#457): its
// challenge is recorded as consumed in the database when it completes, so
// it cannot open a second session within its five minutes, at this replica
// or any other, and a store that cannot be reached refuses it.

// pendingTOTPChallenge enrols a TOTP second factor on a fresh account and
// signs it in through the fake GitHub, returning the challenge the social
// callback answered with, the TOTP secret and the account's id.
func pendingTOTPChallenge(t *testing.T, env *testEnv, gh *fakeGitHub, name string) (challenge, secret string, userID uuid.UUID) {
	t.Helper()
	handle := env.register(name)
	env.verifyEmail(handle)
	sess := env.login(handle)
	var setup struct {
		Secret string `json:"secret"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/2fa/totp/setup", nil, &setup, http.StatusOK)
	code, err := totpCode(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/2fa/totp/verify",
		map[string]any{"code": code}, nil, http.StatusNoContent)
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, handle+"@example.test").Scan(&userID); err != nil {
		t.Fatal(err)
	}

	gh.email = handle + "@example.test"
	gh.verified = true
	return socialChallenge(t, env), setup.Secret, userID
}

// socialChallenge signs the fake GitHub's account in at env and returns the
// challenge its callback answered with.
func socialChallenge(t *testing.T, env *testEnv) string {
	t.Helper()
	res := env.socialLogin(t, "github")
	defer func() { _ = res.Body.Close() }()
	var out struct {
		TotpRequired bool    `json:"totpRequired"`
		Challenge    *string `json:"challenge"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || !out.TotpRequired || out.Challenge == nil {
		t.Fatalf("social callback: %d %+v, want 200 with a challenge", res.StatusCode, out)
	}
	return *out.Challenge
}

// completeChallenge presents the challenge with a current code at env and
// returns the status, the problem type (empty on success) and whether a
// session cookie came back.
func completeChallenge(t *testing.T, env *testEnv, challenge, secret string) (int, string, bool) {
	t.Helper()
	code, err := totpCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	res := env.do(anonymous, http.MethodPost, "/api/v1/auth/2fa/totp/challenge",
		map[string]any{"challenge": challenge, "code": code})
	defer func() { _ = res.Body.Close() }()
	session := false
	for _, c := range res.Cookies() {
		if c.Name == "agentry_session" && c.Value != "" {
			session = true
		}
	}
	var p struct {
		Type string `json:"type"`
	}
	if res.StatusCode != http.StatusOK {
		_ = json.NewDecoder(res.Body).Decode(&p)
	}
	return res.StatusCode, p.Type, session
}

// loginFailureReasons lists the reasons of the user's challenge-stage login
// failures in the audit trail, oldest first.
func loginFailureReasons(t *testing.T, env *testEnv, userID uuid.UUID) []string {
	t.Helper()
	rows, err := env.st.Pool().Query(context.Background(),
		`SELECT COALESCE(detail->>'reason', '') FROM audit_events
		  WHERE action = 'user.login_failed' AND actor_id = $1 AND detail->>'stage' = 'totp_challenge'
		  ORDER BY occurred_at`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestTOTPChallengeIsRefusedWhenReplayed(t *testing.T) {
	gh := newFakeGitHub(t)
	env := newTestEnvCfg(t, gh.configure)
	challenge, secret, userID := pendingTOTPChallenge(t, env, gh, "totp-replay")

	if status, typ, session := completeChallenge(t, env, challenge, secret); status != http.StatusOK || !session {
		t.Fatalf("first completion: %d %q session=%v, want 200 with a session", status, typ, session)
	}
	status, typ, session := completeChallenge(t, env, challenge, secret)
	if status != http.StatusUnauthorized || typ != api.ProblemTypeBase+"totp-challenge-used" || session {
		t.Fatalf("replayed challenge: %d %q session=%v, want 401 totp-challenge-used and no session", status, typ, session)
	}
	if got := loginFailureReasons(t, env, userID); len(got) != 1 || got[0] != "replayed" {
		t.Fatalf("audit reasons %v, want [replayed]", got)
	}
}

// The consumed set is shared, not per process: a challenge completed at one
// replica is refused at another that shares the database.
func TestTOTPChallengeReplayIsRefusedAtAnotherReplica(t *testing.T) {
	gh := newFakeGitHub(t)
	a := newTestEnvCfg(t, gh.configure)
	b := newTestEnvCfg(t, gh.configure)
	challenge, secret, _ := pendingTOTPChallenge(t, a, gh, "totp-xrep")

	if status, typ, _ := completeChallenge(t, a, challenge, secret); status != http.StatusOK {
		t.Fatalf("completion at the first replica: %d %q, want 200", status, typ)
	}
	if status, typ, session := completeChallenge(t, b, challenge, secret); status != http.StatusUnauthorized || typ != api.ProblemTypeBase+"totp-challenge-used" || session {
		t.Fatalf("replay at the other replica: %d %q session=%v, want 401 totp-challenge-used", status, typ, session)
	}
	// The control: a challenge the first replica sealed and nobody completed
	// (the same account signing in again) completes at the other, so the
	// refusal above came from the shared set and not from a replica that
	// cannot open what the first one sealed.
	fresh := socialChallenge(t, a)
	if status, typ, session := completeChallenge(t, b, fresh, secret); status != http.StatusOK || !session {
		t.Fatalf("a fresh challenge at the other replica: %d %q session=%v, want 200 with a session", status, typ, session)
	}
}

// Two completions of one challenge at once, at two replicas, open one
// session between them: the insert decides, not a read before it.
func TestTOTPChallengeSingleUseHoldsUnderConcurrentCompletions(t *testing.T) {
	gh := newFakeGitHub(t)
	a := newTestEnvCfg(t, gh.configure)
	b := newTestEnvCfg(t, gh.configure)
	challenge, secret, _ := pendingTOTPChallenge(t, a, gh, "totp-race")

	code, err := totpCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"challenge": challenge, "code": code})
	if err != nil {
		t.Fatal(err)
	}
	const each = 4
	type result struct {
		status int
		typ    string
		err    error
	}
	results := make(chan result, 2*each)
	start := make(chan struct{})
	for i := range 2 * each {
		env := a
		if i%2 == 1 {
			env = b
		}
		go func() {
			<-start
			res, err := env.srv.Client().Post(env.srv.URL+"/api/v1/auth/2fa/totp/challenge", "application/json", bytes.NewReader(body))
			if err != nil {
				results <- result{err: err}
				return
			}
			defer func() { _ = res.Body.Close() }()
			var p struct {
				Type string `json:"type"`
			}
			_ = json.NewDecoder(res.Body).Decode(&p)
			results <- result{status: res.StatusCode, typ: p.Type}
		}()
	}
	close(start)
	won := 0
	for range 2 * each {
		r := <-results
		switch {
		case r.err != nil:
			t.Errorf("a racing completion: %v", r.err)
		case r.status == http.StatusOK:
			won++
		case r.status == http.StatusUnauthorized && r.typ == api.ProblemTypeBase+"totp-challenge-used":
		default:
			t.Errorf("a racing completion: %d %q, want 200 or 401 totp-challenge-used", r.status, r.typ)
		}
	}
	if won != 1 {
		t.Fatalf("%d racing completions opened a session, want exactly 1", won)
	}
}

// A consumed set that cannot be reached refuses the challenge and opens no
// session; once it answers again, the challenge it never recorded completes
// once, and only once.
func TestTOTPChallengeFailsClosedWhenTheStoreDoesNotAnswer(t *testing.T) {
	gh := newFakeGitHub(t)
	env := newTestEnvCfg(t, gh.configure)
	challenge, secret, _ := pendingTOTPChallenge(t, env, gh, "totp-dead")

	env.srvObj.SetTOTPConsumeTimeout(300 * time.Millisecond)
	ctx := context.Background()
	tx, err := env.st.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE totp_consumed_challenges IN ACCESS EXCLUSIVE MODE`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	status, typ, session := completeChallenge(t, env, challenge, secret)
	// The lock is held until the server's cancelled insert has left the
	// database: released any earlier, the insert could still commit.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := env.st.Pool().QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND query LIKE '%INSERT INTO totp_consumed_challenges%' AND pid <> pg_backend_pid()`).Scan(&waiting); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if waiting == 0 {
			break
		}
		if time.Now().After(deadline) {
			_ = tx.Rollback(ctx)
			t.Fatal("the cancelled insert is still waiting on the lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = tx.Rollback(ctx)
	if status == http.StatusOK || session {
		t.Fatalf("a challenge the store could not record: %d %q session=%v, want a refusal and no session", status, typ, session)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("a challenge the store could not record: %d %q, want 503", status, typ)
	}

	if status, typ, _ := completeChallenge(t, env, challenge, secret); status != http.StatusOK {
		t.Fatalf("completion once the store answers: %d %q, want 200", status, typ)
	}
	if status, typ, _ := completeChallenge(t, env, challenge, secret); status != http.StatusUnauthorized || typ != api.ProblemTypeBase+"totp-challenge-used" {
		t.Fatalf("replay after the store came back: %d %q, want 401 totp-challenge-used", status, typ)
	}
}

// The expiry still binds, and its refusal is told apart from a replay's in
// the audit trail.
func TestTOTPChallengeExpiryIsRefusedAndAuditedApartFromAReplay(t *testing.T) {
	gh := newFakeGitHub(t)
	env := newTestEnvCfg(t, gh.configure)
	_, secret, userID := pendingTOTPChallenge(t, env, gh, "totp-expired")

	stale, err := env.srvObj.SealTOTPChallengeAt(userID, "github", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	status, typ, session := completeChallenge(t, env, stale, secret)
	if status != http.StatusUnauthorized || typ != api.ProblemTypeBase+"totp-challenge-expired" || session {
		t.Fatalf("expired challenge: %d %q session=%v, want 401 totp-challenge-expired", status, typ, session)
	}
	if got := loginFailureReasons(t, env, userID); len(got) != 1 || got[0] != "expired" {
		t.Fatalf("audit reasons %v, want [expired]", got)
	}
}
