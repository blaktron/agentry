package api_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"
)

// TestLoginMissCostsAsMuchAsAWrongPassword (agentry#413): a login that
// finds no password to check — an unknown login, an account without a
// password, an inactive one — still pays the argon2id comparison, so the
// time a refusal takes does not say which of those it was. The wrong-
// password path is the reference; the miss paths must take a comparable
// time (well above what the database lookup alone costs).
func TestLoginMissCostsAsMuchAsAWrongPassword(t *testing.T) {
	env := newTestEnv(t)
	knownH := env.register("lt-known")
	env.verifyEmail(knownH)
	ssoH := env.register("lt-sso")
	env.verifyEmail(ssoH)
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE users SET password_hash = NULL WHERE id = (SELECT id FROM handles WHERE handle = $1)`, ssoH); err != nil {
		t.Fatal(err)
	}

	attempt := func(login string) time.Duration {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/api/v1/auth/login",
			bytes.NewReader(mustJSON(map[string]any{"login": login, "password": "not-the-password"})))
		req.Header.Set("Content-Type", "application/json")
		start := time.Now()
		res, err := env.srv.Client().Do(req)
		took := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("login %q: %d, want 401", login, res.StatusCode)
		}
		return took
	}
	// The smallest of a few samples stands for each path: a slow sample
	// from a busy machine only ever makes a path look more expensive.
	fastest := func(login string) time.Duration {
		best := time.Duration(1<<63 - 1)
		for range 3 {
			if d := attempt(login); d < best {
				best = d
			}
		}
		return best
	}
	reference := fastest(knownH)
	for name, login := range map[string]string{
		"unknown account":          "lt-nobody" + env.sfx,
		"account with no password": ssoH,
	} {
		if took := fastest(login); took*3 < reference {
			t.Errorf("%s: refused in %v, the wrong-password path takes %v — the miss is visible in the timing", name, took, reference)
		}
	}
}
