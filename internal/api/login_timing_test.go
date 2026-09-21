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
// password, a suspended one — still pays the argon2id comparison, so the
// time a refusal takes does not say which of those it was. The wrong-
// password path is the reference; each miss path must take at least half
// of it, which no path that skipped the comparison could (the lookup
// alone is a few milliseconds against argon2id's hundred).
func TestLoginMissCostsAsMuchAsAWrongPassword(t *testing.T) {
	env := newTestEnv(t)
	knownH := env.register("lt-known")
	env.verifyEmail(knownH)
	ssoH := env.register("lt-sso")
	env.verifyEmail(ssoH)
	suspendedH := env.register("lt-suspended")
	env.verifyEmail(suspendedH)
	for handle, set := range map[string]string{ssoH: "password_hash = NULL", suspendedH: "state = 'suspended'"} {
		if _, err := env.st.Pool().Exec(context.Background(),
			`UPDATE users SET `+set+` WHERE id = (SELECT id FROM handles WHERE handle = $1)`, handle); err != nil {
			t.Fatal(err)
		}
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
	// The smallest of a few samples stands for each path, and the paths
	// are sampled in turn rather than one after another, so a load swing
	// on the machine lands on all of them alike; a slow sample only ever
	// makes a path look more expensive.
	misses := map[string]string{
		"unknown account":          "lt-nobody" + env.sfx,
		"account with no password": ssoH,
		"suspended account":        suspendedH,
	}
	best := map[string]time.Duration{}
	for range 3 {
		for name, login := range misses {
			if d := attempt(login); best[name] == 0 || d < best[name] {
				best[name] = d
			}
		}
		if d := attempt(knownH); best["reference"] == 0 || d < best["reference"] {
			best["reference"] = d
		}
	}
	reference := best["reference"]
	for name := range misses {
		if took := best[name]; took*2 < reference {
			t.Errorf("%s: refused in %v, the wrong-password path takes %v — the miss is visible in the timing", name, took, reference)
		}
	}
}
