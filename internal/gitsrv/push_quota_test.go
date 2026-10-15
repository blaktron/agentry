package gitsrv_test

// 60 pushes/h per repo. Without a push budget a loop could drive unbounded
// git subprocesses and pack writes against one repository.
//
// The check sits in receivePack, at the admission point, rather than in the
// pre-receive hook: the hook is a fresh process per push with no shared state,
// so a token bucket there would be empty on every invocation. Enforcing before
// the subprocess starts also means a repo under a hammering costs a 429 rather
// than a fork and a packfile.

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// receivePackAttempt makes the admission-level request a `git push` makes,
// with an empty body. The push budget is spent before the body matters, so an
// empty request is enough to observe the quota — and much cheaper than 60
// real pushes.
func (e *gitEnv) receivePackAttempt(t *testing.T, ns, agent, pat string) *http.Response {
	t.Helper()
	url := strings.TrimSuffix(e.srv.URL, "/") + "/" + ns + "/" + agent + ".git/git-receive-pack"
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("token", pat)
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("receive-pack request: %v", err)
	}
	return res
}

func TestPushQuotaRefusesPastTheHourlyBudget(t *testing.T) {
	const budget = 3
	env := newGitEnvCfg(t, func(c *config.Config) { c.Limits.GitPushesPerHour = budget })
	agent := env.seedAgent("pushquota", "private")
	_ = agent

	// The whole budget is the burst: the limit is 60 pushes/h, not one a
	// minute, so a developer landing a run of commits must not be paced.
	for i := range budget {
		res := env.receivePackAttempt(t, env.owner.handle, "pushquota", env.owner.patRW)
		_ = res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("push %d of %d within the budget was refused", i+1, budget)
		}
	}

	res := env.receivePackAttempt(t, env.owner.handle, "pushquota", env.owner.patRW)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("push %d past a budget of %d returned %d, want 429", budget+1, budget, res.StatusCode)
	}
	// A refusal has to tell the client when to come back, or it will spin.
	retry := res.Header.Get("Retry-After")
	if retry == "" {
		t.Fatal("a 429 with no Retry-After leaves the client guessing")
	}
	if n, err := strconv.Atoi(retry); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want a positive integer of seconds", retry)
	}
}

// The budget is per repository: one busy repo must not lock out another.
func TestPushQuotaIsPerRepo(t *testing.T) {
	const budget = 2
	env := newGitEnvCfg(t, func(c *config.Config) { c.Limits.GitPushesPerHour = budget })
	env.seedAgent("busyrepo", "private")
	env.seedAgent("quietrepo", "private")

	for range budget + 1 {
		res := env.receivePackAttempt(t, env.owner.handle, "busyrepo", env.owner.patRW)
		_ = res.Body.Close()
	}
	// busyrepo is now over budget; quietrepo must be untouched.
	res := env.receivePackAttempt(t, env.owner.handle, "quietrepo", env.owner.patRW)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusTooManyRequests {
		t.Fatal("a second repository inherited the first one's exhausted budget")
	}
}

// The quota must not become an authorization bypass: a caller with no write
// permission is refused on permission grounds, and never sees a 429 that would
// tell it the repo exists and is merely busy.
func TestPushQuotaRunsAfterAuthorization(t *testing.T) {
	const budget = 1
	env := newGitEnvCfg(t, func(c *config.Config) { c.Limits.GitPushesPerHour = budget })
	env.seedAgent("authfirst", "private")

	// Exhaust the budget with a legitimate writer.
	for range budget + 1 {
		res := env.receivePackAttempt(t, env.owner.handle, "authfirst", env.owner.patRW)
		_ = res.Body.Close()
	}

	// A read-only PAT must still be refused as forbidden, not throttled.
	res := env.receivePackAttempt(t, env.owner.handle, "authfirst", env.owner.patRO)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusTooManyRequests {
		t.Fatal("an unauthorized caller was throttled instead of refused; " +
			"the quota must be checked after authorization, not before")
	}
	if res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusNotFound {
		t.Errorf("read-only PAT push returned %d, want 403 or 404", res.StatusCode)
	}
}

// A push that never reaches the quota check must not spend a token — the
// budget belongs to pushes, not to unauthenticated probes.
func TestPushQuotaIsNotSpentByAnonymousProbes(t *testing.T) {
	const budget = 2
	env := newGitEnvCfg(t, func(c *config.Config) { c.Limits.GitPushesPerHour = budget })
	env.seedAgent("probed", "private")

	for range 5 {
		res := env.receivePackAttempt(t, env.owner.handle, "probed", "")
		_ = res.Body.Close()
	}
	// The whole budget must still be available to the real owner.
	for i := range budget {
		res := env.receivePackAttempt(t, env.owner.handle, "probed", env.owner.patRW)
		_ = res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("push %d was refused; anonymous probes spent the repo's budget", i+1)
		}
	}
}
