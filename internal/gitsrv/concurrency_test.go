package gitsrv_test

// §19's per-address budget of concurrent git operations, through the real
// smart-HTTP transport and the api middleware that resolves the client
// address (agentry#454). The finding was starvation of *other* callers, so
// each test holds one address at its budget and asks what a second address
// gets; and a budget keyed on a header the client writes would be worse than
// none, so the untrusted case checks that X-Forwarded-For buys nothing.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/config"
)

// holdUploadPack opens a git-upload-pack request from addr whose body never
// ends: the server admits it, starts git, and git waits on its stdin, so
// the operation's slot stays held until the returned func is called (or
// the test ends).
func (e *gitEnv) holdUploadPack(t *testing.T, repo, addr string) (release func()) {
	t.Helper()
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/%s/%s.git/git-upload-pack", e.srv.URL, e.owner.handle, repo), pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("X-Forwarded-For", addr)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if res, err := e.srv.Client().Do(req); err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
	}()
	var once sync.Once
	release = func() {
		once.Do(func() {
			_ = pw.CloseWithError(io.ErrUnexpectedEOF)
			cancel()
			<-done
		})
	}
	// Registered after the env's server, so it runs before the server's
	// Close, which would otherwise wait forever on the held request when a
	// test fails before releasing it.
	t.Cleanup(release)
	return release
}

// infoRefs asks for the upload-pack advertisement as addr and returns the
// status.
func (e *gitEnv) infoRefs(t *testing.T, repo, addr string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s/%s.git/info/refs?service=git-upload-pack", e.srv.URL, e.owner.handle, repo), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", addr)
	res, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return res.StatusCode
}

// untilStatus polls infoRefs as addr until it answers want, or fails.
func (e *gitEnv) untilStatus(t *testing.T, repo, addr string, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := e.infoRefs(t, repo, addr)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("info/refs as %s: %d, want %d", addr, got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func seedPublicRepo(t *testing.T, e *gitEnv, name string) {
	t.Helper()
	e.seedAgent(name, "public")
	work := seedWorkdir(t, map[string]string{"agent.yaml": "schemaVersion: \"1\"\n", "README.md": "# budget\n"})
	mustGit(t, work, "remote", "add", "origin", e.cloneURL(name, e.owner.patRW))
	mustGit(t, work, "push", "origin", "main")
}

// Behind a trusted proxy each forwarded address is its own client: one at
// its budget is refused with 429, another is served beside it, and the
// first is served again once its operation ends.
func TestGitConcurrencyIsBudgetedPerTrustedAddress(t *testing.T) {
	env := newGitEnvCfg(t, func(c *config.Config) {
		c.Limits.GitConcurrentPerIP = 1
		c.HTTP.TrustedProxies = 1
		c.HTTP.TrustedProxyCIDRs = []string{"127.0.0.0/8", "::1/128"}
	})
	seedPublicRepo(t, env, "budget-a")
	seedPublicRepo(t, env, "budget-b")
	const greedy, other = "203.0.113.7", "198.51.100.9"

	release := env.holdUploadPack(t, "budget-a", greedy)
	// The held operation is admitted asynchronously; the refusal of the
	// next one from the same address is what shows it holds the slot. On
	// another repository, so the per-repository cap is not what refuses it.
	env.untilStatus(t, "budget-b", greedy, http.StatusTooManyRequests)

	if got := env.infoRefs(t, "budget-b", other); got != http.StatusOK {
		t.Fatalf("a second address beside one at its budget: info/refs %d, want 200", got)
	}
	if got := env.infoRefs(t, "budget-a", other); got != http.StatusOK {
		t.Fatalf("a second address on the held repository: info/refs %d, want 200", got)
	}

	release()
	env.untilStatus(t, "budget-b", greedy, http.StatusOK)
}

// With no trusted proxy (the default) X-Forwarded-For is the client's own
// writing, so it cannot move a request out of the peer's budget.
func TestGitConcurrencyBudgetIgnoresAnUntrustedForwardedFor(t *testing.T) {
	env := newGitEnvCfg(t, func(c *config.Config) {
		c.Limits.GitConcurrentPerIP = 1
	})
	seedPublicRepo(t, env, "spoof-a")
	seedPublicRepo(t, env, "spoof-b")

	env.holdUploadPack(t, "spoof-a", "203.0.113.7")
	env.untilStatus(t, "spoof-b", "203.0.113.7", http.StatusTooManyRequests)
	if got := env.infoRefs(t, "spoof-b", "198.51.100.9"); got != http.StatusTooManyRequests {
		t.Fatalf("a forged X-Forwarded-For from the same peer: info/refs %d, want 429 (the peer's budget)", got)
	}
}
