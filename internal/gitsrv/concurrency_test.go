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
// ends: the server admits it, starts git, and git waits on its stdin, so the
// operation's slot stays held until the returned func is called (or the test
// ends). It returns once the server books the slot to key, the address the
// budget is expected to charge, and fails the test if the server refuses or
// finishes the request instead.
//
// It waits on the server's own count rather than on a request from the same
// address: such a probe holds that address's slot while it runs, so with a
// budget of one it could refuse the operation being held, after which every
// probe was served and the test failed on a correct server (agentry#562).
func (e *gitEnv) holdUploadPack(t *testing.T, repo, addr, key string) (release func()) {
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
	status := make(chan int, 1) // the held request's status, should it end
	go func() {
		defer close(done)
		res, err := e.srv.Client().Do(req)
		if err != nil {
			return
		}
		status <- res.StatusCode
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
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
	e.untilClientOps(t, key, 1, status, done)
	return release
}

// untilClientOps waits until the server counts want operations held by the
// client address key. status and done belong to a held request: if it ends
// before the count is reached, the wait fails at once with its status.
func (e *gitEnv) untilClientOps(t *testing.T, key string, want int, status <-chan int, done <-chan struct{}) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if got := e.git.ClientOpsHeld(key); got == want {
			return
		}
		select {
		case code := <-status:
			t.Fatalf("the held upload-pack ended with %d before %s held %d operation(s)", code, key, want)
		case <-done:
			t.Fatalf("the held upload-pack failed before %s held %d operation(s)", key, want)
		case <-tick.C:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s holds %d git operation(s) after 10s, want %d", key, e.git.ClientOpsHeld(key), want)
		}
	}
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

	release := env.holdUploadPack(t, "budget-a", greedy, greedy)
	// The address is at its budget: its next operation is refused. On
	// another repository, so the per-repository cap is not what refuses it.
	if got := env.infoRefs(t, "budget-b", greedy); got != http.StatusTooManyRequests {
		t.Fatalf("an address at its budget: info/refs %d, want 429", got)
	}

	if got := env.infoRefs(t, "budget-b", other); got != http.StatusOK {
		t.Fatalf("a second address beside one at its budget: info/refs %d, want 200", got)
	}
	if got := env.infoRefs(t, "budget-a", other); got != http.StatusOK {
		t.Fatalf("a second address on the held repository: info/refs %d, want 200", got)
	}

	release()
	// The server lets the slot go when git exits, after the client has
	// already hung up.
	env.untilClientOps(t, greedy, 0, nil, nil)
	if got := env.infoRefs(t, "budget-b", greedy); got != http.StatusOK {
		t.Fatalf("the address once its operation ended: info/refs %d, want 200", got)
	}
}

// With no trusted proxy (the default) X-Forwarded-For is the client's own
// writing, so it cannot move a request out of the peer's budget.
func TestGitConcurrencyBudgetIgnoresAnUntrustedForwardedFor(t *testing.T) {
	env := newGitEnvCfg(t, func(c *config.Config) {
		c.Limits.GitConcurrentPerIP = 1
	})
	seedPublicRepo(t, env, "spoof-a")
	seedPublicRepo(t, env, "spoof-b")

	// The slot is booked to the peer, not to the address the client wrote.
	env.holdUploadPack(t, "spoof-a", "203.0.113.7", "127.0.0.1")
	if got := env.infoRefs(t, "spoof-b", "203.0.113.7"); got != http.StatusTooManyRequests {
		t.Fatalf("the peer at its budget: info/refs %d, want 429", got)
	}
	if got := env.infoRefs(t, "spoof-b", "198.51.100.9"); got != http.StatusTooManyRequests {
		t.Fatalf("a forged X-Forwarded-For from the same peer: info/refs %d, want 429 (the peer's budget)", got)
	}
}
