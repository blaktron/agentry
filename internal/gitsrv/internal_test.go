package gitsrv

// White-box conformance for the pieces whose contract is not observable over
// the git wire: the §6.2 per-repo concurrency semaphore, and the post-receive
// bookkeeping rules of §6.3 (accepted refs only, survives client
// disconnection, never fabricates a repo size).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// TestRepoSemaphoreIsolatesRepos pins §6.2's "semaphore per repo and global":
// work on one repository queues at its own cap while another repository keeps
// flowing, and the map does not grow without bound.
func TestRepoSemaphoreIsolatesRepos(t *testing.T) {
	sem := newRepoSemaphores(2)
	hot, cold := uuid.New(), uuid.New()
	ctx := context.Background()

	held := make([]func(), 0, 2)
	for i := 0; i < 2; i++ {
		release, err := sem.acquire(ctx, hot)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		held = append(held, release)
	}

	// A third operation on the hot repo must wait for a slot.
	queued := make(chan struct{})
	go func() {
		release, err := sem.acquire(ctx, hot)
		if err != nil {
			return
		}
		close(queued)
		release()
	}()
	select {
	case <-queued:
		t.Fatal("third operation on a repo at its cap must queue")
	case <-time.After(150 * time.Millisecond):
	}

	// Meanwhile the cold repo is unaffected — the point of the per-repo cap.
	proceeded := make(chan struct{})
	go func() {
		release, err := sem.acquire(ctx, cold)
		if err != nil {
			t.Errorf("cold repo acquire: %v", err)
			return
		}
		release()
		close(proceeded)
	}()
	select {
	case <-proceeded:
	case <-time.After(2 * time.Second):
		t.Fatal("a busy repo starved another repo")
	}

	// Releasing one hot slot admits the queued operation.
	held[0]()
	select {
	case <-queued:
	case <-time.After(2 * time.Second):
		t.Fatal("queued operation not admitted after a slot freed")
	}
	held[1]()

	// Idle repos are forgotten rather than accumulating forever.
	deadline := time.Now().Add(time.Second)
	for sem.tracked() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := sem.tracked(); n != 0 {
		t.Fatalf("semaphore map leaked %d entries", n)
	}
}

// TestRepoSemaphoreHonorsContext: a caller whose request is already gone stops
// waiting instead of pinning a slot forever.
func TestRepoSemaphoreHonorsContext(t *testing.T) {
	sem := newRepoSemaphores(1)
	id := uuid.New()
	release, err := sem.acquire(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sem.acquire(ctx, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire with a canceled context: %v", err)
	}
	if n := sem.tracked(); n != 1 {
		t.Fatalf("abandoned waiter left %d entries (want 1, the live holder)", n)
	}
}

// bkEnv is a Handler wired to the test database with one agent and its bare
// repo, for exercising afterReceive directly.
type bkEnv struct {
	t     *testing.T
	h     *Handler
	st    *store.Store
	reg   *registry.Service
	repos *RepoStore
	owner uuid.UUID
	sfx   string
}

func newBookkeepingEnv(t *testing.T) *bkEnv {
	t.Helper()
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set; skipping git bookkeeping tests")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	st, err := store.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	cfg := config.Default()
	cfg.DevMode = true
	cfg.Git.DataDir = t.TempDir()
	cfg.Git.HooksDir = t.TempDir()
	cfg.Storage.LocalDir = t.TempDir()
	repos, err := NewRepoStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	apiSrv := api.New(cfg, st, nil)
	reg := apiSrv.Reg()
	reg.SetGitArchiver(repos)

	e := &bkEnv{
		t: t, st: st, reg: reg, repos: repos,
		h:   NewHandler(cfg, st, repos, reg, audit.NewWriter(nil), nil),
		sfx: fmt.Sprintf("%06x", rand.Int63n(1<<24)), //nolint:gosec // test fixture naming
	}
	e.owner = e.seedUser("bko" + e.sfx)
	return e
}

func (e *bkEnv) seedUser(handle string) uuid.UUID {
	e.t.Helper()
	ctx := context.Background()
	q := e.st.Queries()
	id := uuid.New()
	if err := q.CreateHandle(ctx, storegen.CreateHandleParams{ID: id, Handle: handle, Kind: "user"}); err != nil {
		e.t.Fatal(err)
	}
	hash := "x"
	if _, err := q.CreateUser(ctx, storegen.CreateUserParams{ID: id, Email: handle + "@example.test", DisplayName: handle, PasswordHash: &hash}); err != nil {
		e.t.Fatal(err)
	}
	if err := q.MarkEmailVerified(ctx, id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// seedAgent creates an agent plus its bare repo, and returns it with a commit
// already present on refs/heads/main (built with plumbing — this test drives
// afterReceive directly, not the wire).
func (e *bkEnv) seedAgent(name string) (registry.Agent, string) {
	e.t.Helper()
	p := &auth.Principal{UserID: e.owner, Handle: "bko" + e.sfx, Via: "session", EmailVerified: true}
	agent, err := e.reg.CreateAgent(context.Background(), p, registry.CreateAgentInput{
		Namespace: "bko" + e.sfx, Name: name, Modes: []string{"autonomous"}, Visibility: "public",
	}, audit.Event{Actor: e.owner, ActorKind: audit.ActorUser})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.repos.InitBare(context.Background(), agent.RepoID, agent.DefaultBranch); err != nil {
		e.t.Fatal(err)
	}
	dir := e.repos.Path(agent.RepoID)
	git := func(stdin string, args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // test fixture
		cmd.Stdin = strings.NewReader(stdin)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
		out, err := cmd.Output()
		if err != nil {
			e.t.Fatalf("git %s: %v", strings.Join(args, " "), err)
		}
		return strings.TrimSpace(string(out))
	}
	blob := git("hello\n", "hash-object", "-w", "--stdin")
	tree := git("100644 blob "+blob+"\tREADME.md\n", "mktree")
	commit := git("seed\n", "commit-tree", tree)
	git("", "update-ref", "refs/heads/main", commit)
	return agent, commit
}

// pktCommands renders receive-pack command lines the way a client sends them.
func pktCommands(lines ...string) *bytes.Buffer {
	var b bytes.Buffer
	for _, l := range lines {
		fmt.Fprintf(&b, "%04x%s\n", len(l)+5, l)
	}
	b.WriteString("0000")
	return &b
}

func (e *bkEnv) repo(id uuid.UUID) storegen.Repo {
	e.t.Helper()
	r, err := e.st.Queries().GetRepo(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *bkEnv) pushAudits(agentID uuid.UUID) int {
	e.t.Helper()
	var n int
	err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'repo.push' AND target_id = $1`, agentID).Scan(&n)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestAfterReceiveBookkeeping(t *testing.T) {
	env := newBookkeepingEnv(t)
	principal := &auth.Principal{UserID: env.owner, Via: "pat", Scopes: []string{"repo:read", "repo:write"}}

	// A push the hook rejected: receive-pack still exits 0 and the requested
	// commands still name the ref, but the repository never moved.
	t.Run("rejected push writes no bookkeeping", func(t *testing.T) {
		agent, _ := env.seedAgent("rejected")
		var called int
		env.h.PostReceive = func(context.Context, registry.Agent, []RefUpdate, *auth.Principal) { called++ }
		defer func() { env.h.PostReceive = nil }()

		unapplied := strings.Repeat("1", 40)
		env.h.afterReceive(context.Background(), agent, principal,
			pktCommands(zeroOID+" "+unapplied+" refs/heads/feature\x00report-status side-band-64k"))

		r := env.repo(agent.RepoID)
		if r.LastPushAt != nil || r.SizeBytes != 0 {
			t.Fatalf("denied push bookkept: last_push_at=%v size=%d", r.LastPushAt, r.SizeBytes)
		}
		if n := env.pushAudits(agent.ID); n != 0 {
			t.Fatalf("denied push produced %d repo.push audit rows", n)
		}
		if called != 0 {
			t.Fatalf("denied push invoked the publication trigger %d times", called)
		}
	})

	// A client that hangs up the moment it has the report must not cancel the
	// bookkeeping: afterReceive detaches from the request context.
	t.Run("accepted push survives client disconnect", func(t *testing.T) {
		agent, commit := env.seedAgent("detached")
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // the request is already gone

		env.h.afterReceive(ctx, agent, principal, pktCommands(zeroOID+" "+commit+" refs/heads/main"))

		r := env.repo(agent.RepoID)
		if r.LastPushAt == nil || r.SizeBytes == 0 {
			t.Fatalf("bookkeeping lost to a canceled request: %+v", r)
		}
		if n := env.pushAudits(agent.ID); n != 1 {
			t.Fatalf("repo.push audit rows = %d, want 1", n)
		}
	})

	// A size that cannot be measured must leave the recorded size alone
	// rather than writing a 0 that reads as "empty repo" everywhere else.
	t.Run("unmeasurable size leaves the previous size intact", func(t *testing.T) {
		agent, commit := env.seedAgent("dufail")
		cmds := pktCommands(zeroOID + " " + commit + " refs/heads/main")
		env.h.afterReceive(context.Background(), agent, principal, cmds)
		before := env.repo(agent.RepoID)
		if before.SizeBytes == 0 || before.LastPushAt == nil {
			t.Fatalf("setup push not bookkept: %+v", before)
		}

		env.h.diskUsage = func(uuid.UUID) (int64, error) { return 0, errors.New("du: I/O error") }
		defer func() { env.h.diskUsage = env.repos.DiskUsage }()
		time.Sleep(10 * time.Millisecond) // make the last_push_at advance visible
		env.h.afterReceive(context.Background(), agent, principal, cmds)

		after := env.repo(agent.RepoID)
		if after.SizeBytes != before.SizeBytes {
			t.Fatalf("size overwritten on measurement failure: %d → %d", before.SizeBytes, after.SizeBytes)
		}
		if after.LastPushAt == nil || !after.LastPushAt.After(*before.LastPushAt) {
			t.Fatalf("last_push_at did not advance: %v → %v", before.LastPushAt, after.LastPushAt)
		}
	})
}

// TestAcquireGitOrdersRepoBeforeGlobal documents the acquisition order the
// handler relies on: a repo at its cap queues on its own semaphore, so it
// cannot sit on global slots while it waits.
func TestAcquireGitOrdersRepoBeforeGlobal(t *testing.T) {
	h := &Handler{sem: make(chan struct{}, 4), perRepo: newRepoSemaphores(1)}
	id := uuid.New()
	release, err := h.acquireGit(context.Background(), id, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(h.sem) != 1 {
		t.Fatalf("global slots held = %d, want 1", len(h.sem))
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := h.acquireGit(ctx, id, ""); err == nil {
			t.Error("second operation on a repo at its cap must not be admitted")
		}
	}()
	wg.Wait()
	if len(h.sem) != 1 {
		t.Fatalf("a queued repo operation consumed global slots: %d held", len(h.sem))
	}
	release()
	if len(h.sem) != 0 {
		t.Fatalf("release left %d global slots held", len(h.sem))
	}
}

// TestAcquireGitBudgetsEachClientAddress is §19's "20 concurrent git ops
// per IP" (agentry#454): one address spread over many repositories used to
// take every global slot and stall the instance. At its budget an address
// is refused at once — it does not queue, so it holds no repository's slot
// while it waits — and a second address is admitted beside it. The global
// cap here is larger than the budget, so what refuses the first address is
// its own budget, not the instance being full.
func TestAcquireGitBudgetsEachClientAddress(t *testing.T) {
	const budget = 3
	h := &Handler{
		sem:       make(chan struct{}, 8),
		perRepo:   newRepoSemaphores(4),
		perClient: newClientSemaphores(budget),
	}
	const greedy, other = "203.0.113.7", "198.51.100.9"
	var releases []func()
	for i := 0; i < budget; i++ {
		// A different repository each time: the per-repository cap is not
		// what stops this address.
		release, err := h.acquireGit(context.Background(), uuid.New(), greedy)
		if err != nil {
			t.Fatalf("operation %d within the budget: %v", i+1, err)
		}
		releases = append(releases, release)
	}

	// Refused without waiting: a context with no deadline would hang here
	// if the refusal queued.
	repo := uuid.New()
	if _, err := h.acquireGit(context.Background(), repo, greedy); !errors.Is(err, errClientBusy) {
		t.Fatalf("operation past the budget: err = %v, want errClientBusy", err)
	}
	if len(h.sem) != budget {
		t.Fatalf("a refused operation took a global slot: %d held, want %d", len(h.sem), budget)
	}
	if h.perRepo.tracked() != budget {
		t.Fatalf("a refused operation took a repository slot: %d repositories tracked, want %d", h.perRepo.tracked(), budget)
	}

	// Another address is unaffected, on the same repository too.
	release, err := h.acquireGit(context.Background(), repo, other)
	if err != nil {
		t.Fatalf("a second address beside one at its budget: %v", err)
	}
	release()

	// Releasing one of the first address's operations gives it a slot back.
	releases[0]()
	release, err = h.acquireGit(context.Background(), repo, greedy)
	if err != nil {
		t.Fatalf("after a release, within the budget again: %v", err)
	}
	release()
	for _, r := range releases[1:] {
		r()
	}
	if len(h.sem) != 0 || h.perRepo.tracked() != 0 || h.perClient.tracked() != 0 {
		t.Fatalf("slots left held: global %d, repositories %d, addresses %d", len(h.sem), h.perRepo.tracked(), h.perClient.tracked())
	}
}

// TestAcquireGitWithoutAnAddressSkipsTheBudget: an operation the server
// starts on its own behalf has no client address, and is bounded by the
// repository and global caps alone.
func TestAcquireGitWithoutAnAddressSkipsTheBudget(t *testing.T) {
	h := &Handler{sem: make(chan struct{}, 4), perRepo: newRepoSemaphores(4), perClient: newClientSemaphores(1)}
	a, err := h.acquireGit(context.Background(), uuid.New(), "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.acquireGit(context.Background(), uuid.New(), "")
	if err != nil {
		t.Fatalf("a second address-less operation: %v", err)
	}
	a()
	b()
}
