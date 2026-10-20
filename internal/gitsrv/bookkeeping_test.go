package gitsrv

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/queue"
)

// captureQueue records Enqueue calls; Register/Work are unused here.
type captureQueue struct {
	kind     string
	queue    string
	args     []byte
	fail     bool
	calls    int
	kinds    map[string]int
	handlers map[string]queue.Handler
}

func (c *captureQueue) Enqueue(_ context.Context, kind, queueName string, args any, _ ...queue.EnqueueOption) (uuid.UUID, error) {
	c.calls++
	if c.fail {
		return uuid.Nil, errors.New("queue down")
	}
	if c.kinds == nil {
		c.kinds = map[string]int{}
	}
	c.kinds[kind]++
	if kind == KindRepoPushed {
		c.kind, c.queue = kind, queueName
		c.args, _ = json.Marshal(args)
	}
	return uuid.New(), nil
}
func (c *captureQueue) Register(kind string, h queue.Handler) {
	if c.handlers != nil {
		c.handlers[kind] = h
	}
}

func (*captureQueue) CountWaiting(context.Context, string) (int64, error) { return 0, nil }
func (c *captureQueue) Work(context.Context, ...string) error             { return nil }

// TestPushBookkeepingRidesTheQueue: with a queue wired, afterReceive
// enqueues one repo.pushed job carrying everything the bookkeeping needs
// and does NOT bookkeep inline; running the job does. When the enqueue
// itself fails, the inline path still runs — durability is best effort
// on top of correctness, never instead of it.
func TestPushBookkeepingRidesTheQueue(t *testing.T) {
	env := newBookkeepingEnv(t)
	principal := &auth.Principal{UserID: env.owner, Via: "pat"}
	agent, commit := env.seedAgent("queued")
	q := &captureQueue{}
	env.h.queue = q

	env.h.afterReceive(context.Background(), agent, principal, pktCommands(zeroOID+" "+commit+" refs/heads/main"))
	if q.kinds[KindRepoPushed] != 1 || q.kind != KindRepoPushed || q.queue != "core" {
		t.Fatalf("enqueue: kinds=%v kind=%q queue=%q", q.kinds, q.kind, q.queue)
	}
	if r := env.repo(agent.RepoID); r.LastPushAt != nil {
		t.Fatalf("bookkeeping must not run inline when enqueued: %+v", r)
	}
	if n := env.pushAudits(agent.ID); n != 0 {
		t.Fatalf("audit rows before the job ran = %d", n)
	}
	var args RepoPushedArgs
	if err := json.Unmarshal(q.args, &args); err != nil {
		t.Fatal(err)
	}
	if args.AgentID != agent.ID || args.RepoID != agent.RepoID || args.ActorID != principal.UserID || len(args.Refs) == 0 {
		t.Fatalf("args: %+v", args)
	}

	bk := NewPushBookkeeper(env.st, env.repos, env.h.aud, nil)
	if err := bk.Run(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	if r := env.repo(agent.RepoID); r.LastPushAt == nil || r.SizeBytes == 0 {
		t.Fatalf("job must bookkeep: %+v", r)
	}
	if n := env.pushAudits(agent.ID); n != 1 {
		t.Fatalf("audit rows after the job = %d, want 1", n)
	}
	if args.OrgID != uuid.Nil {
		t.Fatalf("a user's agent put organization %v in the job", args.OrgID)
	}
	// The audit row names the pusher as a token, the agent as the target,
	// the refs, and no organization.
	row := env.latestPushAudit(agent.ID)
	if row.actor == nil || *row.actor != principal.UserID.String() || row.actorKind != "pat" ||
		row.targetKind == nil || *row.targetKind != "agent" || row.org != nil || row.refs != `["refs/heads/main"]` {
		t.Fatalf("audit row = %+v, want actor %v (pat) on target kind agent, no organization, refs [refs/heads/main]", row, principal.UserID)
	}

	// Enqueue failure: inline fallback.
	agent2, commit2 := env.seedAgent("fallback")
	env.h.queue = &captureQueue{fail: true}
	env.h.afterReceive(context.Background(), agent2, principal, pktCommands(zeroOID+" "+commit2+" refs/heads/main"))
	if r := env.repo(agent2.RepoID); r.LastPushAt == nil {
		t.Fatalf("enqueue failure must fall back to inline bookkeeping: %+v", r)
	}
	if n := env.pushAudits(agent2.ID); n != 1 {
		t.Fatalf("fallback audit rows = %d, want 1", n)
	}

	// A role without repository storage still advances last_push_at and
	// audits; the size stays untouched.
	agent3, _ := env.seedAgent("norepos")
	noRepos := NewPushBookkeeper(env.st, nil, env.h.aud, nil)
	if err := noRepos.Run(context.Background(), RepoPushedArgs{AgentID: agent3.ID, RepoID: agent3.RepoID, ActorID: principal.UserID, Refs: []string{"refs/heads/main"}}); err != nil {
		t.Fatal(err)
	}
	if r := env.repo(agent3.RepoID); r.LastPushAt == nil || r.SizeBytes != 0 {
		t.Fatalf("no-repos bookkeeping: %+v", r)
	}

	// An agent in an organization's namespace carries the organization into
	// the job, and the job into the audit row.
	orgID := uuid.New()
	orgAgent, orgCommit := env.seedAgent("orgpush")
	orgAgent.NamespaceKind, orgAgent.NamespaceID = "org", orgID
	orgQueue := &captureQueue{}
	env.h.queue = orgQueue
	env.h.afterReceive(context.Background(), orgAgent, principal, pktCommands(zeroOID+" "+orgCommit+" refs/heads/main"))
	var orgArgs RepoPushedArgs
	if err := json.Unmarshal(orgQueue.args, &orgArgs); err != nil {
		t.Fatal(err)
	}
	if orgArgs.OrgID != orgID {
		t.Fatalf("job organization = %v, want %v", orgArgs.OrgID, orgID)
	}
	if err := bk.Run(context.Background(), orgArgs); err != nil {
		t.Fatal(err)
	}
	if row := env.latestPushAudit(orgAgent.ID); row.org == nil || *row.org != orgID.String() {
		t.Fatalf("audit row organization = %v, want %v", row.org, orgID)
	}

	// The registered handler decodes the job and runs the bookkeeping; a
	// payload that is not the job's arguments fails it, so the queue sees
	// the error instead of a push recorded against nothing.
	handlers := &captureQueue{handlers: map[string]queue.Handler{}}
	bk.Register(handlers)
	good, err := json.Marshal(RepoPushedArgs{AgentID: agent.ID, RepoID: agent.RepoID, ActorID: principal.UserID, Refs: []string{"refs/heads/main"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlers.handlers[KindRepoPushed](context.Background(), queue.Job{Kind: KindRepoPushed, Args: good}); err != nil {
		t.Fatalf("a repo.pushed job: %v", err)
	}
	if n := env.pushAudits(agent.ID); n != 2 {
		t.Fatalf("audit rows after the registered handler ran = %d, want 2", n)
	}
	if err := handlers.handlers[KindRepoPushed](context.Background(), queue.Job{Kind: KindRepoPushed, Args: []byte(`{"agentId":`)}); err == nil || !strings.HasPrefix(err.Error(), "repo.pushed: bad args: ") {
		t.Fatalf("a repo.pushed job with a truncated payload: %v, want a bad-args error", err)
	}
}

// TestRepoGCJob: the push handler enqueues a delayed repo.gc beside
// repo.pushed, and the job runs git's auto housekeeping on the bare repo.
// A role without repositories completes the job quietly.
func TestRepoGCJob(t *testing.T) {
	env := newBookkeepingEnv(t)
	principal := &auth.Principal{UserID: env.owner, Via: "pat"}
	agent, commit := env.seedAgent("gc")
	q := &captureQueue{}
	env.h.queue = q
	env.h.afterReceive(context.Background(), agent, principal, pktCommands(zeroOID+" "+commit+" refs/heads/main"))
	if q.kinds["repo.gc"] != 1 || q.kinds["repo.pushed"] != 1 {
		t.Fatalf("expected one repo.pushed and one repo.gc job, got %v", q.kinds)
	}
	if err := env.repos.GC(context.Background(), agent.RepoID); err != nil {
		t.Fatalf("gc: %v", err)
	}
	// Auto housekeeping is a no-op below git's thresholds: the few loose
	// objects of a fresh push are not packed.
	if packs, _ := filepath.Glob(filepath.Join(env.repos.Path(agent.RepoID), "objects", "pack", "*.pack")); len(packs) != 0 {
		t.Fatalf("gc packed a repository below git's thresholds: %v", packs)
	}
	if err := env.repos.GC(context.Background(), uuid.New()); err == nil {
		t.Fatal("gc on a missing repo must fail loudly")
	}

	// What it runs, and what it reports when git fails: the first line git
	// said when it said anything, the exit status otherwise.
	t.Run("gc runs git gc --auto --quiet in the repository", func(t *testing.T) {
		dir := t.TempDir()
		argv := filepath.Join(dir, "argv")
		fake := fakeGit(t, dir, "printf '%s\\n' \"$@\" > "+argv+"\n")
		store := &RepoStore{dataDir: env.repos.dataDir, gitBin: fake}
		if err := store.GC(context.Background(), agent.RepoID); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(argv)
		if err != nil {
			t.Fatal(err)
		}
		if want := "-C\n" + env.repos.Path(agent.RepoID) + "\ngc\n--auto\n--quiet\n"; string(got) != want {
			t.Fatalf("git was run with %q, want %q", got, want)
		}
	})
	t.Run("a failed gc reports git's first line of complaint", func(t *testing.T) {
		store := &RepoStore{dataDir: env.repos.dataDir, gitBin: fakeGit(t, t.TempDir(), "echo 'fatal: first complaint' >&2\necho 'hint: second line' >&2\nexit 1\n")}
		want := "gitsrv: gc " + agent.RepoID.String() + ": fatal: first complaint"
		if err := store.GC(context.Background(), agent.RepoID); err == nil || err.Error() != want {
			t.Fatalf("gc error = %v, want %q", err, want)
		}
	})
	t.Run("a failed gc that said nothing reports the exit status", func(t *testing.T) {
		store := &RepoStore{dataDir: env.repos.dataDir, gitBin: fakeGit(t, t.TempDir(), "exit 3\n")}
		want := "gitsrv: gc " + agent.RepoID.String() + ": exit status 3"
		err := store.GC(context.Background(), agent.RepoID)
		var exit *exec.ExitError
		if err == nil || err.Error() != want || !errors.As(err, &exit) {
			t.Fatalf("gc error = %v, want %q wrapping the exit error", err, want)
		}
	})
	reg := &captureQueue{handlers: map[string]queue.Handler{}}
	NewPushBookkeeper(env.st, nil, env.h.aud, nil).Register(reg)
	if err := reg.handlers["repo.gc"](context.Background(), queue.Job{Kind: "repo.gc", Args: []byte(`{"repoId":"` + agent.RepoID.String() + `"}`)}); err != nil {
		t.Fatalf("no-repos role must complete the job: %v", err)
	}

	// A role with repositories runs the housekeeping for the repository the
	// job names, and fails a payload that names none.
	withRepos := &captureQueue{handlers: map[string]queue.Handler{}}
	NewPushBookkeeper(env.st, env.repos, env.h.aud, nil).Register(withRepos)
	gcJob := withRepos.handlers["repo.gc"]
	if err := gcJob(context.Background(), queue.Job{Kind: "repo.gc", Args: []byte(`{"repoId":"` + agent.RepoID.String() + `"}`)}); err != nil {
		t.Fatalf("gc job: %v", err)
	}
	if err := gcJob(context.Background(), queue.Job{Kind: "repo.gc", Args: []byte(`{"repoId":"` + uuid.NewString() + `"}`)}); err == nil {
		t.Fatal("a gc job for a repository that is not there must fail")
	}
	if err := gcJob(context.Background(), queue.Job{Kind: "repo.gc", Args: []byte(`{"repoId":`)}); err == nil || !strings.HasPrefix(err.Error(), "repo.gc: bad args: ") {
		t.Fatalf("a gc job with a truncated payload: %v, want a bad-args error", err)
	}

	// The job is scheduled for a quiet moment, not at once, and the push's
	// own bookkeeping job is not delayed.
	t.Run("the gc job waits for the burst to end", func(t *testing.T) {
		delayed, delayedCommit := env.seedAgent("gcdelay")
		env.h.queue = queue.NewRiverClient(env.st, nil)
		t.Cleanup(func() {
			_, _ = env.st.Pool().Exec(context.Background(), `DELETE FROM river_job WHERE args->>'repoId' = $1`, delayed.RepoID.String())
		})
		env.h.afterReceive(context.Background(), delayed, principal, pktCommands(zeroOID+" "+delayedCommit+" refs/heads/main"))
		rows, err := env.st.Pool().Query(context.Background(),
			`SELECT kind, extract(epoch FROM scheduled_at - now())::float8 FROM river_job WHERE args->>'repoId' = $1`, delayed.RepoID.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		waits := map[string]float64{}
		for rows.Next() {
			var kind string
			var seconds float64
			if err := rows.Scan(&kind, &seconds); err != nil {
				t.Fatal(err)
			}
			waits[kind] = seconds
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if pushed, ok := waits["repo.pushed"]; !ok || pushed > 60 {
			t.Fatalf("repo.pushed is scheduled %.0f seconds out (queued: %v), want it due now", pushed, ok)
		}
		if gc, ok := waits["repo.gc"]; !ok || gc < 600 || gc > 1800 {
			t.Fatalf("repo.gc is scheduled %.0f seconds out (queued: %v), want about fifteen minutes", gc, ok)
		}
	})
}

// fakeGit writes an executable shell script standing in for the git binary.
func fakeGit(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "git")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil { //nolint:gosec // an executable test double
		t.Fatal(err)
	}
	return path
}
