package gitsrv

import (
	"context"
	"encoding/json"
	"errors"
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
	if err := env.repos.GC(context.Background(), uuid.New()); err == nil {
		t.Fatal("gc on a missing repo must fail loudly")
	}
	reg := &captureQueue{handlers: map[string]queue.Handler{}}
	NewPushBookkeeper(env.st, nil, env.h.aud, nil).Register(reg)
	if err := reg.handlers["repo.gc"](context.Background(), queue.Job{Kind: "repo.gc", Args: []byte(`{"repoId":"` + agent.RepoID.String() + `"}`)}); err != nil {
		t.Fatalf("no-repos role must complete the job: %v", err)
	}
}
