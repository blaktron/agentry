package extension

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/store"
)

// jobber is an extension with the jobs it is given.
type jobber struct {
	noop
	jobs []Job
}

func (j jobber) Jobs() []Job { return j.jobs }

func kinds(jobs []Job) []string {
	var out []string
	for _, j := range jobs {
		out = append(out, j.Kind)
	}
	return out
}

// The api role takes the api queue's jobs and nothing else; the worker
// takes every other queue's, an unnamed queue included.
func TestExtensionJobsSplitsTheAPIQueue(t *testing.T) {
	exts := []Extension{
		jobber{jobs: []Job{{Kind: "a.core", Queue: "core"}, {Kind: "a.api", Queue: QueueAPI}}},
		jobber{jobs: []Job{{Kind: "b.sandbox", Queue: "sandbox"}, {Kind: "b.unnamed"}, {Kind: "b.api", Queue: QueueAPI}}},
	}
	if got, want := kinds(extensionJobs(exts, true)), []string{"a.api", "b.api"}; !slices.Equal(got, want) {
		t.Errorf("api role's jobs = %v, want %v", got, want)
	}
	if got, want := kinds(extensionJobs(exts, false)), []string{"a.core", "b.sandbox", "b.unnamed"}; !slices.Equal(got, want) {
		t.Errorf("worker's jobs = %v, want %v", got, want)
	}
	if got := extensionJobs([]Extension{noop{}}, true); len(got) != 0 {
		t.Errorf("an extension with no jobs gives the api role %v", got)
	}
}

// The api role runs an extension's api-queue job, enqueued at start by
// its period, and enqueues none of the worker's: a periodic core-queue
// job stays the worker's to enqueue.
func TestAPIRoleDrainsTheAPIQueue(t *testing.T) {
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := store.Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := store.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(st.Close)

	suffix := uuid.NewString()
	apiKind, coreKind := "test.api_job."+suffix, "test.core_job."+suffix
	ran := make(chan string, 4)
	ext := jobber{jobs: []Job{
		{Kind: apiKind, Queue: QueueAPI, Every: time.Hour, Handler: func(_ context.Context, j queue.Job) error {
			ran <- j.Queue
			return nil
		}},
		{Kind: coreKind, Queue: "core", Every: time.Hour, Handler: func(context.Context, queue.Job) error {
			ran <- "core"
			return nil
		}},
	}}

	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	mx, err := metrics.New(ctx, metrics.Config{ServiceName: "agentryd", Role: "api", Env: cfg.Env})
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	_, closeAll, err := buildHandler(ctx, cfg, st, slog.New(slog.DiscardHandler), "api", mx, []Extension{ext})
	if err != nil {
		t.Fatalf("buildHandler(api): %v", err)
	}
	t.Cleanup(func() { _ = closeAll() })
	t.Cleanup(cancel) // runs first: the queue stops, then closeAll returns

	select {
	case q := <-ran:
		if q != QueueAPI {
			t.Fatalf("the api role ran a job from the %q queue", q)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the api role never ran its api-queue job")
	}
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1`, coreKind).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("the api role enqueued %s; that is the worker's", coreKind)
	}
}
