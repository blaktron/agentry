package extension

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
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

// roleConfig is a development configuration whose data directories are the
// test's own, for the role tests that need no database.
func roleConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	cfg.Git.DataDir = t.TempDir()
	cfg.Git.HooksDir = t.TempDir()
	cfg.Git.SSHAddr = ""
	return cfg
}

// roleConfigFile writes roleConfig's choices, with a database no one
// answers, to a file for the entry points that read one.
func roleConfigFile(t *testing.T) string {
	t.Helper()
	t.Setenv("AGENTRY_DATABASE_URL", "postgres://agentry:agentry@127.0.0.1:1/agentry?sslmode=disable")
	t.Setenv("AGENTRY_DATABASE_MIGRATE_ON_START", "false")
	path := filepath.Join(t.TempDir(), "agentry.yaml")
	body := "devMode: true\ngit:\n  dataDir: " + t.TempDir() + "\n  hooksDir: " + t.TempDir() + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The roles that act on the database or on the repositories do not start
// without one, and say so; a name that is no role is no role.
func TestRolesThatNeedADatabaseRefuseToStartWithoutOne(t *testing.T) {
	ctx := context.Background()
	cfg := roleConfig(t)
	log := slog.New(slog.DiscardHandler)
	for _, role := range []string{"git", "all"} {
		if _, _, err := buildHandler(ctx, cfg, nil, log, role, nil, nil); err == nil || !strings.Contains(err.Error(), "the git role requires a database") {
			t.Errorf("buildHandler(%s) without a database: %v, want the git role to require one", role, err)
		}
	}
	for _, role := range []string{"worker", "bogus", ""} {
		if _, _, err := buildHandler(ctx, cfg, nil, log, role, nil, nil); err == nil || !strings.Contains(err.Error(), "unknown http role "+`"`+role+`"`) {
			t.Errorf("buildHandler(%q): %v, want an unknown http role", role, err)
		}
	}
	if err := runWorker(ctx, cfg, nil, log, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "the worker role requires a database") {
		t.Errorf("runWorker without a database: %v", err)
	}
	if _, err := newWorkerQueue(ctx, cfg, api.New(cfg, nil, log), nil, log, nil, nil); err == nil || !strings.Contains(err.Error(), "requires archive storage") {
		t.Errorf("a worker without archive storage: %v", err)
	}
}

// The entry point starts the role it is asked for, or refuses it in the
// same words as the role itself; it never starts a name it does not know.
func TestRunWithRefusesAnUnknownRoleAndOneThatCannotRun(t *testing.T) {
	path := roleConfigFile(t)
	ended, stop := context.WithCancel(context.Background())
	stop()
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	for _, c := range []struct{ role, want string }{
		{"bogus", `unknown role "bogus"`},
		{"worker", "the worker role requires a database"},
		{"git", "the git role requires a database"},
		{"all", "the git role requires a database"},
	} {
		if err := RunWith(ended, path, c.role, Options{}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("RunWith(%s): %v, want %q", c.role, err, c.want)
		}
	}
}

// agentryd's commands: the four roles, the migration and the hook shim; only
// the worker takes --queues, and a bad list is refused before the role starts.
func TestRootCmdHasTheRolesAndOnlyTheWorkerTakesQueues(t *testing.T) {
	commands := map[string]bool{}
	for _, c := range rootCmd(nil).Commands() {
		commands[c.Name()] = true
		hasQueues := c.Flags().Lookup("queues") != nil
		switch c.Name() {
		case "worker":
			if !hasQueues {
				t.Error("the worker takes no --queues")
			}
		case "hook":
			if !c.Hidden {
				t.Error("the git hook shim is listed in help")
			}
			if len(c.Commands()) != 1 || c.Commands()[0].Name() != "pre-receive" {
				t.Errorf("the hook shim's commands = %v, want pre-receive", c.Commands())
			}
		default:
			if hasQueues {
				t.Errorf("%s takes --queues", c.Name())
			}
		}
	}
	for _, want := range []string{"api", "git", "worker", "all", "migrate", "hook"} {
		if !commands[want] {
			t.Errorf("no %s command", want)
		}
	}

	path := roleConfigFile(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"worker", "--queues", "judge"}, `"judge" is not a queue`},
		{[]string{"worker", "--queues", ","}, "--queues names no queue"},
		{[]string{"api", "--queues", "core"}, "unknown flag: --queues"},
		{[]string{"git", "--queues", "core"}, "unknown flag: --queues"},
		{[]string{"all", "--queues", "core"}, "unknown flag: --queues"},
	} {
		root := rootCmd(nil)
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs(append([]string{"--config", path}, c.args...))
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("agentryd %s: %v, want %q", strings.Join(c.args, " "), err, c.want)
		}
	}
}

// The api role without a database (limited dev mode) serves the extensions'
// routes under their names and lists them on /meta, and an extension whose
// job is on the api queue opens no queue there is no database to hold.
func TestAPIRoleWithoutADatabaseServesTheExtensions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := roleConfig(t)
	log := slog.New(slog.DiscardHandler)
	ext := jobber{jobs: []Job{{Kind: "probe.api", Queue: QueueAPI, Every: time.Hour, Handler: func(context.Context, queue.Job) error { return nil }}}}

	h, closeAll, err := buildHandler(ctx, cfg, nil, log, "api", nil, []Extension{ext})
	if err != nil {
		t.Fatalf("buildHandler(api) without a database: %v", err)
	}
	t.Cleanup(func() { _ = closeAll() })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x/noop/status", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("GET /api/v1/x/noop/status: %d %s, want the extension's 204", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/meta", nil))
	var meta struct {
		Extensions []string `json:"extensions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil || rec.Code != http.StatusOK || !slices.Equal(meta.Extensions, []string{"noop"}) {
		t.Errorf("GET /api/v1/meta: %d %s (%v), want extensions [noop]", rec.Code, rec.Body.String(), err)
	}

	// With no database there is no api queue to drain; with no api-queue job
	// there is none either. Either way the wait returns at once.
	for name, exts := range map[string][]Extension{"an api-queue job": {ext}, "no api-queue job": {noop{}}, "no extension": nil} {
		wait, err := apiQueue(ctx, cfg, nil, log, nil, exts)
		if err != nil || wait == nil {
			t.Fatalf("apiQueue with %s and no database: %v %v", name, wait != nil, err)
		}
		wait()
	}
}

// serveHTTP reports a listener that cannot start, and ends cleanly when its
// context does.
func TestServeHTTPReportsAListenFailureAndStopsWithItsContext(t *testing.T) {
	cfg := roleConfig(t)
	log := slog.New(slog.DiscardHandler)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = taken.Close() })
	cfg.HTTP.Addr = taken.Addr().String()
	bounded, giveUp := context.WithTimeout(context.Background(), 30*time.Second)
	defer giveUp()
	if err := serveHTTP(bounded, cfg, nil, log, "api", nil, nil); err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("serving on an address in use: %v, want it refused", err)
	}

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.HTTP.Addr = free.Addr().String()
	_ = free.Close()
	ended, stop := context.WithCancel(context.Background())
	stop()
	if err := serveHTTP(ended, cfg, nil, log, "api", nil, nil); err != nil {
		t.Errorf("serving until the context ends: %v, want a clean stop", err)
	}
}
