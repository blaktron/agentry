package api_test

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/store"
	"github.com/blaktron/agentry/pkg/ruleset"
)

// The §17.5 red-team job (agentry#67) stores a report of the corpus
// rewrites the S3/S4 bundle no longer catches, a second run within the
// interval for the same bundle is a no-op, and platform staff read the
// reports; nothing on the publish path changes.
func TestRedTeamJobStoresReportStaffReads(t *testing.T) {
	var srvObj *api.Server
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.RedTeam.Interval = time.Hour
		c.RedTeam.CorpusDir = "../../testdata/attack-corpus"
	}, func(s *api.Server) { srvObj = s })

	ctx := context.Background()
	// The test database is shared across runs: a report left by an earlier
	// run would satisfy the per-bundle dedupe and skew the count below.
	if _, err := env.st.Pool().Exec(ctx, "DELETE FROM redteam_reports"); err != nil {
		t.Fatal(err)
	}
	if err := srvObj.RunRedTeamNow(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := srvObj.RunRedTeamNow(ctx); err != nil { // dedupe within the interval
		t.Fatalf("second run: %v", err)
	}

	staff := env.register("rt-staff")
	env.verifyEmail(staff)
	env.makePlatformStaff(t, staff)
	staffSess := env.login(staff)
	var reports []api.RedTeamReport
	env.doJSON(staffSess, http.MethodGet, "/api/v1/platform/redteam/reports?limit=5", nil, &reports, http.StatusOK)
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want exactly one (second run deduped)", len(reports))
	}
	r := reports[0]
	if r.Fixtures == 0 || r.Cases == 0 || r.RulesetSemver == "" || r.BundleDigest == "" {
		t.Fatalf("report = %+v", r)
	}
	if _, ok := r.Report["byMutator"]; !ok {
		t.Fatalf("report body lacks byMutator: %v", r.Report)
	}
	if evs, ok := r.Report["evasions"].([]any); !ok || len(evs) != r.Evaded {
		t.Fatalf("evasions %v vs evaded %d", r.Report["evasions"], r.Evaded)
	}

	plain := env.register("rt-plain")
	env.verifyEmail(plain)
	if res := env.do(env.login(plain), http.MethodGet, "/api/v1/platform/redteam/reports", nil); res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-staff: got %d want 403", res.StatusCode)
	}
}

// redTeamWaiting counts the red-team runs waiting in River's table.
func redTeamWaiting(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM river_job WHERE kind = 'redteam.run'
		   AND state IN ('available', 'scheduled', 'retryable', 'pending')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRedTeamKeepsOneRunWaiting is agentry#853: dev's seed had counted a
// row the retired pg driver left in its jobs table (dropped since
// agentry#244), so River was never seeded and no report was stored again.
// The seed counts River's own table, every start keeps exactly one run
// waiting, and a run keeps one successor waiting without stacking another.
func TestRedTeamKeepsOneRunWaiting(t *testing.T) {
	var srvObj *api.Server
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.RedTeam.Interval = time.Hour
		c.RedTeam.CorpusDir = "../../testdata/attack-corpus"
	}, func(s *api.Server) { srvObj = s })
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := env.st.Pool().Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`DELETE FROM river_job WHERE kind = 'redteam.run'`)
	t.Cleanup(func() {
		_, _ = env.st.Pool().Exec(context.Background(), `DELETE FROM river_job WHERE kind = 'redteam.run'`)
	})

	for start := 1; start <= 3; start++ {
		q := queue.NewRiverClient(env.st, nil)
		q.SetTestOnly(true)
		srvObj.RegisterQueueHandlers(q)
		if n := redTeamWaiting(t, env.st); n != 1 {
			t.Fatalf("after worker start %d: %d red-team runs waiting in river_job, want 1", start, n)
		}
	}

	// A run with its successor already waiting adds none...
	exec(`DELETE FROM redteam_reports`)
	if err := srvObj.RunRedTeamNow(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if n := redTeamWaiting(t, env.st); n != 1 {
		t.Fatalf("after a run: %d waiting, want still 1", n)
	}
	// ...and a run with none waiting enqueues one.
	exec(`DELETE FROM river_job WHERE kind = 'redteam.run'`)
	if err := srvObj.RunRedTeamNow(ctx); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if n := redTeamWaiting(t, env.st); n != 1 {
		t.Fatalf("after a run with no successor: %d waiting, want 1", n)
	}
}

// TestRedTeamRunForAnotherRulesetIsHandedBack: a run queued for a new
// ruleset that reaches a worker of another build is handed back for a worker
// that carries it, as the catalogue sweep is (agentry#805), and stores no
// report of the wrong rules; one queued for this worker's ruleset runs.
func TestRedTeamRunForAnotherRulesetIsHandedBack(t *testing.T) {
	var srvObj *api.Server
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.RedTeam.Interval = time.Hour
		c.RedTeam.CorpusDir = "../../testdata/attack-corpus"
	}, func(s *api.Server) { srvObj = s })
	ctx := context.Background()
	pool := env.st.Pool()
	for _, sql := range []string{`DELETE FROM river_job WHERE kind = 'redteam.run'`, `DELETE FROM redteam_reports`} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM river_job WHERE kind = 'redteam.run'`) })
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	srvObj.RegisterQueueHandlers(q)
	reports := func() int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM redteam_reports`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if _, err := q.Enqueue(ctx, "redteam.run", "core", map[string]string{"ruleset": "0.0.0-another-build"}); err != nil {
		t.Fatal(err)
	}
	q.Drain(ctx, "core")
	var lastErr string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(errors[array_length(errors, 1)]->>'error', '') FROM river_job
	      WHERE kind = 'redteam.run' AND args->>'ruleset' = '0.0.0-another-build'`).Scan(&lastErr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastErr, "queued for another ruleset") {
		t.Fatalf("the run for another ruleset was not handed back: last error %q", lastErr)
	}
	if n := reports(); n != 0 {
		t.Fatalf("%d reports stored for a run queued for another ruleset, want 0", n)
	}

	bundle, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(ctx, "redteam.run", "core", map[string]string{"ruleset": bundle.Version()}); err != nil {
		t.Fatal(err)
	}
	q.Drain(ctx, "core")
	if n := reports(); n != 1 {
		t.Fatalf("%d reports after the run queued for %s, want 1", n, bundle.Version())
	}
}

// TestANewRulesetQueuesARedTeamRun: the process that registers a ruleset
// semver the registry has never seen queues a red-team run of it a couple
// of minutes out, so a new ruleset is measured the day it ships; a restart
// on the same ruleset queues none. A database of its own, because only a
// first registration is new.
func TestANewRulesetQueuesARedTeamRun(t *testing.T) {
	st := isolatedStore(t)
	cfg := testConfig()
	cfg.RedTeam.Interval = time.Hour
	bundle, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	queued := func() (int, time.Time) {
		var n int
		var at time.Time
		if err := st.Pool().QueryRow(ctx, `SELECT count(*), COALESCE(max(scheduled_at), 'epoch') FROM river_job
		      WHERE kind = 'redteam.run' AND args->>'ruleset' = $1`, bundle.Version()).Scan(&n, &at); err != nil {
			t.Fatal(err)
		}
		return n, at
	}

	before := time.Now()
	_ = api.New(cfg, st, nil)
	n, at := queued()
	if n != 1 {
		t.Fatalf("%d red-team runs queued for the new ruleset %s, want 1", n, bundle.Version())
	}
	if at.Before(before.Add(time.Minute)) || at.After(time.Now().Add(3*time.Minute)) {
		t.Fatalf("the run is scheduled at %s, want about two minutes after the registration at %s", at, before)
	}
	_ = api.New(cfg, st, nil)
	if n, _ := queued(); n != 1 {
		t.Fatalf("a restart on the same ruleset queued another run: %d", n)
	}
}

// isolatedStore is a migrated database of the test's own, dropped after it.
func isolatedStore(t *testing.T) *store.Store {
	t.Helper()
	shared := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if shared == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set; skipping API integration test")
	}
	ctx := context.Background()
	admin, err := store.Connect(ctx, shared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	name := "agentry_api_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := admin.Pool().Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Pool().Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(shared)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	if err := store.Migrate(ctx, u.String()); err != nil {
		t.Fatalf("migrate %s: %v", name, err)
	}
	st, err := store.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}
