package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
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
