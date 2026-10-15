package api

// The red-team job: a worker periodically rewrites the
// golden attack corpus with paraphrase/encoding/unicode/obfuscation
// mutators, scans the rewrites with the rule bundle in service, and stores
// a report of what the S3/S4 rules no longer catch. Report-only by
// construction — the job never touches a version, a scan run or a gate;
// platform staff read the reports to steer rule development.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/redteam"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/ruleset"
)

// jobRedTeam is the queue kind.
const jobRedTeam = "redteam.run"

// redTeamNewRulesetDelay is how long after a new ruleset's registration its
// red-team run waits: long enough for the worker role of the new build to
// be up in a rollout, short enough that the new rules are measured the same
// hour.
const redTeamNewRulesetDelay = 2 * time.Minute

// redTeamRulesetAttempts is the retry budget of a run queued for a new
// ruleset: a worker of the outgoing build hands it back until one of the
// new build takes it, as the catalogue sweep does. Twelve
// attempts at 2^n seconds keep it alive for about an hour of a rollout.
const redTeamRulesetAttempts = 12

// redTeamArgs are a run's arguments. The recurring chain carries none.
type redTeamArgs struct {
	// Ruleset is the semver a run queued by a new ruleset's registration
	// was queued to measure. A worker whose bundle is another version
	// hands the run back rather than measure the wrong rules.
	Ruleset string `json:"ruleset,omitempty"`
}

// registerRedTeam wires the handler and seeds the recurring job: one run
// waiting at a time, whatever the restarts (keepOneWaiting).
func (s *Server) registerRedTeam(q queue.Client) {
	if q == nil {
		return
	}
	q.Register(jobRedTeam, s.runRedTeam)
	if s.st == nil {
		return
	}
	if s.cfg.RedTeam.Interval <= 0 {
		s.log.Info("redteam: disabled (redTeam.interval is not positive)")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	seeded, err := keepOneWaiting(ctx, q, jobRedTeam, redTeamArgs{},
		queue.WithDelay(5*time.Minute), queue.WithMaxAttempts(2))
	if err != nil {
		s.log.WarnContext(ctx, "redteam: seed", "err", err)
		return
	}
	if seeded {
		s.log.InfoContext(ctx, "redteam: run scheduled", "in", (5 * time.Minute).String())
	}
}

// queueRedTeamForNewRuleset queues a red-team run shortly after this
// process registered a ruleset semver the registry had never seen, so the
// new rules are measured on the day they ship rather than at the chain's
// next turn. Registration is one insert across replicas, so one process
// queues it. The run is an ordinary one: finding the chain's next run
// waiting, it enqueues no successor.
func (s *Server) queueRedTeamForNewRuleset(ctx context.Context, semver string) {
	if s.jobs == nil || s.st == nil || s.cfg.RedTeam.Interval <= 0 {
		return
	}
	if _, err := s.jobs.Enqueue(ctx, jobRedTeam, "core", redTeamArgs{Ruleset: semver},
		queue.WithDelay(redTeamNewRulesetDelay), queue.WithMaxAttempts(redTeamRulesetAttempts)); err != nil {
		s.log.WarnContext(ctx, "redteam: could not queue a run for the new ruleset", "ruleset", semver, "err", err)
		return
	}
	s.log.InfoContext(ctx, "redteam: new ruleset registered; a run is queued", "ruleset", semver, "in", redTeamNewRulesetDelay.String())
}

// errRedTeamOtherRuleset hands a run queued for another ruleset back to the
// queue, for a worker of the build that carries it.
var errRedTeamOtherRuleset = errors.New("redteam: queued for another ruleset")

// runRedTeam executes one run and keeps the chain's next run waiting.
// Every failure is logged here, attempt by attempt: the queue logs only a
// job's last.
func (s *Server) runRedTeam(ctx context.Context, job queue.Job) error {
	defer s.scheduleNextRedTeam(ctx)
	var args redTeamArgs
	if len(job.Args) > 0 {
		if err := json.Unmarshal(job.Args, &args); err != nil {
			s.log.ErrorContext(ctx, "redteam: bad args; run dropped", "err", err)
			return nil
		}
	}
	err := s.redTeamOnce(ctx, args)
	switch {
	case errors.Is(err, errRedTeamOtherRuleset):
		s.log.InfoContext(ctx, "redteam: handed back", "err", err, "attempt", job.Attempt)
	case err != nil:
		s.log.ErrorContext(ctx, "redteam: run failed", "err", err, "attempt", job.Attempt)
	}
	return err
}

func (s *Server) redTeamOnce(ctx context.Context, args redTeamArgs) error {
	if s.st == nil || s.cfg.RedTeam.Interval <= 0 {
		return nil
	}
	bundle, err := ruleset.Load()
	if err != nil {
		return err
	}
	if args.Ruleset != "" && args.Ruleset != bundle.Version() {
		return fmt.Errorf("%w: run queued for %s, this worker has %s", errRedTeamOtherRuleset, args.Ruleset, bundle.Version())
	}
	// One report per bundle per interval across replicas: a fresh report
	// for this exact bundle means another worker already ran it.
	if latest, err := s.q().LatestRedTeamReportForBundle(ctx, bundle.Digest()); err == nil &&
		time.Since(latest.CreatedAt) < s.cfg.RedTeam.Interval/2 {
		s.log.InfoContext(ctx, "redteam: skipped, this bundle has a fresh report", "ruleset", bundle.Version(), "reportedAt", latest.CreatedAt)
		return nil
	}
	dir, err := redteam.FindCorpus(s.cfg.RedTeam.CorpusDir)
	if err != nil {
		s.log.WarnContext(ctx, "redteam: skipped", "err", err)
		return nil
	}
	rep, err := redteam.Run(bundle, dir)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	if _, err := s.q().InsertRedTeamReport(ctx, storegen.InsertRedTeamReportParams{
		ID: id, RulesetSemver: rep.RulesetSemver, BundleDigest: rep.BundleDigest,
		Fixtures: int32(rep.Fixtures), Cases: int32(rep.Cases), Evaded: int32(rep.Evaded), //nolint:gosec // counts are small
		Report: raw,
	}); err != nil {
		return err
	}
	s.log.InfoContext(ctx, "redteam: report stored", "ruleset", rep.RulesetSemver, "fixtures", rep.Fixtures, "cases", rep.Cases, "evaded", rep.Evaded)
	return nil
}

func (s *Server) scheduleNextRedTeam(ctx context.Context) {
	if s.jobs == nil || s.cfg.RedTeam.Interval <= 0 {
		return
	}
	if _, err := keepOneWaiting(ctx, s.jobs, jobRedTeam, redTeamArgs{},
		queue.WithDelay(s.cfg.RedTeam.Interval), queue.WithMaxAttempts(2)); err != nil {
		s.log.WarnContext(ctx, "redteam: reschedule", "err", err)
	}
}

// ListRedTeamReports implements GET /platform/redteam/reports (staff).
func (s *Server) ListRedTeamReports(w http.ResponseWriter, r *http.Request, params ListRedTeamReportsParams) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireStaff(w, r) {
		return
	}
	limit := clampLimit(params.Limit, 10, 50)
	rows, err := s.q().ListRedTeamReports(r.Context(), int32(limit)) //nolint:gosec // clamped
	if err != nil {
		s.log.ErrorContext(r.Context(), "list redteam reports", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]RedTeamReport, 0, len(rows))
	for _, row := range rows {
		var report map[string]any
		_ = json.Unmarshal(row.Report, &report)
		if report == nil {
			report = map[string]any{}
		}
		out = append(out, RedTeamReport{
			Id: row.ID, RulesetSemver: row.RulesetSemver, BundleDigest: row.BundleDigest,
			Fixtures: int(row.Fixtures), Cases: int(row.Cases), Evaded: int(row.Evaded),
			CreatedAt: row.CreatedAt, Report: report,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// RunRedTeamNow executes one red-team run immediately (the job body without
// the queue): the entry point for tests and for an operator who does not
// want to wait for the interval.
func (s *Server) RunRedTeamNow(ctx context.Context) error {
	return s.runRedTeam(ctx, queue.Job{Kind: jobRedTeam})
}
