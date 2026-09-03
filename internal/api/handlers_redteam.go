package api

// The §17.5 red-team job (agentry#67): a worker periodically rewrites the
// golden attack corpus with paraphrase/encoding/unicode/obfuscation
// mutators, scans the rewrites with the rule bundle in service, and stores
// a report of what the S3/S4 rules no longer catch. Report-only by
// construction — the job never touches a version, a scan run or a gate;
// platform staff read the reports to steer rule development.

import (
	"context"
	"encoding/json"
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

// registerRedTeam wires the handler and seeds the recurring job (same
// shape as audit retention: the job reschedules itself, seeding is guarded
// by the pending count so a worker restart cannot stack duplicates).
func (s *Server) registerRedTeam(q queue.Client) {
	if q == nil {
		return
	}
	q.Register(jobRedTeam, s.runRedTeam)
	if s.st == nil || s.cfg.RedTeam.Interval <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pending, err := s.q().CountPendingJobsOfKind(ctx, jobRedTeam)
	if err != nil {
		s.log.Warn("redteam: could not check for a pending run", "err", err)
		return
	}
	if pending > 0 {
		return
	}
	if _, err := q.Enqueue(ctx, jobRedTeam, "core", struct{}{},
		queue.WithDelay(5*time.Minute), queue.WithMaxAttempts(2)); err != nil {
		s.log.Warn("redteam: seed enqueue", "err", err)
	}
}

// runRedTeam executes one run and schedules the next.
func (s *Server) runRedTeam(ctx context.Context, _ queue.Job) error {
	defer s.scheduleNextRedTeam(ctx)
	if s.st == nil || s.cfg.RedTeam.Interval <= 0 {
		return nil
	}
	bundle, err := ruleset.Load()
	if err != nil {
		return err
	}
	// One report per bundle per interval across replicas: a fresh report
	// for this exact bundle means another worker already ran it.
	if latest, err := s.q().LatestRedTeamReportForBundle(ctx, bundle.Digest()); err == nil &&
		time.Since(latest.CreatedAt) < s.cfg.RedTeam.Interval/2 {
		return nil
	}
	dir, err := redteam.FindCorpus(s.cfg.RedTeam.CorpusDir)
	if err != nil {
		s.log.Warn("redteam: skipped", "err", err)
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
	s.log.Info("redteam: report stored", "ruleset", rep.RulesetSemver, "fixtures", rep.Fixtures, "cases", rep.Cases, "evaded", rep.Evaded)
	return nil
}

func (s *Server) scheduleNextRedTeam(ctx context.Context) {
	if s.jobs == nil || s.cfg.RedTeam.Interval <= 0 {
		return
	}
	if _, err := s.jobs.Enqueue(ctx, jobRedTeam, "core", struct{}{},
		queue.WithDelay(s.cfg.RedTeam.Interval), queue.WithMaxAttempts(2)); err != nil {
		s.log.Warn("redteam: reschedule", "err", err)
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
		s.log.Error("list redteam reports", "err", err)
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
