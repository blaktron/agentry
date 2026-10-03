package api

// Hot-table audit retention (§4.3: "400 days hot on SaaS, then S3 archive
// (already streamed there continuously, §12.6); self-host retention
// configurable").
//
// Pruning DROPS whole monthly partitions rather than deleting rows. Two
// reasons: the append-only trigger from migration 00002 refuses row deletes
// outright, and dropping a partition is a catalog operation rather than a
// 400-day table scan. The consequence is that the effective retention is
// rounded UP to a month boundary — a partition is dropped only once ALL of
// its rows are older than the cutoff, so nothing inside the window is ever
// lost to make the arithmetic tidy.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/queue"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// jobAuditPrune is the queue kind for the retention sweep.
const jobAuditPrune = "audit.prune"

// auditPruneInterval is how often the sweep reschedules itself. Daily: the
// unit of work is a whole month's partition, so anything finer is wasted.
const auditPruneInterval = 24 * time.Hour

type auditPruneArgs struct {
	// RetentionDays is captured at enqueue time so a running deployment's
	// history of what it pruned, and why, is legible in the jobs table.
	RetentionDays int `json:"retention_days"`
}

// registerAuditRetention wires the retention handler onto a queue worker and
// seeds the recurring job. Called from Server.RegisterQueueHandlers.
//
// The job reschedules itself rather than relying on an external scheduler
// (there is none in v1), and the seed and the reschedule both keep one run
// waiting (keepOneWaiting), so a worker restart cannot stack duplicates.
func (s *Server) registerAuditRetention(q queue.Client) {
	if q == nil {
		return
	}
	q.Register(jobAuditPrune, s.runAuditPrune)
	if s.st == nil || s.cfg.Audit.RetentionDays <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := keepOneWaiting(ctx, q, jobAuditPrune,
		auditPruneArgs{RetentionDays: s.cfg.Audit.RetentionDays},
		queue.WithDelay(time.Hour), queue.WithMaxAttempts(3)); err != nil {
		s.log.WarnContext(ctx, "audit retention: seed", "err", err)
	}
}

// runAuditPrune drops audit partitions entirely older than the retention
// window, then schedules the next sweep.
func (s *Server) runAuditPrune(ctx context.Context, job queue.Job) error {
	// Reschedule first: a sweep that errors must still leave a successor, or
	// retention silently stops after one bad day.
	defer s.scheduleNextAuditPrune(ctx)

	days := s.cfg.Audit.RetentionDays
	var args auditPruneArgs
	if err := json.Unmarshal(job.Args, &args); err == nil && args.RetentionDays > 0 {
		days = args.RetentionDays
	}
	if s.st == nil || days <= 0 {
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	dropped, err := s.q().PruneAuditPartitions(ctx, pgtype.Date{Time: cutoff, Valid: true})
	if err != nil {
		return err
	}
	if dropped == 0 {
		return nil
	}
	s.log.InfoContext(ctx, "audit retention: partitions dropped", "count", dropped, "retention_days", days)
	// The prune is itself an auditable act on the audit log (§12.6).
	return s.st.WithTx(ctx, func(q *storegen.Queries) error {
		return s.auditW.Write(ctx, q, audit.Event{
			Action: audit.ActionAuditPrune, ActorKind: audit.ActorSystem,
			TargetKind: "audit_events",
			Detail: map[string]any{
				"partitionsDropped": dropped,
				"retentionDays":     days,
				"cutoff":            cutoff.Format(time.RFC3339),
			},
		})
	})
}

func (s *Server) scheduleNextAuditPrune(ctx context.Context) {
	if s.jobs == nil || s.cfg.Audit.RetentionDays <= 0 {
		return
	}
	if _, err := keepOneWaiting(ctx, s.jobs, jobAuditPrune,
		auditPruneArgs{RetentionDays: s.cfg.Audit.RetentionDays},
		queue.WithDelay(auditPruneInterval), queue.WithMaxAttempts(3)); err != nil {
		s.log.WarnContext(ctx, "audit retention: reschedule", "err", err)
	}
}
