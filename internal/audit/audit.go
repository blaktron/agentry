package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// ActorKind mirrors audit_events.actor_kind.
type ActorKind string

// Actor kinds (§4.2 audit_events).
const (
	ActorUser   ActorKind = "user"
	ActorPAT    ActorKind = "pat"
	ActorSCIM   ActorKind = "scim"
	ActorSystem ActorKind = "system"
)

// Event is one audit record. OrgID/Target are optional; Detail must not
// contain secrets or tokens (§16.2 rule — reviewers grep for violations).
type Event struct {
	Actor      uuid.UUID // zero for system events
	ActorKind  ActorKind
	OrgID      uuid.UUID // zero when not org-scoped
	Action     Action
	TargetKind string
	TargetID   uuid.UUID
	IP         netip.Addr
	UserAgent  string
	Detail     map[string]any
}

// Writer persists events. It is safe for concurrent use. The query handle is
// passed per call so events join the caller's transaction: an audited
// mutation and its audit row commit or roll back together.
type Writer struct {
	log *slog.Logger

	mu            sync.Mutex
	ensuredMonths map[string]struct{}
	stream        Stream
}

// NewWriter builds a Writer. Archiving is off until SetStream is called.
func NewWriter(log *slog.Logger) *Writer {
	if log == nil {
		log = slog.Default()
	}
	return &Writer{log: log, ensuredMonths: map[string]struct{}{}, stream: NopStream{}}
}

// SetStream attaches the §12.6 NDJSON archive sink. Called once at startup.
func (w *Writer) SetStream(s Stream) {
	if s == nil {
		s = NopStream{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stream = s
}

// Stream returns the attached archive sink (tests, shutdown flush).
func (w *Writer) Stream() Stream {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stream
}

// Write records the event via q (pass the transaction-bound queries when the
// mutation runs in a tx). Failures are returned AND logged: callers in
// request paths must fail the mutation if the audit write fails (append-only
// log is a §1.6 trust property, not telemetry).
func (w *Writer) Write(ctx context.Context, q *storegen.Queries, e Event) error {
	if !Registered(e.Action) {
		return fmt.Errorf("audit: unregistered action %q", e.Action)
	}
	now := time.Now().UTC()
	if err := w.ensureMonth(ctx, q, now); err != nil {
		return err
	}

	detail, err := json.Marshal(e.Detail)
	if err != nil {
		return fmt.Errorf("audit: detail marshal: %w", err)
	}
	if e.Detail == nil {
		detail = []byte("{}")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("audit: id: %w", err)
	}
	params := storegen.InsertAuditEventParams{
		ID:         id,
		OccurredAt: now,
		ActorKind:  string(e.ActorKind),
		Action:     string(e.Action),
		Detail:     detail,
	}
	if e.Actor != uuid.Nil {
		params.ActorID = &e.Actor
	}
	if e.OrgID != uuid.Nil {
		params.OrgID = &e.OrgID
	}
	if e.TargetKind != "" {
		params.TargetKind = &e.TargetKind
	}
	if e.TargetID != uuid.Nil {
		params.TargetID = &e.TargetID
	}
	if e.IP.IsValid() {
		params.Ip = &e.IP
	}
	if e.UserAgent != "" {
		ua := truncate(e.UserAgent, 512)
		params.UserAgent = &ua
	}

	if err := q.InsertAuditEvent(ctx, params); err != nil {
		w.log.Error("audit write failed", "action", e.Action, "err", err)
		return fmt.Errorf("audit: insert: %w", err)
	}

	// Archive copy (§12.6). Queued only after the row is written, so the
	// stream never gets an event the database refused. Best-effort by
	// design — see the stream.go package comment.
	w.Stream().Append(Record{
		ID: id, OccurredAt: now, ActorID: params.ActorID, ActorKind: string(e.ActorKind),
		OrgID: params.OrgID, Action: string(e.Action), TargetKind: e.TargetKind,
		TargetID: params.TargetID, Detail: detail,
	})
	return nil
}

// ensureMonth creates the current month's partition once per process-month.
func (w *Writer) ensureMonth(ctx context.Context, q *storegen.Queries, t time.Time) error {
	key := t.Format("200601")
	w.mu.Lock()
	_, done := w.ensuredMonths[key]
	w.mu.Unlock()
	if done {
		return nil
	}
	if err := q.EnsureAuditPartition(ctx, pgtype.Date{Time: t, Valid: true}); err != nil {
		return fmt.Errorf("audit: ensure partition: %w", err)
	}
	w.mu.Lock()
	w.ensuredMonths[key] = struct{}{}
	w.mu.Unlock()
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
