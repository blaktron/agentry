package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/queue"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// jobAuditExport is the queue kind for an async audit export.
const jobAuditExport = "audit.export"

const auditExportBatch = 1000

type auditExportArgs struct {
	ExportID uuid.UUID `json:"export_id"`
}

func auditExportToAPI(row storegen.AuditExport) AuditExport {
	out := AuditExport{Id: row.ID, Status: AuditExportStatus(row.Status)}
	ec := int(row.EventCount)
	out.EventCount = &ec
	out.CreatedAt = &row.CreatedAt
	if row.ObjectKey != nil {
		out.DownloadPath = row.ObjectKey
	}
	if row.Error != nil {
		out.Error = row.Error
	}
	return out
}

// CreateAuditExport implements POST /orgs/{org}/audit/exports (admin+):
// it records an export job and enqueues it, returning 202 with the job id.
func (s *Server) CreateAuditExport(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgAuditRead, orgRow.ID) {
		return
	}
	if s.blobs == nil {
		problemUnavailable(w, r, "This deployment has no object storage configured, so audit exports cannot run.")
		return
	}
	var req CreateAuditExportJSONBody
	_ = readJSONOptional(r, &req)

	p := principalFrom(r.Context())
	id := newUUID()
	var created storegen.AuditExport
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		row, err := q.CreateAuditExport(r.Context(), storegen.CreateAuditExportParams{
			ID: id, OrgID: orgRow.ID, RequestedBy: &p.UserID, ActionFilter: req.Action,
		})
		if err != nil {
			return err
		}
		created = row
		e := auditEvent(r, audit.ActionAuditExport)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "audit_export", id
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "create audit export", "err", err)
		problemInternal(w, r)
		return
	}
	if s.jobs != nil {
		if _, err := s.jobs.Enqueue(r.Context(), jobAuditExport, "core", auditExportArgs{ExportID: id}); err != nil {
			s.log.ErrorContext(r.Context(), "enqueue audit export", "err", err)
		}
	}
	writeJSON(w, http.StatusAccepted, auditExportToAPI(created))
}

// GetAuditExport implements GET /orgs/{org}/audit/exports/{id} (admin+).
func (s *Server) GetAuditExport(w http.ResponseWriter, r *http.Request, org OrgHandle, id openapi_types.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgAuditRead, orgRow.ID) {
		return
	}
	row, err := s.q().GetAuditExport(r.Context(), storegen.GetAuditExportParams{ID: id, OrgID: orgRow.ID})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, auditExportToAPI(row))
}

// runAuditExport is the queue handler: it streams the org's audit slice to the
// blob store as NDJSON and records the object key. Idempotent enough
// for at-least-once delivery — a re-run overwrites the same content-keyed path.
func (s *Server) runAuditExport(ctx context.Context, job queue.Job) error {
	var args auditExportArgs
	if err := json.Unmarshal(job.Args, &args); err != nil {
		return nil
	}
	q := s.q()
	exp, err := q.GetAuditExportByID(ctx, args.ExportID)
	if err != nil {
		return nil // export row gone
	}
	if s.blobs == nil {
		_ = q.FailAuditExport(ctx, storegen.FailAuditExportParams{ID: exp.ID, Error: strptr("no object storage")})
		return nil
	}
	if err := q.SetAuditExportRunning(ctx, exp.ID); err != nil {
		return err
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	count := 0
	var afterTime *time.Time
	var afterID *uuid.UUID
	for {
		orgID := exp.OrgID
		rows, err := q.StreamOrgAuditEvents(ctx, storegen.StreamOrgAuditEventsParams{
			OrgID: &orgID, Action: exp.ActionFilter, AfterTime: afterTime, AfterID: afterID, Limit: auditExportBatch,
		})
		if err != nil {
			_ = q.FailAuditExport(ctx, storegen.FailAuditExportParams{ID: exp.ID, Error: strptr(err.Error())})
			return err
		}
		if len(rows) == 0 {
			break
		}
		for _, ev := range rows {
			if err := enc.Encode(auditEventNDJSON(ev)); err != nil {
				_ = q.FailAuditExport(ctx, storegen.FailAuditExportParams{ID: exp.ID, Error: strptr(err.Error())})
				return err
			}
			count++
		}
		last := rows[len(rows)-1]
		t, id := last.OccurredAt, last.ID
		afterTime, afterID = &t, &id
		if len(rows) < auditExportBatch {
			break
		}
	}

	key := fmt.Sprintf("audit-exports/%s/%s.ndjson", exp.OrgID.String(), exp.ID.String())
	if err := s.blobs.Put(ctx, key, bytes.NewReader(buf.Bytes())); err != nil {
		_ = q.FailAuditExport(ctx, storegen.FailAuditExportParams{ID: exp.ID, Error: strptr(err.Error())})
		return err
	}
	if err := q.CompleteAuditExport(ctx, storegen.CompleteAuditExportParams{
		ID: exp.ID, ObjectKey: &key, EventCount: int32(count),
	}); err != nil {
		return err
	}
	return nil
}

// auditEventNDJSON is the per-line export shape (NDJSON stream).
func auditEventNDJSON(ev storegen.AuditEvent) map[string]any {
	m := map[string]any{
		"id":          ev.ID.String(),
		"occurred_at": ev.OccurredAt.UTC().Format(time.RFC3339Nano),
		"actor_kind":  ev.ActorKind,
		"action":      ev.Action,
	}
	if ev.ActorID != nil {
		m["actor_id"] = ev.ActorID.String()
	}
	if ev.OrgID != nil {
		m["org_id"] = ev.OrgID.String()
	}
	if ev.TargetKind != nil {
		m["target_kind"] = *ev.TargetKind
	}
	if ev.TargetID != nil {
		m["target_id"] = ev.TargetID.String()
	}
	if len(ev.Detail) > 0 {
		m["detail"] = json.RawMessage(ev.Detail)
	}
	return m
}

func strptr(s string) *string { return &s }
