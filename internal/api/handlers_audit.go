package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

const (
	auditDefaultLimit = 50
	auditMaxLimit     = 200
)

// auditRow is the shape both audit listings share (org and platform).
type auditRow struct {
	ID          uuid.UUID
	OccurredAt  time.Time
	ActorKind   string
	Action      string
	ActorHandle *string
	TargetKind  *string
	TargetID    *uuid.UUID
	Detail      []byte
}

func auditRowToAPI(row auditRow) AuditEvent {
	e := AuditEvent{
		Id:         row.ID,
		OccurredAt: row.OccurredAt,
		ActorKind:  AuditEventActorKind(row.ActorKind),
		Action:     row.Action,
	}
	e.ActorHandle = row.ActorHandle
	e.TargetKind = row.TargetKind
	e.TargetId = row.TargetID
	if len(row.Detail) > 0 {
		var detail map[string]interface{}
		if err := json.Unmarshal(row.Detail, &detail); err == nil {
			e.Detail = &detail
		}
	}
	return e
}

// ListOrgAudit implements GET /orgs/{org}/audit (admin+, §12.6).
func (s *Server) ListOrgAudit(w http.ResponseWriter, r *http.Request, org OrgHandle, params ListOrgAuditParams) {
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

	limit := clampLimit(params.Limit, auditDefaultLimit, auditMaxLimit)
	before, beforeID, ok := cursorParams(w, r, params.Cursor)
	if !ok {
		return
	}
	qp := storegen.ListOrgAuditEventsParams{
		OrgID: &orgRow.ID, Limit: int32(limit), BeforeTime: before, BeforeID: beforeID,
	}
	if params.Action != nil && *params.Action != "" {
		qp.Action = params.Action
	}

	rows, err := s.q().ListOrgAuditEvents(r.Context(), qp)
	if err != nil {
		s.log.Error("list audit", "err", err)
		problemInternal(w, r)
		return
	}

	events := make([]AuditEvent, 0, len(rows))
	for _, row := range rows {
		events = append(events, auditRowToAPI(auditRow{
			ID: row.ID, OccurredAt: row.OccurredAt, ActorKind: row.ActorKind,
			Action: row.Action, ActorHandle: row.ActorHandle,
			TargetKind: row.TargetKind, TargetID: row.TargetID, Detail: row.Detail,
		}))
	}

	page := AuditPage{Events: events}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		cur := encodeCursor(last.OccurredAt, last.ID)
		page.NextCursor = &cur
		setNextLink(w, r, cur)
	}
	writeJSON(w, http.StatusOK, page)
}

// ListPlatformAudit implements GET /platform/audit (§12.6): platform staff
// see every org's slice. §12.6 requires that this access is itself audited,
// so each call writes one audit.platform_read event naming the filters used —
// reading everyone's log is exactly the action an auditor wants a record of.
func (s *Server) ListPlatformAudit(w http.ResponseWriter, r *http.Request, params ListPlatformAuditParams) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireStaff(w, r) {
		return
	}
	limit := clampLimit(params.Limit, auditDefaultLimit, auditMaxLimit)
	before, beforeID, ok := cursorParams(w, r, params.Cursor)
	if !ok {
		return
	}
	qp := storegen.ListPlatformAuditEventsParams{
		Limit: int32(limit), BeforeTime: before, BeforeID: beforeID,
	}
	if params.Action != nil && *params.Action != "" {
		qp.Action = params.Action
	}
	detail := map[string]any{"limit": limit}
	if params.Org != nil && *params.Org != "" {
		orgRow, ok := s.orgOrNotFound(w, r, *params.Org)
		if !ok {
			return
		}
		qp.OrgID = &orgRow.ID
		detail["org"] = orgRow.Handle
	}
	if params.Action != nil && *params.Action != "" {
		detail["action"] = *params.Action
	}

	rows, err := s.q().ListPlatformAuditEvents(r.Context(), qp)
	if err != nil {
		s.log.Error("list platform audit", "err", err)
		problemInternal(w, r)
		return
	}

	// Audit the staff read BEFORE responding: a read we cannot record is a
	// read we do not serve (§12.6 "platform staff see all — access itself
	// audited").
	e := auditEvent(r, audit.ActionAuditPlatformRead)
	e.TargetKind = "audit_events"
	e.Detail = detail
	if err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		return s.auditW.Write(r.Context(), q, e)
	}); err != nil {
		s.log.Error("audit platform read", "err", err)
		problemInternal(w, r)
		return
	}

	events := make([]AuditEvent, 0, len(rows))
	for _, row := range rows {
		events = append(events, auditRowToAPI(auditRow{
			ID: row.ID, OccurredAt: row.OccurredAt, ActorKind: row.ActorKind,
			Action: row.Action, ActorHandle: row.ActorHandle,
			TargetKind: row.TargetKind, TargetID: row.TargetID, Detail: row.Detail,
		}))
	}
	page := AuditPage{Events: events}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		cur := encodeCursor(last.OccurredAt, last.ID)
		page.NextCursor = &cur
		setNextLink(w, r, cur)
	}
	writeJSON(w, http.StatusOK, page)
}
