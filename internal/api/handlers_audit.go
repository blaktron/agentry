package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

const (
	auditDefaultLimit = 50
	auditMaxLimit     = 200
)

// auditCursor encodes/decodes the opaque (occurred_at, id) keyset cursor.
func encodeAuditCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeAuditCursor(s string) (time.Time, uuid.UUID, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, false
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return t, id, true
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

	limit := auditDefaultLimit
	if params.Limit != nil {
		limit = *params.Limit
		if limit < 1 || limit > auditMaxLimit {
			problemValidation(w, r, "limit must be 1-200")
			return
		}
	}

	qp := storegen.ListOrgAuditEventsParams{OrgID: &orgRow.ID, Limit: int32(limit)}
	if params.Action != nil && *params.Action != "" {
		qp.Action = params.Action
	}
	if params.Cursor != nil && *params.Cursor != "" {
		t, id, ok := decodeAuditCursor(*params.Cursor)
		if !ok {
			problemValidation(w, r, "invalid cursor")
			return
		}
		qp.BeforeTime = &t
		qp.BeforeID = &id
	}

	rows, err := s.q().ListOrgAuditEvents(r.Context(), qp)
	if err != nil {
		s.log.Error("list audit", "err", err)
		problemInternal(w, r)
		return
	}

	events := make([]AuditEvent, 0, len(rows))
	for _, row := range rows {
		e := AuditEvent{
			Id:         row.ID,
			OccurredAt: row.OccurredAt,
			ActorKind:  AuditEventActorKind(row.ActorKind),
			Action:     row.Action,
		}
		if row.ActorHandle != nil {
			e.ActorHandle = row.ActorHandle
		}
		if row.TargetKind != nil {
			e.TargetKind = row.TargetKind
		}
		if row.TargetID != nil {
			e.TargetId = row.TargetID
		}
		if len(row.Detail) > 0 {
			var detail map[string]interface{}
			if err := json.Unmarshal(row.Detail, &detail); err == nil {
				e.Detail = &detail
			}
		}
		events = append(events, e)
	}

	page := AuditPage{Events: events}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		cur := encodeAuditCursor(last.OccurredAt, last.ID)
		page.NextCursor = &cur
	}
	writeJSON(w, http.StatusOK, page)
}
