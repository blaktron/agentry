package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// ListUserActivity implements GET /user/activity: the audit
// events the caller performed, newest first, with the address and client
// each came from — the "was that me?" view of an account.
func (s *Server) ListUserActivity(w http.ResponseWriter, r *http.Request, params ListUserActivityParams) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	limit := clampLimit(params.Limit, activityDefaultLimit, activityMaxLimit)
	before, beforeID, ok := cursorParams(w, r, params.Cursor)
	if !ok {
		return
	}
	rows, err := s.q().ListUserActivity(r.Context(), storegen.ListUserActivityParams{
		Limit: int32(limit), ActorID: &p.UserID, BeforeTime: before, BeforeID: beforeID,
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "user activity", "err", err)
		problemInternal(w, r)
		return
	}
	events := make([]ActivityEvent, 0, len(rows))
	for _, row := range rows {
		ev := ActivityEvent{Id: row.ID, OccurredAt: row.OccurredAt, Action: row.Action}
		if row.TargetKind != nil {
			ev.TargetKind = row.TargetKind
		}
		if row.Version != nil {
			ev.Version = row.Version
		}
		if row.Ip != "" {
			ip := row.Ip
			ev.Ip = &ip
		}
		if row.UserAgent != nil && *row.UserAgent != "" {
			ev.UserAgent = row.UserAgent
		}
		if len(row.Detail) > 0 {
			var detail map[string]interface{}
			if json.Unmarshal(row.Detail, &detail) == nil && len(detail) > 0 {
				ev.Detail = &detail
			}
		}
		events = append(events, ev)
	}
	page := ActivityPage{Events: events}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		cur := encodeCursor(last.OccurredAt, last.ID)
		page.NextCursor = &cur
		setNextLink(w, r, cur)
	}
	writeJSON(w, http.StatusOK, page)
}
