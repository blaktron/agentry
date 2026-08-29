package api

// Session self-management (§12.1): the endpoints behind the console's
// "where am I signed in" panel and the CLI's account view.
//
//	GET    /user/sessions           list the caller's live sessions
//	DELETE /user/sessions/{id}      revoke one of them
//	DELETE /user/sessions           revoke every one EXCEPT the caller's own
//
// One rule shapes all three: a session list is a list of credentials that can
// still act as you, and only a session may manage sessions. A PAT is a
// different credential class — it sees an empty list rather than an error
// (nothing is hidden from it that it could otherwise reach), and it is
// refused outright on the revoking routes, exactly as it is on logout.

import (
	"net/http"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// ListUserSessions implements GET /user/sessions.
func (s *Server) ListUserSessions(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())

	// A PAT has no sessions of its own. Answering with the *user's* browser
	// sessions would turn any `user:profile` token into a device-inventory
	// read, so the honest answer for a non-session caller is an empty list.
	if p.Via != "session" {
		writeJSON(w, http.StatusOK, SessionList{Sessions: []SessionInfo{}})
		return
	}

	rows, err := s.q().ListActiveUserSessions(r.Context(), p.UserID)
	if err != nil {
		s.log.Error("list sessions", "err", err)
		problemInternal(w, r)
		return
	}
	out := SessionList{Sessions: make([]SessionInfo, 0, len(rows))}
	for _, row := range rows {
		out.Sessions = append(out.Sessions, sessionToAPI(row, p.SessionID))
	}
	writeJSON(w, http.StatusOK, out)
}

// sessionToAPI maps a row to the wire shape, marking the calling session.
func sessionToAPI(row storegen.ListActiveUserSessionsRow, current uuid.UUID) SessionInfo {
	out := SessionInfo{
		Id:         row.ID,
		CreatedAt:  row.CreatedAt,
		LastSeenAt: row.LastSeenAt,
		Current:    row.ID == current,
	}
	if row.Ip != nil {
		ip := row.Ip.String()
		out.Ip = &ip
	}
	out.UserAgent = row.UserAgent
	return out
}

// RevokeUserSession implements DELETE /user/sessions/{sessionId}.
func (s *Server) RevokeUserSession(w http.ResponseWriter, r *http.Request, sessionID openapi_types.UUID) {
	if !s.authorize(w, r, auth.ActUserSecurityManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Via != "session" {
		problemForbidden(w, r, "managing sessions requires a session")
		return
	}

	var rows int64
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		// The query is scoped by user_id, so "not mine" and "does not exist"
		// collapse into rows == 0 in the database rather than in a branch
		// here — there is no lookup that could leak another user's session id.
		n, err := q.RevokeUserSessionByID(r.Context(), storegen.RevokeUserSessionByIDParams{
			ID: sessionID, UserID: p.UserID,
		})
		if err != nil {
			return err
		}
		rows = n
		if n == 0 {
			return nil
		}
		e := auditEvent(r, audit.ActionUserLogout)
		e.TargetKind, e.TargetID = "session", sessionID
		e.Detail = map[string]any{"scope": "one", "self": sessionID == p.SessionID}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("revoke session", "err", err)
		problemInternal(w, r)
		return
	}
	if rows == 0 {
		problemNotFound(w, r)
		return
	}
	// Revoking the session you are holding is a logout: clear the cookie so
	// the browser stops presenting a credential the server has just killed.
	if sessionID == p.SessionID {
		clearSessionCookie(w, s.cfg.Auth.CookieSecure)
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeOtherUserSessions implements DELETE /user/sessions — "sign out
// everywhere else". The calling session is deliberately spared: a control
// that logs you out of the browser you are using is one nobody presses twice.
func (s *Server) RevokeOtherUserSessions(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSecurityManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Via != "session" {
		problemForbidden(w, r, "managing sessions requires a session")
		return
	}

	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.RevokeOtherUserSessions(r.Context(), storegen.RevokeOtherUserSessionsParams{
			UserID: p.UserID, ID: p.SessionID,
		})
		if err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserLogout)
		e.TargetKind, e.TargetID = "user", p.UserID
		e.Detail = map[string]any{"scope": "others", "revoked": n}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("revoke other sessions", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clearSessionCookie expires the session cookie (shared with logout).
func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
