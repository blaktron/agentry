package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/knowledge"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// eventUserDataCleared tells extensions that a user cleared their data
// (agentry#498), so each clears what it holds for the account — hosted run
// history lives in an extension the core cannot reach.
const eventUserDataCleared = "user.data_cleared"

// ClearCurrentUserData implements POST /user/clear-data (agentry#498): the
// account's credentials, installs and settings go, the account stays. The
// scope is the operator's ("credentials and history only", 2026-09-23):
// BriefAgents, memberships, stars, the handle, the email, the sign-in
// account at the directory, the subscription and credits are untouched.
// The caller's own session survives, so the person sees the result.
func (s *Server) ClearCurrentUserData(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSecurityManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Via != "session" {
		problemForbidden(w, r, "Clearing an account's data requires a session, not a token.")
		return
	}

	counts := map[string]any{}
	var knowledgeKeys []string
	err := s.st.WithTx(r.Context(), func(tq *storegen.Queries) error {
		n, err := tq.RevokeAllPATsForUser(r.Context(), p.UserID)
		if err != nil {
			return err
		}
		counts["tokens"] = n
		if n, err = tq.RevokeAllSSHKeysForUser(r.Context(), p.UserID); err != nil {
			return err
		}
		counts["sshKeys"] = n
		if n, err = tq.DeleteTrustedDevicesForUser(r.Context(), p.UserID); err != nil {
			return err
		}
		counts["trustedDevices"] = n
		// A desktop sign-in code another session minted moments ago would
		// otherwise still exchange for a fresh token after the clear.
		if n, err = tq.ConsumeDesktopGrantsForUser(r.Context(), p.UserID); err != nil {
			return err
		}
		counts["desktopCodes"] = n
		if n, err = tq.RevokeOtherUserSessions(r.Context(), storegen.RevokeOtherUserSessionsParams{
			UserID: p.UserID, ID: p.SessionID,
		}); err != nil {
			return err
		}
		counts["otherSessions"] = n
		if n, err = tq.DeleteAccountInstallsForUser(r.Context(), p.UserID); err != nil {
			return err
		}
		counts["installs"] = n
		if _, err = tq.UpdateUserDisplayName(r.Context(), storegen.UpdateUserDisplayNameParams{ID: p.UserID, DisplayName: ""}); err != nil {
			return err
		}
		if n, err = tq.DeleteUserNotificationSettings(r.Context(), p.UserID); err != nil {
			return err
		}
		counts["notificationSettingsReset"] = n > 0
		// The account's knowledge packs and what opens them (agentry#593):
		// the rows here, the key and the sealed trees once this commits.
		if knowledgeKeys, err = knowledge.EraseOwner(r.Context(), tq, knowledge.User(p.UserID)); err != nil {
			return err
		}
		counts["knowledgeObjects"] = len(knowledgeKeys)
		e := auditEvent(r, audit.ActionUserDataClear)
		e.TargetKind, e.TargetID = "user", p.UserID
		e.Detail = counts
		return s.auditW.Write(r.Context(), tq, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "clear user data", "err", err)
		problemInternal(w, r)
		return
	}
	s.knowledge.FinishErasure(r.Context(), knowledge.User(p.UserID), knowledgeKeys)
	s.fireEvent(r.Context(), Event{Kind: eventUserDataCleared, UserID: p.UserID, Payload: counts})
	w.WriteHeader(http.StatusNoContent)
}
