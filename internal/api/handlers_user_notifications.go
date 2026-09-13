package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/notify"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Notification settings (agentry#190): how the registry's alerts reach the
// caller. Self-scoped like the profile; a PAT with user:profile may read
// and change them.

// GetUserNotificationSettings implements GET /user/notifications.
func (s *Server) GetUserNotificationSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	row, err := notify.Settings(r.Context(), s.q(), p.UserID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "notification settings: read", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, notificationSettingsToAPI(row))
}

// UpdateUserNotificationSettings implements PUT /user/notifications: a full
// replace, so a client never has to know which fields exist to keep the
// others as they were — it sends what it read back, changed.
func (s *Server) UpdateUserNotificationSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req NotificationSettings
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().UpsertUserNotificationSettings(r.Context(), storegen.UpsertUserNotificationSettingsParams{
		UserID:                p.UserID,
		EmailDependencyAlerts: req.Email.DependencyAlerts,
		EmailQuarantine:       req.Email.Quarantine,
		EmailReviewDecisions:  req.Email.ReviewDecisions,
		EmailAdvisories:       req.Email.Advisories,
		EmailOrgInvites:       req.Email.OrgInvites,
		WebDependencyAlerts:   req.Web.DependencyAlerts,
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "notification settings: write", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, notificationSettingsToAPI(row))
}

func notificationSettingsToAPI(row storegen.UserNotificationSetting) NotificationSettings {
	return NotificationSettings{
		Email: EmailNotificationSettings{
			DependencyAlerts: row.EmailDependencyAlerts, Quarantine: row.EmailQuarantine,
			ReviewDecisions: row.EmailReviewDecisions, Advisories: row.EmailAdvisories, OrgInvites: row.EmailOrgInvites,
		},
		Web: WebNotificationSettings{DependencyAlerts: row.WebDependencyAlerts},
	}
}
