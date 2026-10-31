package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/notify"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Notification settings: how the registry's alerts reach the
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
// replace of the switches every client knows, sent back as read and
// changed — with five exceptions. billing, schedules, bugReports,
// runFailures and runFinished may be omitted, and an
// omitted one keeps the row's value: clients predate them, and reading an
// absence as false would switch that mail off for anyone who saved any
// other setting (or, for the run kinds, could never turn it on). The keep is the
// statement's own (COALESCE in the upsert), so two clients writing at
// once cannot resurrect a value neither sent.
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
		EmailBilling:          req.Email.Billing,     // nil keeps the row's value
		EmailSchedules:        req.Email.Schedules,   // nil keeps the row's value
		EmailBugReports:       req.Email.BugReports,  // nil keeps the row's value
		EmailRunFailures:      req.Email.RunFailures, // nil keeps the row's value
		EmailRunFinished:      req.Email.RunFinished, // nil keeps the row's value
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
			Billing: &row.EmailBilling, Schedules: &row.EmailSchedules, BugReports: &row.EmailBugReports,
			RunFailures: &row.EmailRunFailures, RunFinished: &row.EmailRunFinished,
		},
		Web: WebNotificationSettings{DependencyAlerts: row.WebDependencyAlerts},
	}
}
