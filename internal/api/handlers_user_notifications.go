package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

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
// runFailures and runFinished may be omitted, and an omitted one keeps
// the row's value: clients predate them, and reading an absence as a
// value would move a switch the client never showed, off for the first
// three and never on for the run kinds. The keep is the
// statement's own (COALESCE in the upsert), so two clients writing at
// once cannot resurrect a value neither sent. A write that leaves out a
// required switch is refused with 422 and changes nothing.
func (s *Server) UpdateUserNotificationSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		problemBadRequest(w, r, "Could not read the request body: "+err.Error())
		return
	}
	var req NotificationSettings
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		problemBadRequest(w, r, "Could not decode the request body: "+err.Error())
		return
	}
	if missing := missingNotificationSwitches(body); len(missing) > 0 {
		fields := make([]FieldError, 0, len(missing))
		for _, f := range missing {
			fields = append(fields, FieldError{Field: f, Message: "Required: send it on or off."})
		}
		problemValidation(w, r, "Send every required switch: "+strings.Join(missing, ", ")+".", fields...)
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

// requiredNotificationSwitches are the switches a write must carry. They
// decode as plain booleans, so an omitted one would read as off: a
// client that sent only the switch it changed would turn quarantine and
// advisory mail off without saying so. The optional switches are not
// listed; an omitted one keeps the row's value.
var requiredNotificationSwitches = []struct{ object, key string }{
	{"email", "dependencyAlerts"},
	{"email", "quarantine"},
	{"email", "reviewDecisions"},
	{"email", "advisories"},
	{"email", "orgInvites"},
	{"web", "dependencyAlerts"},
}

// missingNotificationSwitches names, as object.key, each required switch
// the body does not carry. A body that decoded into NotificationSettings
// is an object, so a failure to read it here means nothing is present.
func missingNotificationSwitches(body []byte) []string {
	var present map[string]map[string]json.RawMessage
	_ = json.Unmarshal(body, &present)
	var missing []string
	for _, sw := range requiredNotificationSwitches {
		if _, ok := present[sw.object][sw.key]; !ok {
			missing = append(missing, sw.object+"."+sw.key)
		}
	}
	return missing
}
