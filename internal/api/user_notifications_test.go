package api_test

import (
	"net/http"
	"testing"
)

// Notification settings: defaults read back as everything on,
// a full replace persists, and each caller sees only their own.
func TestNotificationSettingsRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	u := env.register("notif-user")
	env.verifyEmail(u)
	sess := env.login(u)
	other := env.register("notif-other")
	env.verifyEmail(other)
	otherSess := env.login(other)

	type settings struct {
		Email map[string]bool `json:"email"`
		Web   map[string]bool `json:"web"`
	}
	var got settings
	env.doJSON(sess, http.MethodGet, "/api/v1/user/notifications", nil, &got, http.StatusOK)
	for _, k := range []string{"dependencyAlerts", "quarantine", "reviewDecisions", "advisories", "orgInvites"} {
		if !got.Email[k] {
			t.Fatalf("default email.%s must be on: %+v", k, got)
		}
	}
	if !got.Web["dependencyAlerts"] {
		t.Fatalf("default web banner must be on: %+v", got)
	}

	want := map[string]any{
		"email": map[string]bool{"dependencyAlerts": true, "quarantine": false, "reviewDecisions": false, "advisories": true, "orgInvites": false},
		"web":   map[string]bool{"dependencyAlerts": false},
	}
	env.doJSON(sess, http.MethodPut, "/api/v1/user/notifications", want, &got, http.StatusOK)
	if got.Email["quarantine"] || got.Email["reviewDecisions"] || got.Email["orgInvites"] || !got.Email["dependencyAlerts"] || got.Web["dependencyAlerts"] {
		t.Fatalf("saved settings: %+v", got)
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/notifications", nil, &got, http.StatusOK)
	if got.Email["quarantine"] || got.Web["dependencyAlerts"] {
		t.Fatalf("settings did not persist: %+v", got)
	}
	// The other user is untouched, and nobody reads without a session.
	env.doJSON(otherSess, http.MethodGet, "/api/v1/user/notifications", nil, &got, http.StatusOK)
	if !got.Email["quarantine"] || !got.Web["dependencyAlerts"] {
		t.Fatalf("another user's settings changed: %+v", got)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/user/notifications", nil, nil, http.StatusUnauthorized)
}
