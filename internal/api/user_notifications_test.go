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
	env.doJSON(anonymous, http.MethodPut, "/api/v1/user/notifications", want, nil, http.StatusUnauthorized)

	// Every switch is its own: writing one on and the rest off reads back
	// exactly that, on the write and on the next read, and the web banner
	// follows its own value. Each write after the first replaces the row.
	keys := []string{"dependencyAlerts", "quarantine", "reviewDecisions", "advisories", "orgInvites"}
	for i, on := range keys {
		email := map[string]bool{}
		for _, k := range keys {
			email[k] = k == on
		}
		banner := i%2 == 0
		body := map[string]any{"email": email, "web": map[string]bool{"dependencyAlerts": banner}}
		for step, read := range []func(){
			func() { env.doJSON(sess, http.MethodPut, "/api/v1/user/notifications", body, &got, http.StatusOK) },
			func() { env.doJSON(sess, http.MethodGet, "/api/v1/user/notifications", nil, &got, http.StatusOK) },
		} {
			read()
			for _, k := range keys {
				if got.Email[k] != (k == on) {
					t.Fatalf("only %s on, step %d: email.%s = %t in %+v", on, step, k, got.Email[k], got)
				}
			}
			if got.Web["dependencyAlerts"] != banner {
				t.Fatalf("only %s on, step %d: web banner = %t, want %t", on, step, got.Web["dependencyAlerts"], banner)
			}
		}
	}

	// A body that does not read as settings is refused and changes nothing.
	for name, bad := range map[string]any{
		"an unknown switch":              map[string]any{"email": map[string]any{"dependencyAlerts": true, "bogus": true}},
		"a switch that is not a boolean": map[string]any{"email": map[string]any{"quarantine": "yes"}},
		"an unknown section":             map[string]any{"sms": map[string]any{"quarantine": true}},
	} {
		env.doJSON(sess, http.MethodPut, "/api/v1/user/notifications", bad, nil, http.StatusBadRequest)
		env.doJSON(sess, http.MethodGet, "/api/v1/user/notifications", nil, &got, http.StatusOK)
		if !got.Email["orgInvites"] || got.Email["quarantine"] || got.Email["dependencyAlerts"] {
			t.Fatalf("%s changed the settings: %+v", name, got)
		}
	}
}
