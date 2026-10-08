package api_test

import (
	"net/http"
	"testing"
)

// The report theme (agentry#989): an account that never chose reads back
// with no theme, a built-in name round-trips, an unknown one is refused, a
// body with no theme clears the choice, and each account reads only its
// own — a user:profile token included, since the CLI reads it that way.
func TestReportSettingsRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	u := env.register("report-user")
	env.verifyEmail(u)
	sess := env.login(u)
	other := env.register("report-other")
	env.verifyEmail(other)
	otherSess := env.login(other)

	type settings struct {
		Theme *string `json:"theme"`
	}
	const path = "/api/v1/user/report-settings"
	var got settings
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Theme != nil {
		t.Fatalf("never chosen must read back with no theme, got %q", *got.Theme)
	}

	for _, name := range []string{"plain", "formal", "brief", "technical", "letter"} {
		got = settings{}
		env.doJSON(sess, http.MethodPut, path, map[string]any{"theme": name}, &got, http.StatusOK)
		if got.Theme == nil || *got.Theme != name {
			t.Fatalf("PUT %s answered %+v", name, got)
		}
	}
	env.doJSON(sess, http.MethodPut, path, map[string]any{"theme": "formal"}, nil, http.StatusOK)
	got = settings{}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Theme == nil || *got.Theme != "formal" {
		t.Fatalf("the theme did not persist: %+v", got)
	}

	// An unknown name, a capitalised one and an empty one are refused, and
	// the saved choice stands.
	for _, bad := range []string{"fancy", "Formal", "", "../plain"} {
		env.doJSON(sess, http.MethodPut, path, map[string]any{"theme": bad}, nil, http.StatusUnprocessableEntity)
	}
	got = settings{}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Theme == nil || *got.Theme != "formal" {
		t.Fatalf("a refused PUT changed the theme: %+v", got)
	}

	// The other account reads its own (none) and cannot see or change this
	// one's: the route has no account in its path, so the only account it
	// reaches is the caller's.
	got = settings{}
	env.doJSON(otherSess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Theme != nil {
		t.Fatalf("another account reads a theme it never chose: %q", *got.Theme)
	}
	env.doJSON(otherSess, http.MethodPut, path, map[string]any{"theme": "brief"}, nil, http.StatusOK)
	got = settings{}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Theme == nil || *got.Theme != "formal" {
		t.Fatalf("another account's PUT reached this one: %+v", got)
	}

	// A user:profile token reads it, as the CLI's sign-in grant does; a
	// token without the scope does not; nobody reads without a credential.
	_, profilePAT := env.mintPAT(sess, "report-profile", "user:profile")
	got = settings{}
	env.doJSON(caller{name: "pat", pat: profilePAT}, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Theme == nil || *got.Theme != "formal" {
		t.Fatalf("a user:profile token read %+v", got)
	}
	_, agentPAT := env.mintPAT(sess, "report-agent", "agent:read")
	env.doJSON(caller{name: "pat", pat: agentPAT}, http.MethodGet, path, nil, nil, http.StatusForbidden)
	env.doJSON(anonymous, http.MethodGet, path, nil, nil, http.StatusUnauthorized)

	// A body with no theme clears the choice back to never chosen.
	got = settings{}
	env.doJSON(sess, http.MethodPut, path, map[string]any{}, &got, http.StatusOK)
	if got.Theme != nil {
		t.Fatalf("a PUT with no theme answered %q", *got.Theme)
	}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Theme != nil {
		t.Fatalf("the cleared theme reads back %q", *got.Theme)
	}
}
