package api_test

import (
	"net/http"
	"testing"
)

// The account's own activity feed: the caller's sign-in and
// token creation are listed with where they came from, and nobody sees
// anyone else's.
func TestUserActivityFeed(t *testing.T) {
	env, idp := newOIDCTestEnv(t, nil)
	sess := env.mintAccount(t, idp, "act-user")
	_, _ = env.mintPAT(sess, "scripts", "agent:read")
	otherSess := env.mintAccount(t, idp, "act-other")

	var page struct {
		Events []struct {
			Action     string         `json:"action"`
			TargetKind *string        `json:"targetKind"`
			Ip         *string        `json:"ip"`
			Detail     map[string]any `json:"detail"`
		} `json:"events"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/activity", nil, &page, http.StatusOK)
	seen := map[string]bool{}
	for _, e := range page.Events {
		seen[e.Action] = true
	}
	for _, want := range []string{"user.login", "pat.create"} {
		if !seen[want] {
			t.Fatalf("own feed lacks %s: %+v", want, page.Events)
		}
	}
	if page.Events[0].Action != "pat.create" {
		t.Fatalf("newest first: %+v", page.Events[0])
	}
	env.doJSON(otherSess, http.MethodGet, "/api/v1/user/activity", nil, &page, http.StatusOK)
	for _, e := range page.Events {
		if e.Action == "pat.create" {
			t.Fatalf("another user's token creation leaked: %+v", e)
		}
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/user/activity", nil, nil, http.StatusUnauthorized)
}
