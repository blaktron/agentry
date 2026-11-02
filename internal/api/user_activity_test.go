package api_test

import (
	"net/http"
	"strings"
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
			UserAgent  *string        `json:"userAgent"`
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
	// Each event says where it came from and what it was about.
	created := page.Events[0]
	if created.Ip == nil || *created.Ip != "127.0.0.1" || created.UserAgent == nil || !strings.HasPrefix(*created.UserAgent, "Go-http-client") ||
		created.TargetKind == nil || *created.TargetKind != "pat" || created.Detail["name"] != "scripts" {
		t.Fatalf("pat.create event = %+v", created)
	}
	env.doJSON(otherSess, http.MethodGet, "/api/v1/user/activity", nil, &page, http.StatusOK)
	for _, e := range page.Events {
		if e.Action == "pat.create" {
			t.Fatalf("another user's token creation leaked: %+v", e)
		}
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/user/activity", nil, nil, http.StatusUnauthorized)

	// The feed pages by cursor: a full page names the next one and a page
	// that holds the rest names none.
	type activityPage struct {
		Events []struct {
			Id     string `json:"id"`
			Action string `json:"action"`
		} `json:"events"`
		NextCursor *string `json:"nextCursor"`
	}
	var all, first, second activityPage
	res := env.do(sess, http.MethodGet, "/api/v1/user/activity", nil)
	decodeInto(t, res, &all)
	if len(all.Events) < 2 || all.NextCursor != nil || res.Header.Get("Link") != "" {
		t.Fatalf("a page holding the whole feed: %d events, next %v, Link %q", len(all.Events), all.NextCursor, res.Header.Get("Link"))
	}
	res = env.do(sess, http.MethodGet, "/api/v1/user/activity?limit=1", nil)
	decodeInto(t, res, &first)
	if len(first.Events) != 1 || first.NextCursor == nil || !strings.Contains(res.Header.Get("Link"), `rel="next"`) || first.Events[0].Id != all.Events[0].Id {
		t.Fatalf("first page of one: %+v next %v Link %q", first.Events, first.NextCursor, res.Header.Get("Link"))
	}
	res = env.do(sess, http.MethodGet, "/api/v1/user/activity?limit=1&cursor="+*first.NextCursor, nil)
	decodeInto(t, res, &second)
	if len(second.Events) != 1 || second.Events[0].Id != all.Events[1].Id {
		t.Fatalf("second page of one: %+v, want the feed's second event %s", second.Events, all.Events[1].Id)
	}
}
