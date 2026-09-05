package api_test

// The global advisory feed and permalinks (agentry#24, DEV-038): newest
// first, public agents only, keyset-paged with a Link header; the per-agent
// mode is unchanged.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAdvisoryFeedAndPermalink(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("adv-feed")
	env.verifyEmail(user)
	sess := env.login(user)
	for _, spec := range []struct{ name, vis string }{{"pub-a", "public"}, {"pub-b", "public"}, {"priv", "private"}} {
		env.doJSON(sess, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": user, "name": spec.name, "modes": []string{"autonomous"}, "visibility": spec.vis}, nil, http.StatusCreated)
	}
	ids := map[string]uuid.UUID{}
	for i, name := range []string{"pub-a", "pub-b", "priv"} {
		id := uuid.New()
		ids[name] = id
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, published_at)
			 SELECT $1, a.id, '<1.0.0', 'high', $3, now() - make_interval(mins => $4::int)
			 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $2 AND a.name = $5`,
			id, user, "advisory on "+name, 10-i, name); err != nil {
			t.Fatal(err)
		}
	}

	type adv struct {
		Id      string `json:"id"`
		Agent   string `json:"agent"`
		Summary string `json:"summary"`
	}
	// Feed: newest first, the private agent's advisory absent.
	var feed []adv
	env.doJSON(anonymous, http.MethodGet, "/api/v1/advisories?limit=100", nil, &feed, http.StatusOK)
	seen := map[string]bool{}
	for _, a := range feed {
		seen[a.Id] = true
		if strings.HasSuffix(a.Agent, "/priv") {
			t.Fatalf("feed leaked a private agent's advisory: %+v", a)
		}
	}
	if !seen[ids["pub-a"].String()] || !seen[ids["pub-b"].String()] {
		t.Fatalf("feed misses the public advisories: %+v", feed)
	}
	// Ordering: pub-b (newer) before pub-a within this user's entries.
	posA, posB := -1, -1
	for i, a := range feed {
		if a.Id == ids["pub-a"].String() {
			posA = i
		}
		if a.Id == ids["pub-b"].String() {
			posB = i
		}
	}
	if posB > posA {
		t.Fatalf("feed not newest-first: pub-b at %d, pub-a at %d", posB, posA)
	}
	if feed[posA].Agent != user+"/pub-a" {
		t.Fatalf("feed item lacks the agent ref: %+v", feed[posA])
	}

	// Paging: limit=1 yields a Link: rel="next" whose cursor continues.
	res := env.do(anonymous, http.MethodGet, "/api/v1/advisories?limit=1", nil)
	_ = res.Body.Close()
	link := res.Header.Get("Link")
	if !strings.Contains(link, `rel="next"`) || !strings.Contains(link, "cursor=") {
		t.Fatalf("no next link on a full page: %q", link)
	}
	next := link[strings.Index(link, "<")+1 : strings.Index(link, ">")]
	var page2 []adv
	env.doJSON(anonymous, http.MethodGet, next, nil, &page2, http.StatusOK)
	if len(page2) == 0 || page2[0].Id == feed[0].Id {
		t.Fatalf("second page did not advance: %+v", page2)
	}
	res = env.do(anonymous, http.MethodGet, "/api/v1/advisories?cursor=garbage", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity && res.StatusCode != http.StatusBadRequest {
		t.Fatalf("corrupt cursor: got %d", res.StatusCode)
	}

	// Permalink: public resolves with the agent ref; private is a 404.
	var one adv
	env.doJSON(anonymous, http.MethodGet, "/api/v1/advisories/"+ids["pub-a"].String(), nil, &one, http.StatusOK)
	if one.Agent != user+"/pub-a" || one.Summary != "advisory on pub-a" {
		t.Fatalf("permalink: %+v", one)
	}
	res = env.do(anonymous, http.MethodGet, "/api/v1/advisories/"+ids["priv"].String(), nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("private advisory permalink: got %d want 404", res.StatusCode)
	}

	// Per-agent mode unchanged (and it still serves the private agent to
	// its owner's session, as before).
	var mine []adv
	env.doJSON(sess, http.MethodGet, "/api/v1/advisories?affecting="+user+"/pub-a", nil, &mine, http.StatusOK)
	if len(mine) != 1 || mine[0].Id != ids["pub-a"].String() {
		t.Fatalf("affecting mode: %+v", mine)
	}
}
