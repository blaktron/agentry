package api_test

// The global advisory feed and permalinks: newest
// first, public agents only, keyset-paged with a Link header; the per-agent
// mode is unchanged.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

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
			`INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, detail, published_at)
			 SELECT $1, a.id, '<1.0.0', 'high', $3, $6, now() - make_interval(mins => $4::int)
			 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $2 AND a.name = $5`,
			id, user, "advisory on "+name, 10-i, name, "details of "+name); err != nil {
			t.Fatal(err)
		}
	}

	type adv struct {
		Id               string  `json:"id"`
		Agent            string  `json:"agent"`
		Summary          string  `json:"summary"`
		AffectedVersions string  `json:"affectedVersions"`
		Severity         string  `json:"severity"`
		Detail           *string `json:"detail"`
		PublishedAt      *string `json:"publishedAt"`
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
	// Page 2 is compared with what page 1 actually returned, not with the
	// feed snapshot above: the feed is global and the package's tests run
	// in parallel, so another test can publish an advisory between the
	// two requests and move the head.
	res := env.do(anonymous, http.MethodGet, "/api/v1/advisories?limit=1", nil)
	var page1 []adv
	if err := json.NewDecoder(res.Body).Decode(&page1); err != nil {
		t.Fatalf("page 1: decode: %v", err)
	}
	_ = res.Body.Close()
	if len(page1) != 1 {
		t.Fatalf("page 1 with limit=1: %+v", page1)
	}
	link := res.Header.Get("Link")
	if !strings.Contains(link, `rel="next"`) || !strings.Contains(link, "cursor=") {
		t.Fatalf("no next link on a full page: %q", link)
	}
	next := link[strings.Index(link, "<")+1 : strings.Index(link, ">")]
	var page2 []adv
	env.doJSON(anonymous, http.MethodGet, next, nil, &page2, http.StatusOK)
	if len(page2) == 0 || page2[0].Id == page1[0].Id {
		t.Fatalf("second page did not advance past %s: %+v", page1[0].Id, page2)
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
	if one.AffectedVersions != "<1.0.0" || one.Severity != "high" || one.Detail == nil || *one.Detail != "details of pub-a" || one.PublishedAt == nil {
		t.Fatalf("permalink does not carry the whole advisory: %+v", one)
	}
	if feedItem := feed[posA]; feedItem.AffectedVersions != "<1.0.0" || feedItem.Severity != "high" || feedItem.Detail == nil || *feedItem.Detail != "details of pub-a" || feedItem.PublishedAt == nil {
		t.Fatalf("feed item does not carry the whole advisory: %+v", feedItem)
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
	if mine[0].AffectedVersions != "<1.0.0" || mine[0].Severity != "high" || mine[0].Detail == nil || *mine[0].Detail != "details of pub-a" || mine[0].PublishedAt == nil {
		t.Fatalf("affecting mode does not carry the whole advisory: %+v", mine[0])
	}
	// A reference that names no namespace and agent is refused; an empty one
	// is no reference at all, and answers the feed.
	env.doJSON(anonymous, http.MethodGet, "/api/v1/advisories?affecting=nope", nil, nil, http.StatusUnprocessableEntity)
	var viaEmpty []adv
	env.doJSON(anonymous, http.MethodGet, "/api/v1/advisories?affecting=", nil, &viaEmpty, http.StatusOK)
	if len(viaEmpty) == 0 || viaEmpty[0].Agent == "" {
		t.Fatalf("an empty affecting should answer the feed: %+v", viaEmpty)
	}

	// Advisories on agents of their own, so the per-agent mode above stays
	// as it was: a draft, a tie, an agent's order, and enough rows to meet
	// the page bounds.
	ctx := context.Background()
	for _, name := range []string{"draft", "tie", "multi", "bulk"} {
		env.doJSON(sess, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": user, "name": name, "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	}
	insert := func(agent, summary string, id uuid.UUID, at *time.Time) {
		t.Helper()
		if _, err := env.st.Pool().Exec(ctx,
			`INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, published_at)
			 SELECT $1, a.id, '<1.0.0', 'high', $3, $4
			 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $2 AND a.name = $5`,
			id, user, summary, at, agent); err != nil {
			t.Fatal(err)
		}
	}

	// An advisory not yet published is on neither public surface.
	draft := uuid.New()
	insert("draft", "not yet published", draft, nil)
	env.doJSON(anonymous, http.MethodGet, "/api/v1/advisories?limit=100", nil, &feed, http.StatusOK)
	for _, a := range feed {
		if a.Id == draft.String() {
			t.Fatalf("feed lists an unpublished advisory: %+v", a)
		}
	}
	res = env.do(anonymous, http.MethodGet, "/api/v1/advisories/"+draft.String(), nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unpublished advisory permalink: got %d want 404", res.StatusCode)
	}

	// Per agent, newest first.
	older, newer := time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	multiOld, multiNew := uuid.New(), uuid.New()
	insert("multi", "the older advisory", multiOld, &older)
	insert("multi", "the newer advisory", multiNew, &newer)
	var multi []adv
	env.doJSON(anonymous, http.MethodGet, "/api/v1/advisories?affecting="+user+"/multi", nil, &multi, http.StatusOK)
	if len(multi) != 2 || multi[0].Id != multiNew.String() || multi[1].Id != multiOld.String() {
		t.Fatalf("an agent's advisories are not newest first: %+v", multi)
	}

	// Advisories published at the same instant keep a fixed order, the larger
	// id first, and a page boundary between them loses neither.
	instant := time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
	tieA, tieB := uuid.New(), uuid.New()
	insert("tie", "one of a tie", tieA, &instant)
	insert("tie", "the other of a tie", tieB, &instant)
	hi, lo := tieA, tieB
	if tieB.String() > tieA.String() {
		hi, lo = tieB, tieA
	}
	res = env.do(anonymous, http.MethodGet, "/api/v1/advisories?limit=1", nil)
	var tie1, tie2 []adv
	if err := json.NewDecoder(res.Body).Decode(&tie1); err != nil {
		t.Fatalf("tie page 1: decode: %v", err)
	}
	_ = res.Body.Close()
	if len(tie1) != 1 || tie1[0].Id != hi.String() {
		t.Fatalf("first of a tie: %+v, want %s", tie1, hi)
	}
	link = res.Header.Get("Link")
	next = link[strings.Index(link, "<")+1 : strings.Index(link, ">")]
	env.doJSON(anonymous, http.MethodGet, next, nil, &tie2, http.StatusOK)
	if len(tie2) == 0 || tie2[0].Id != lo.String() {
		t.Fatalf("second of a tie: %+v, want %s", tie2, lo)
	}

	// Page bounds: 25 by default, never more than 100, a limit below one is
	// the default, and a short page carries no next link.
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, published_at)
		 SELECT gen_random_uuid(), a.id, '<1.0.0', 'high', 'bulk ' || g, now() - make_interval(secs => g)
		 FROM agents a JOIN handles h ON h.id = a.namespace_id, generate_series(1, 101) g
		 WHERE h.handle = $1 AND a.name = 'bulk'`, user); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		query string
		want  int
	}{{"", 25}, {"?limit=0", 25}, {"?limit=-1", 25}, {"?limit=7", 7}, {"?limit=100", 100}, {"?limit=101", 100}, {"?limit=1000", 100}} {
		res := env.do(anonymous, http.MethodGet, "/api/v1/advisories"+c.query, nil)
		var got []adv
		if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
			t.Fatalf("advisories%s: decode: %v", c.query, err)
		}
		_ = res.Body.Close()
		if len(got) != c.want {
			t.Fatalf("advisories%s returned %d items, want %d", c.query, len(got), c.want)
		}
		if !strings.Contains(res.Header.Get("Link"), `rel="next"`) {
			t.Fatalf("advisories%s: a full page carries no next link: %q", c.query, res.Header.Get("Link"))
		}
	}
	past := base64.RawURLEncoding.EncodeToString([]byte("2000-01-01T00:00:00Z|" + uuid.Nil.String()))
	res = env.do(anonymous, http.MethodGet, "/api/v1/advisories?cursor="+past, nil)
	var last []adv
	if err := json.NewDecoder(res.Body).Decode(&last); err != nil {
		t.Fatalf("last page: decode: %v", err)
	}
	_ = res.Body.Close()
	if len(last) != 0 || res.Header.Get("Link") != "" {
		t.Fatalf("a page past the oldest advisory: %+v, Link %q", last, res.Header.Get("Link"))
	}
	// A page that holds fewer than a full page, though not none, carries no
	// next link either: from just after the oldest advisory only it is left.
	shortCursor := base64.RawURLEncoding.EncodeToString([]byte(older.Add(time.Second).UTC().Format(time.RFC3339Nano) + "|" + uuid.Nil.String()))
	res = env.do(anonymous, http.MethodGet, "/api/v1/advisories?cursor="+shortCursor, nil)
	var tail []adv
	if err := json.NewDecoder(res.Body).Decode(&tail); err != nil {
		t.Fatalf("short page: decode: %v", err)
	}
	_ = res.Body.Close()
	if len(tail) == 0 || len(tail) >= 25 || tail[len(tail)-1].Id != multiOld.String() || res.Header.Get("Link") != "" {
		t.Fatalf("a short page: %d advisories, Link %q; want the oldest alone and no next link", len(tail), res.Header.Get("Link"))
	}
}
