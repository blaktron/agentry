package api_test

// search: the ranking formula and the README's weight-C place in the
// index. The ORDER BY combines its three factors rather than chaining
// them as tie-breaks, and readme_text is indexed, so a term appearing only
// in an agent's README (which is where an agent actually describes
// itself) is found.

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

type searchHit struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Installs  int64  `json:"installs30d"`
}

type searchResults struct {
	Results []searchHit `json:"results"`
}

// search runs a query and keeps only the hits in ns, preserving order.
//
// The test database is shared and never truncated, so fixtures from earlier
// runs are still present — and the trigram fallback matches on name
// similarity, which means a term like "rankterm<sfx>" also matches
// "rankterm<some other sfx>" from a previous run. Filtering to this test's
// own namespace is what makes the result set closed; the relative order of
// what remains is still exactly what the ranking produced.
func (env *testEnv) search(t *testing.T, ns, query string, extra ...string) []searchHit {
	t.Helper()
	path := "/api/v1/search?q=" + query
	extras := strings.Join(extra, "&")
	if !strings.Contains(extras, "limit=") {
		// Enough headroom that this test's own fixtures cannot be paged out by
		// leftovers from earlier runs before the namespace filter sees them.
		path += "&limit=100"
	}
	if extras != "" {
		path += "&" + extras
	}
	var out searchResults
	env.doJSON(anonymous, http.MethodGet, path, nil, &out, http.StatusOK)
	mine := make([]searchHit, 0, len(out.Results))
	for _, h := range out.Results {
		if h.Namespace == ns {
			mine = append(mine, h)
		}
	}
	return mine
}

func names(hits []searchHit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Name)
	}
	return out
}

// publishSearchable creates and publishes a public agent whose summary and
// README bodies are the caller's, so a test can plant a unique term in either.
func (env *testEnv) publishSearchable(t *testing.T, sess caller, ns, name, summary, readme string) {
	t.Helper()
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": ns, "name": name, "modes": []string{"autonomous"}, "visibility": "public",
		"summary": summary,
	}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub-"+name, "agent:publish", "agent:read")
	files := skillFiles(ns, name, "1.0.0", nil)
	files["README.md"] = readme
	status, body := env.uploadVersionCLI(ns, name, pat, files)
	if status != http.StatusAccepted {
		t.Fatalf("publish %s: %d %s", name, status, body)
	}
	// readme_text is written by the pipeline on the publish transition, so the
	// term is only searchable once the version has actually reached published.
	env.waitStatus(ns, name, "1.0.0", "published")
}

// setInstalls plants a 30-day install count for an agent. The rollup the
// ranking reads is sum(installs) over the last 30 days, and nothing in the
// test API records downloads, so this writes download_stats directly.
func (env *testEnv) setInstalls(t *testing.T, ns, name string, installs int) {
	t.Helper()
	ctx := context.Background()
	_, err := env.st.Pool().Exec(ctx, `
		INSERT INTO download_stats (agent_id, version_id, day, installs)
		SELECT a.id, a.latest_published_version_id, current_date, $3
		FROM agents a JOIN handles h ON h.id = a.namespace_id
		WHERE h.handle = $1 AND a.name = $2
		ON CONFLICT (agent_id, version_id, day) DO UPDATE SET installs = EXCLUDED.installs`,
		ns, name, installs)
	if err != nil {
		t.Fatalf("seed download_stats: %v", err)
	}
}

// relevance × log(1+installs_30d) × recency_decay. With relevance and
// recency effectively equal across agents published seconds apart in one test,
// installs is what separates them — a lexicographic ORDER BY could not,
// because ts_rank would be compared first and only ties would fall through.
func TestSearchRanksByPopularityWhenRelevanceIsEqual(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("rank-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	term := "rankterm" + env.sfx
	// Identical summaries: same relevance, same recency, different installs.
	for _, name := range []string{"quiet", "middling", "popular"} {
		env.publishSearchable(t, sess, owner, name, term, "# "+name+"\nBody.\n")
	}
	env.setInstalls(t, owner, "quiet", 0)
	env.setInstalls(t, owner, "middling", 50)
	env.setInstalls(t, owner, "popular", 5000)

	hits := env.search(t, owner, term)
	got := names(hits)
	want := []string{"popular", "middling", "quiet"}
	if len(got) != 3 {
		t.Fatalf("search returned %v, want the three seeded agents", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ranking = %v, want %v (popularity must order equal-relevance hits)", got, want)
		}
	}
	// Each hit reports its own trailing-30-day installs.
	for i, installs := range []int64{5000, 50, 0} {
		if hits[i].Installs != installs {
			t.Fatalf("%s reports %d installs, want %d", hits[i].Name, hits[i].Installs, installs)
		}
	}

	// Age counts too: the score decays with the agent's age, so an agent
	// published years ago falls below fresher ones that are far less
	// installed.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agents SET created_at = now() - interval '2920 days'
		 WHERE name = 'popular' AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`, owner); err != nil {
		t.Fatal(err)
	}
	got = names(env.search(t, owner, term))
	want = []string{"middling", "quiet", "popular"}
	for i := range want {
		if len(got) != 3 || got[i] != want[i] {
			t.Fatalf("ranking with an old agent = %v, want %v (recency decays the score)", got, want)
		}
	}
}

// The popularity factor is 1+ln(1+installs), not the literal ln(1+installs)
// writes. With no installs the literal expression is 0, and
// since the score is a product it takes relevance and recency with it: every
// zero-install agent scores exactly 0, ties with every other, and the order
// falls through to created_at DESC — newest first, relevance ignored.
//
// This seeds the BETTER match first, so under the literal formula the tie
// would put the worse, newer match on top. Only a popularity factor of at
// least 1 lets relevance decide.
func TestZeroInstallAgentsAreRankedByRelevanceNotArrivalOrder(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("zero-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	term := "zeroterm" + env.sfx
	nameTerm := strings.ToLower(term)

	// Matches on name (weight A) AND summary (B). Published first.
	env.publishSearchable(t, sess, owner, nameTerm, term, "# "+nameTerm+"\nBody.\n")
	time.Sleep(10 * time.Millisecond)
	// Matches on summary only. Published second, so it is the newer row.
	env.publishSearchable(t, sess, owner, "weaker", term, "# weaker\nBody.\n")

	// Neither has any installs: this is a fresh catalogue, the case the
	// literal formula gets wrong.
	got := env.search(t, owner, term)
	if len(got) != 2 {
		t.Fatalf("search returned %v, want both agents", names(got))
	}
	if got[0].Name != nameTerm {
		t.Errorf("ranking = %v; with zero installs the score collapsed and the "+
			"newest row won instead of the better match", names(got))
	}
	for _, h := range got {
		if h.Installs != 0 {
			t.Fatalf("fixture drift: %s has %d installs", h.Name, h.Installs)
		}
	}
}

// Popularity is a real factor, not a tie-break: a much more popular agent
// outranks a slightly better textual match. This is the other half of the
// balance — the +1 must not flatten popularity into irrelevance.
func TestPopularityCanOutweighASmallRelevanceGap(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("pop-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	term := "popterm" + env.sfx
	nameTerm := strings.ToLower(term)
	env.publishSearchable(t, sess, owner, nameTerm, term, "# "+nameTerm+"\nBody.\n")
	env.publishSearchable(t, sess, owner, "widelyused", term, "# widelyused\nBody.\n")
	env.setInstalls(t, owner, "widelyused", 100000)

	got := names(env.search(t, owner, term))
	if len(got) != 2 {
		t.Fatalf("search returned %v, want both agents", got)
	}
	if got[0] != "widelyused" {
		t.Errorf("ranking = %v; 100k installs did not outweigh a one-weight "+
			"relevance gap, so popularity is not participating", got)
	}
}

// weight C. The README is where an agent describes itself, so a
// term appearing only there must match.
func TestSearchMatchesReadmeTerms(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("readme-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	// The term appears ONLY in the README — not in the name, not in the summary.
	readmeTerm := "kerblunker" + env.sfx
	env.publishSearchable(t, sess, owner, "docsonly",
		"an agent with a summary that shares no words",
		"# docsonly\n\nThis agent performs "+readmeTerm+" analysis on invoices.\n")

	got := env.search(t, owner, readmeTerm)
	if len(got) != 1 || got[0].Name != "docsonly" {
		t.Fatalf("a README-only term matched %v; the readme is indexed at weight C", names(got))
	}
}

// Searching a namespace handle finds its agents. The handle is not in
// search_tsv (covers name/summary/readme), so this rides the dedicated
// handle clause — the CLI lists by namespace, and cli.sh looks a
// fresh publish up by its random handle.
func TestSearchMatchesNamespaceHandle(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("handle-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	env.publishSearchable(t, sess, owner, "by-handle",
		"a summary that never mentions the namespace",
		"# by-handle\n\nreadme without the namespace either.\n")
	// An agent whose name is nothing like the handle is found by the handle
	// alone.
	env.publishSearchable(t, sess, owner, "plain",
		"a summary that never mentions the namespace",
		"# plain\n\nreadme without the namespace either.\n")

	got := env.search(t, owner, owner) // query IS the handle
	found := false
	for _, hit := range got {
		if hit.Name == "by-handle" {
			found = true
		}
	}
	if !found {
		t.Fatalf("searching the namespace handle %q missed its agent; got %v", owner, names(got))
	}
	if plain := names(got); !slices.Contains(plain, "plain") {
		t.Fatalf("searching the namespace handle %q missed an agent that only its handle names; got %v", owner, plain)
	}

	// A handle match scores by how close the handle is to the query, so an
	// agent found only through its handle outranks one that merely mentions
	// the handle in its summary.
	otherH := env.register("handle-c")
	env.verifyEmail(otherH)
	other := env.login(otherH)
	env.publishSearchable(t, other, otherH, "mentions", owner, "# mentions\nBody.\n")
	var all searchResults
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+owner+"&limit=100", nil, &all, http.StatusOK)
	byHandle, mentions := -1, -1
	for i, h := range all.Results {
		if h.Namespace == owner && h.Name == "plain" {
			byHandle = i
		}
		if h.Namespace == otherH && h.Name == "mentions" {
			mentions = i
		}
	}
	if byHandle < 0 || mentions < 0 || byHandle > mentions {
		t.Fatalf("handle match at %d, summary mention at %d; the handle match must come first", byHandle, mentions)
	}
}

// Weight ordering: a term in the name (A) must outrank the same term in a
// README (C), or the weights are decorative.
func TestSearchWeightsNameAboveReadme(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("weight-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	term := "weighted" + env.sfx
	// Lowercase-alphanumeric name grammar, so the term has to be sanitized.
	nameTerm := strings.ToLower(strings.ReplaceAll(term, "_", "-"))
	env.publishSearchable(t, sess, owner, nameTerm, "no shared words here", "# doc\nBody.\n")
	env.publishSearchable(t, sess, owner, "inreadme", "no shared words here",
		"# inreadme\n\nMentions "+term+" once.\n")

	// Equal installs, so weight is the only difference.
	env.setInstalls(t, owner, nameTerm, 10)
	env.setInstalls(t, owner, "inreadme", 10)

	got := names(env.search(t, owner, term))
	if len(got) < 1 {
		t.Fatalf("neither agent matched %q", term)
	}
	if got[0] != nameTerm {
		t.Errorf("ranking = %v; a name match (weight A) must outrank a README match (weight C)", got)
	}

	// A name that is only close to the term, sharing no word with it, is
	// still a match and scores by how close it is: above a README mention.
	// It is the oldest, so only its score can put it first.
	fuzzy := nameTerm + "x"
	env.publishSearchable(t, sess, owner, fuzzy, "no shared words here", "# doc\nBody.\n")
	env.setInstalls(t, owner, fuzzy, 10)
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agents SET created_at = now() - interval '1 day'
		 WHERE name = $2 AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`, owner, fuzzy); err != nil {
		t.Fatal(err)
	}
	got = names(env.search(t, owner, term))
	if want := []string{nameTerm, fuzzy, "inreadme"}; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("ranking = %v, want %v (a close name outranks a README mention)", got, want)
	}
}

// sort= overrides the score; it must still return the same result set.
func TestSearchExplicitSortsOverrideTheScore(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("sort-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	term := "sortterm" + env.sfx
	env.publishSearchable(t, sess, owner, "alpha", term, "# alpha\nBody.\n")
	// A gap so created_at ordering is unambiguous.
	time.Sleep(10 * time.Millisecond)
	env.publishSearchable(t, sess, owner, "beta", term, "# beta\nBody.\n")

	env.setInstalls(t, owner, "alpha", 900)
	env.setInstalls(t, owner, "beta", 1)

	if got := names(env.search(t, owner, term, "sort=installs")); len(got) != 2 || got[0] != "alpha" {
		t.Errorf("sort=installs = %v, want alpha first", got)
	}
	if got := names(env.search(t, owner, term, "sort=newest")); len(got) != 2 || got[0] != "beta" {
		t.Errorf("sort=newest = %v, want beta first", got)
	}

	// With the most installed agent also the oldest, the score (which decays
	// with age) puts the fresher, less installed one first, and the install
	// sort still puts the most installed first.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agents SET created_at = now() - interval '1460 days'
		 WHERE name = 'alpha' AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`, owner); err != nil {
		t.Fatal(err)
	}
	if got := names(env.search(t, owner, term)); len(got) != 2 || got[0] != "beta" {
		t.Errorf("by score = %v, want beta first", got)
	}
	if got := names(env.search(t, owner, term, "sort=installs")); len(got) != 2 || got[0] != "alpha" {
		t.Errorf("sort=installs = %v, want alpha first though the score puts it second", got)
	}

	// The install count a hit reports, and the statistics endpoint's lifetime
	// and trailing-30-day figures, count 30 days back from today inclusive: a
	// day 30 back counts, a day 31 back is in the lifetime figure alone.
	for _, row := range []struct{ daysAgo, installs int }{{30, 7}, {31, 11}} {
		if _, err := env.st.Pool().Exec(context.Background(), `
			INSERT INTO download_stats (agent_id, version_id, day, installs)
			SELECT a.id, a.latest_published_version_id, current_date - $3::int, $4
			FROM agents a JOIN handles h ON h.id = a.namespace_id
			WHERE h.handle = $1 AND a.name = $2`, owner, "alpha", row.daysAgo, row.installs); err != nil {
			t.Fatal(err)
		}
	}
	if hits := env.search(t, owner, term, "sort=installs"); len(hits) != 2 || hits[0].Name != "alpha" || hits[0].Installs != 907 {
		t.Errorf("sort=installs = %+v, want alpha first with 907 installs in the window", hits)
	}
	var stats struct {
		InstallsTotal int64 `json:"installsTotal"`
		Installs30d   int64 `json:"installs30d"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+owner+"/alpha/stats", nil, &stats, http.StatusOK)
	if stats.InstallsTotal != 918 || stats.Installs30d != 907 {
		t.Errorf("stats = %+v, want 918 in all and 907 in the last 30 days", stats)
	}
}

// An empty query is a browse, not a search: relevance is 1 for every row, so
// popularity and recency do the ordering rather than every score collapsing
// to zero and the page arriving unordered.
func TestEmptyQueryBrowsesWithoutCollapsing(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("browse-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	env.publishSearchable(t, sess, owner, "browsable"+strings.ToLower(env.sfx),
		"browse fixture", "# browsable\nBody.\n")

	var out searchResults
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q=&limit=100", nil, &out, http.StatusOK)
	if len(out.Results) == 0 {
		t.Fatal("an empty query returned nothing; browse must list the catalogue")
	}

	// Browsing orders by popularity: the more installed agent leads though a
	// newer one was published after it.
	env.publishSearchable(t, sess, owner, "browsepopular", "browse fixture", "# browsepopular\nBody.\n")
	env.setInstalls(t, owner, "browsepopular", 5000)
	env.publishSearchable(t, sess, owner, "browsefresh", "browse fixture", "# browsefresh\nBody.\n")
	if got := names(env.search(t, owner, "")); len(got) != 3 || got[0] != "browsepopular" {
		t.Fatalf("browse order = %v, want the most installed agent first", got)
	}
	if got := names(env.search(t, owner, "%20%20")); len(got) != 3 || got[0] != "browsepopular" {
		t.Fatalf("a blank query browses: %v, want the same order", got)
	}
}

// The trailing (created_at, id) keys make every ordering total, so the same
// query paged twice cannot return the same agent on two pages.
func TestSearchOrderingIsStableAcrossPages(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("page-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	term := "pageterm" + env.sfx
	for i := range 4 {
		env.publishSearchable(t, sess, owner, fmt.Sprintf("paged%d", i), term,
			fmt.Sprintf("# paged%d\nBody.\n", i))
		env.setInstalls(t, owner, fmt.Sprintf("paged%d", i), 10) // identical scores
	}

	seen := map[string]bool{}
	for offset := 0; offset < 4; offset += 2 {
		page := env.search(t, owner, term, fmt.Sprintf("limit=2&offset=%d", offset))
		for _, h := range page {
			if seen[h.Name] {
				t.Fatalf("%s appeared on two pages; the ordering is not total", h.Name)
			}
			seen[h.Name] = true
		}
	}
	if len(seen) != 4 {
		t.Errorf("paging saw %d of 4 agents: %v", len(seen), seen)
	}
}

// total is the hit count for the predicate before paging:
// three agents under one handle, limit=2 → two hits and total 3; offset=2 →
// one hit and total 3; a query matching one → total 1; a filter matching
// none → total 0. The desktop reads it to print the result count.
func TestSearchTotalCountsBeforePaging(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("total-o")
	env.verifyEmail(owner)
	sess := env.login(owner)
	// A token unique to this run in every summary, rather than the handle:
	// the handle clause is trigram-fuzzy, so a query on "total-o<sfx>" would
	// also count a previous run's "total-o<other sfx>" agents on a reused
	// database.
	all := "triune" + env.sfx
	only := "quintessent" + env.sfx
	env.publishSearchable(t, sess, owner, "total-a", "first of three "+all, "# a\n")
	env.publishSearchable(t, sess, owner, "total-b", "second of three "+all+" "+only, "# b\n")
	env.publishSearchable(t, sess, owner, "total-c", "third of three "+all, "# c\n")
	// Three more agents carry the same term and are none of them a result: a
	// private one, a blocked one, and one with nothing published yet.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "total-priv", "modes": []string{"autonomous"}, "visibility": "private",
		"summary": "private " + all,
	}, nil, http.StatusCreated)
	env.publishVersions(t, sess, owner, "total-priv", []versionFiles{
		{"1.0.0", skillFiles(owner, "total-priv", "1.0.0", nil)},
	})
	env.publishSearchable(t, sess, owner, "total-blk", "blocked "+all, "# blk\n")
	staffH := env.register("total-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	env.doJSON(env.login(staffH), http.MethodPost, "/api/v1/platform/agents/"+owner+"/total-blk/block",
		map[string]any{"reason": "fixture"}, nil, http.StatusNoContent)

	page := func(query, extra string) (hits int, total int) {
		t.Helper()
		var out struct {
			Results []searchHit `json:"results"`
			Total   *int        `json:"total"`
		}
		env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+query+"&"+extra, nil, &out, http.StatusOK)
		if out.Total == nil {
			t.Fatalf("search %q %s: no total in the response", query, extra)
		}
		return len(out.Results), *out.Total
	}
	if h, n := page(all, "limit=2"); h != 2 || n != 3 {
		t.Fatalf("limit=2: %d hits, total %d; want 2 and 3", h, n)
	}
	if h, n := page(all, "limit=2&offset=2"); h != 1 || n != 3 {
		t.Fatalf("offset=2: %d hits, total %d; want 1 and 3 (paging must not move the total)", h, n)
	}
	if h, n := page(only, "limit=100"); h != 1 || n != 1 {
		t.Fatalf("a term in one summary: %d hits, total %d; want 1 and 1", h, n)
	}
	if h, n := page(all, "limit=100&verified=true"); h != 0 || n != 0 {
		t.Fatalf("verified=true on a user namespace: %d hits, total %d; want 0 and 0", h, n)
	}
	// The facets count what the query finds in the public catalogue, and
	// only that: the private and the blocked agent are not in them.
	var faceted struct {
		Facets map[string]map[string]int `json:"facets"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+all+"&limit=100", nil, &faceted, http.StatusOK)
	if faceted.Facets["license"]["Apache-2.0"] != 3 || faceted.Facets["mode"]["autonomous"] != 3 {
		t.Fatalf("facets = %+v, want three agents under license Apache-2.0 and mode autonomous", faceted.Facets)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+only+"&limit=100", nil, &faceted, http.StatusOK)
	if faceted.Facets["license"]["Apache-2.0"] != 1 || faceted.Facets["mode"]["autonomous"] != 1 {
		t.Fatalf("facets for one match = %+v, want one agent", faceted.Facets)
	}
	// An agent with nothing published carries the term too and is no result.
	// A release that stays published under a blocked agent is no result either.
	env.publishSearchable(t, sess, owner, "total-flag", "flagged "+all, "# flag\n")
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agents SET quarantine_state = 'blocked'
		 WHERE name = 'total-flag' AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`, owner); err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "total-draft", "modes": []string{"autonomous"}, "visibility": "public",
		"summary": "unpublished " + all,
	}, nil, http.StatusCreated)
	if h, n := page(all, "limit=100"); h != 3 || n != 3 {
		t.Fatalf("a private, a blocked and an unpublished agent counted: %d hits, total %d; want 3 and 3", h, n)
	}
	// Every filter that narrows the hits narrows the total with them.
	for _, c := range []struct {
		extra string
		want  int
	}{
		{"mode=autonomous", 3}, {"mode=interactive", 0},
		{"license=apache-2.0", 3}, {"license=WTFPL", 0},
		{"capability=network", 0}, {"capability=targetHosts", 0},
	} {
		if h, n := page(all, "limit=100&"+c.extra); h != c.want || n != c.want {
			t.Fatalf("%s: %d hits, total %d; want %d and %d", c.extra, h, n, c.want, c.want)
		}
	}
}
