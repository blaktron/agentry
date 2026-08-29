package api_test

// §10.4 search: the ranking formula and the README's weight-C place in the
// index. Both were claimed and neither was implemented — the ORDER BY was a
// lexicographic tie-break chain that never combined its three factors, and
// readme_text did not exist, so a term appearing only in an agent's README
// (which is where an agent actually describes itself) found nothing.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

type searchHit struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Installs  int64  `json:"installs"`
}

type searchResults struct {
	Results []searchHit `json:"results"`
}

// search runs a query and keeps only the hits in ns, preserving order.
//
// The test database is shared and never truncated, so fixtures from earlier
// runs are still present — and the §10.4 trigram fallback matches on name
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
		"namespace": ns, "name": name, "kind": "skill", "visibility": "public",
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

// §10.4: relevance × log(1+installs_30d) × recency_decay. With relevance and
// recency effectively equal across agents published seconds apart in one test,
// installs is what separates them — and under the old lexicographic ORDER BY
// it could not, because ts_rank was compared first and only ties fell through.
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

	got := names(env.search(t, owner, term))
	want := []string{"popular", "middling", "quiet"}
	if len(got) != 3 {
		t.Fatalf("search returned %v, want the three seeded agents", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ranking = %v, want %v (popularity must order equal-relevance hits)", got, want)
		}
	}
}

// The popularity factor is 1+ln(1+installs), not the literal ln(1+installs)
// §10.4 writes (DEV-030). With no installs the literal expression is 0, and
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
// DEV-030 balance — the +1 must not flatten popularity into irrelevance.
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

// §10.4 weight C. The README is where an agent describes itself; before this
// it was never indexed, so a term appearing only there matched nothing.
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
		t.Fatalf("a README-only term matched %v; §10.4 indexes the readme at weight C", names(got))
	}
}

// Searching a namespace handle finds its agents. The handle is not in
// search_tsv (§10.4 covers name/summary/readme), so this rides the dedicated
// handle clause — the pre-FTS CLI listed by namespace, and m3-cli.sh looks a
// fresh publish up by its random handle.
func TestSearchMatchesNamespaceHandle(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("handle-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	env.publishSearchable(t, sess, owner, "by-handle",
		"a summary that never mentions the namespace",
		"# by-handle\n\nreadme without the namespace either.\n")

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
