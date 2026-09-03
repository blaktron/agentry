package api_test

// The §9.2 endpoints the audit found missing — stars and stats, agent
// deletion, the activity feed, tag browsing, webhook ping and the §19 cap,
// ruleset releases, and the platform audit view — plus the §9.1 conventions
// they all inherit.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ---- M-09: stars + stats ----

func TestStarsAndStats(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("star-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "starred", "kind": "skill", "visibility": "public",
	}, nil, http.StatusCreated)

	statsPath := "/api/v1/agents/" + owner + "/starred/stats"
	starPath := "/api/v1/user/stars/" + owner + "/starred"

	// Stats are public and start at zero.
	var stats struct {
		Stars         int64 `json:"stars"`
		InstallsTotal int64 `json:"installsTotal"`
		Installs30d   int64 `json:"installs30d"`
		Starred       *bool `json:"starred"`
	}
	env.doJSON(anonymous, http.MethodGet, statsPath, nil, &stats, http.StatusOK)
	if stats.Stars != 0 || stats.InstallsTotal != 0 || stats.Installs30d != 0 {
		t.Fatalf("fresh agent stats = %+v, want zeros", stats)
	}
	if stats.Starred != nil {
		t.Fatal("anonymous callers have no star of their own to report")
	}

	// Starring is idempotent in both directions (§9.2): a retried PUT or
	// DELETE must not be an error.
	env.doJSON(sess, http.MethodPut, starPath, nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodPut, starPath, nil, nil, http.StatusNoContent)

	env.doJSON(sess, http.MethodGet, statsPath, nil, &stats, http.StatusOK)
	if stats.Stars != 1 {
		t.Fatalf("stars = %d after two PUTs, want 1", stats.Stars)
	}
	if stats.Starred == nil || !*stats.Starred {
		t.Fatal("the caller's own star must be reported")
	}

	env.doJSON(sess, http.MethodDelete, starPath, nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodDelete, starPath, nil, nil, http.StatusNoContent)
	env.doJSON(anonymous, http.MethodGet, statsPath, nil, &stats, http.StatusOK)
	if stats.Stars != 0 {
		t.Fatalf("stars = %d after unstarring, want 0", stats.Stars)
	}

	// Anonymous callers cannot star.
	res := env.do(anonymous, http.MethodPut, starPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous star: got %d want 401", res.StatusCode)
	}
}

func TestStatsAndStarsHidePrivateAgents(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("star-priv")
	env.verifyEmail(owner)
	ownerSess := env.login(owner)
	env.doJSON(ownerSess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "hidden", "kind": "skill", "visibility": "private",
	}, nil, http.StatusCreated)

	outsider := env.register("star-out")
	env.verifyEmail(outsider)
	outSess := env.login(outsider)

	// Existence privacy (§6.4): a stranger gets 404, not 403.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/agents/" + owner + "/hidden/stats"},
		{http.MethodPut, "/api/v1/user/stars/" + owner + "/hidden"},
	} {
		res := env.do(outSess, tc.method, tc.path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s as an outsider: got %d want 404", tc.method, tc.path, res.StatusCode)
		}
	}
}

// ---- M-10a: agent deletion ----

func TestDeleteAgentWithoutVersions(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("del-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "scratch", "kind": "skill",
	}, nil, http.StatusCreated)

	var repoID string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT a.repo_id::text FROM agents a JOIN handles h ON h.id = a.namespace_id
		 WHERE a.name = 'scratch' AND h.handle = $1`, owner).Scan(&repoID); err != nil {
		t.Fatal(err)
	}

	env.doJSON(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/scratch", nil, nil, http.StatusNoContent)

	res := env.do(sess, http.MethodGet, "/api/v1/agents/"+owner+"/scratch", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted agent: got %d want 404", res.StatusCode)
	}
	// The repo row goes with it (§9.2 "create incl. repo" in reverse).
	var repos int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM repos r WHERE r.id = $1::uuid`, repoID,
	).Scan(&repos); err != nil {
		t.Fatal(err)
	}
	if repos != 0 {
		t.Fatal("the repo row outlived the agent it belonged to")
	}
	// And so does the audit trail entry naming it.
	var n int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'agent.delete'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no agent.delete audit event")
	}
}

func TestDeleteAgentRefusedOncePublished(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("del-pub")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "shipped", "kind": "skill", "visibility": "public",
	}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	status, body := env.uploadVersionCLI(owner, "shipped", pat, skillFiles(owner, "shipped", "1.0.0", nil))
	if status != http.StatusAccepted {
		t.Fatalf("publish: %d %s", status, body)
	}
	env.waitStatus(owner, "shipped", "1.0.0", "published")

	res := env.do(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/shipped", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusConflict {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("delete of a published agent: got %d want 409 (%s)", res.StatusCode, raw)
	}
	// The version row must survive: §4.3 forbids deleting it, and installed
	// copies verify against its digest.
	var versions int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM agent_versions av
		 JOIN agents a ON a.id = av.agent_id
		 JOIN handles h ON h.id = a.namespace_id
		 WHERE a.name = 'shipped' AND h.handle = $1`, owner,
	).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 1 {
		t.Fatalf("version rows = %d, want the published row intact", versions)
	}
}

// ---- M-10b: activity ----

func TestAgentActivityPublicVersusFull(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("act-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "watched", "kind": "skill", "visibility": "public",
	}, nil, http.StatusCreated)
	env.doJSON(sess, http.MethodPatch, "/api/v1/agents/"+owner+"/watched",
		map[string]any{"summary": "now with a summary"}, nil, http.StatusOK)

	path := "/api/v1/agents/" + owner + "/watched/activity"

	type activityPage struct {
		Events []struct {
			Action      string          `json:"action"`
			ActorHandle *string         `json:"actorHandle"`
			Detail      *map[string]any `json:"detail"`
		} `json:"events"`
	}

	// The owner sees the full stream, actor and detail included.
	var full activityPage
	env.doJSON(sess, http.MethodGet, path, nil, &full, http.StatusOK)
	sawUpdate := false
	for _, e := range full.Events {
		if e.Action == "agent.update" {
			sawUpdate = true
			if e.ActorHandle == nil || *e.ActorHandle != owner {
				t.Fatalf("full activity must name the actor, got %+v", e.ActorHandle)
			}
			if e.Detail == nil {
				t.Fatal("full activity must carry detail")
			}
		}
	}
	if !sawUpdate {
		t.Fatalf("owner activity is missing agent.update: %+v", full.Events)
	}

	// A stranger sees only the public-safe subset: how the owning team runs
	// the agent is not part of the public record.
	var public activityPage
	env.doJSON(anonymous, http.MethodGet, path, nil, &public, http.StatusOK)
	for _, e := range public.Events {
		if e.Action == "agent.update" || e.Action == "agent.create" {
			t.Fatalf("public activity leaked %s", e.Action)
		}
		if e.ActorHandle != nil || e.Detail != nil {
			t.Fatalf("public activity leaked actor/detail: %+v", e)
		}
	}
}

// ---- M-10c: tags ----

func TestTagListing(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("tag-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "tagged", "kind": "skill", "visibility": "public",
	}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	tag := "t" + env.sfx
	status, body := env.uploadVersionCLI(owner, "tagged", pat,
		skillFiles(owner, "tagged", "1.0.0", []string{tag, "shared-tag"}))
	if status != http.StatusAccepted {
		t.Fatalf("publish: %d %s", status, body)
	}
	env.waitStatus(owner, "tagged", "1.0.0", "published")

	var page struct {
		Tag     string `json:"tag"`
		Results []struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"results"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/tags/"+tag, nil, &page, http.StatusOK)
	if page.Tag != tag {
		t.Fatalf("tag = %q, want %q", page.Tag, tag)
	}
	found := false
	for _, hit := range page.Results {
		if hit.Namespace == owner && hit.Name == "tagged" {
			found = true
		}
	}
	if !found {
		t.Fatalf("tag listing missing the agent: %+v", page.Results)
	}

	// A tag nobody used lists nothing (and does not 404 — an empty tag page
	// is a valid answer).
	env.doJSON(anonymous, http.MethodGet, "/api/v1/tags/nobodyusesthis", nil, &page, http.StatusOK)
	if len(page.Results) != 0 {
		t.Fatalf("unused tag returned %d results", len(page.Results))
	}
}

// ---- M-10d/e + §19: webhooks and ruleset releases ----

func TestWebhookPingAndEndpointCap(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("wh-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "whorg" + env.sfx
	env.createOrg(sess, orgH)

	var created struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
		"url": "https://example.test/hook", "events": []string{"version.published"},
	}, &created, http.StatusCreated)

	// Ping enqueues a real delivery through the ordinary machinery.
	var delivery struct {
		Id        string `json:"id"`
		EventType string `json:"eventType"`
	}
	env.doJSON(sess, http.MethodPost,
		"/api/v1/orgs/"+orgH+"/webhooks/"+created.Id+"/ping", nil, &delivery, http.StatusAccepted)
	if delivery.EventType != "ping" {
		t.Fatalf("ping delivery event = %q, want ping", delivery.EventType)
	}
	var deliveries []struct {
		Id        string `json:"id"`
		EventType string `json:"eventType"`
	}
	env.doJSON(sess, http.MethodGet,
		"/api/v1/orgs/"+orgH+"/webhooks/"+created.Id+"/deliveries", nil, &deliveries, http.StatusOK)
	if len(deliveries) != 1 || deliveries[0].Id != delivery.Id {
		t.Fatalf("ping delivery not in the ledger: %+v", deliveries)
	}

	// §19: 20 endpoints per org. One exists; add 19 more, then expect a
	// refusal rather than an unbounded fan-out surface.
	for i := 1; i < 20; i++ {
		env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
			"url": "https://example.test/hook", "events": []string{"version.published"},
		}, nil, http.StatusCreated)
	}
	res := env.do(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
		"url": "https://example.test/hook", "events": []string{"version.published"},
	})
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("21st webhook: got %d want 409", res.StatusCode)
	}
}

func TestRulesetReleaseAndPlatformAudit(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("rs-user")
	env.verifyEmail(user)
	plain := env.login(user)

	// Platform-staff only.
	res := env.do(plain, http.MethodPost, "/api/v1/platform/ruleset-releases", map[string]any{})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-staff ruleset release: got %d want 403", res.StatusCode)
	}
	res = env.do(plain, http.MethodGet, "/api/v1/platform/audit", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-staff platform audit: got %d want 403", res.StatusCode)
	}

	staffH := env.register("rs-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)

	// An empty body registers the deployment's own embedded bundle (§8.3).
	var rel struct {
		Id           string `json:"id"`
		Semver       string `json:"semver"`
		BundleDigest string `json:"bundleDigest"`
	}
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/ruleset-releases",
		map[string]any{}, &rel, http.StatusOK) // seeded at server start, so it already exists
	if rel.Semver == "" || rel.BundleDigest == "" {
		t.Fatalf("ruleset release is missing its identity: %+v", rel)
	}

	// A new semver registers; re-registering it returns the same row.
	var fresh, again struct {
		Id     string `json:"id"`
		Semver string `json:"semver"`
	}
	body := map[string]any{"semver": "9.9." + env.sfxDigits(), "bundleDigest": "sha256:" + strings.Repeat("ab", 32)}
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/ruleset-releases", body, &fresh, http.StatusCreated)
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/ruleset-releases", body, &again, http.StatusOK)
	if fresh.Id != again.Id {
		t.Fatalf("re-registering a semver made a second row: %s vs %s", fresh.Id, again.Id)
	}

	// The platform audit view spans orgs and records the staff read itself.
	var page struct {
		Events []struct {
			Action string `json:"action"`
		} `json:"events"`
	}
	env.doJSON(staff, http.MethodGet, "/api/v1/platform/audit?limit=200", nil, &page, http.StatusOK)
	sawRelease := false
	for _, e := range page.Events {
		if e.Action == "ruleset.release" {
			sawRelease = true
		}
	}
	if !sawRelease {
		t.Fatal("platform audit is missing the ruleset.release event")
	}
	var reads int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'audit.platform_read'`).Scan(&reads); err != nil {
		t.Fatal(err)
	}
	if reads == 0 {
		t.Fatal("§12.6 requires staff access to the audit log to be audited itself")
	}
}

// ---- §9.1 conventions ----

func TestListParamsAreClampedNotRejected(t *testing.T) {
	env := newTestEnv(t)
	staffH := env.register("clamp-st")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)

	// A negative limit used to reach LIMIT/OFFSET verbatim and 500.
	for _, path := range []string{
		"/api/v1/search?q=&limit=-5",
		"/api/v1/search?q=&limit=99999",
		"/api/v1/search?q=&offset=-3",
		"/api/v1/tags/anything?limit=-1",
	} {
		res := env.do(anonymous, http.MethodGet, path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: got %d want 200", path, res.StatusCode)
		}
	}
	for _, path := range []string{
		"/api/v1/platform/abuse-reports?limit=-1",
		"/api/v1/platform/audit?limit=0",
	} {
		res := env.do(staff, http.MethodGet, path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: got %d want 200", path, res.StatusCode)
		}
	}
}

func TestSearchFacets(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("facet-o")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "faceted", "kind": "skill", "visibility": "public",
		"summary": "facetsearch" + env.sfx,
	}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	status, body := env.uploadVersionCLI(owner, "faceted", pat, skillFiles(owner, "faceted", "1.0.0", nil))
	if status != http.StatusAccepted {
		t.Fatalf("publish: %d %s", status, body)
	}
	env.waitStatus(owner, "faceted", "1.0.0", "published")

	q := "facetsearch" + env.sfx
	type results struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
		Facets map[string]map[string]int `json:"facets"`
	}

	// license= reads the latest published manifest (Apache-2.0 in skillFiles).
	var hit results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&license=Apache-2.0", nil, &hit, http.StatusOK)
	if len(hit.Results) != 1 || hit.Results[0].Name != "faceted" {
		t.Fatalf("license facet lost the agent: %+v", hit.Results)
	}
	if hit.Facets["license"]["Apache-2.0"] == 0 {
		t.Fatalf("license facet counts missing: %+v", hit.Facets)
	}

	// A license nobody declared matches nothing.
	var miss results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&license=WTFPL", nil, &miss, http.StatusOK)
	if len(miss.Results) != 0 {
		t.Fatalf("license=WTFPL matched %d agents", len(miss.Results))
	}

	// verified= keeps only org namespaces with a verified domain; this agent
	// lives in a personal namespace, so it must drop out.
	var ver results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&verified=true", nil, &ver, http.StatusOK)
	if len(ver.Results) != 0 {
		t.Fatalf("verified=true matched an unverified personal namespace: %+v", ver.Results)
	}

	// sort= is accepted and does not change what matches, only the order.
	for _, sort := range []string{"relevance", "installs", "newest"} {
		var sorted results
		env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&sort="+sort, nil, &sorted, http.StatusOK)
		if len(sorted.Results) != 1 {
			t.Fatalf("sort=%s returned %d results, want 1", sort, len(sorted.Results))
		}
	}

	// capability= filters on the declared capability block.
	var caps results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&capability=network", nil, &caps, http.StatusOK)
	if len(caps.Results) != 0 {
		t.Fatalf("capability=network matched an agent that declares none: %+v", caps.Results)
	}
}

func TestRateLimitHeadersOnEveryResponse(t *testing.T) {
	env := newTestEnv(t)
	res := env.do(anonymous, http.MethodGet, "/api/v1/meta", nil)
	defer func() { _ = res.Body.Close() }()
	for _, h := range []string{"RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"} {
		if res.Header.Get(h) == "" {
			t.Fatalf("%s missing from a 200 response (§9.1)", h)
		}
	}
	if res.Header.Get("Retry-After") != "" {
		t.Fatal("Retry-After must appear only when a request is refused")
	}
}

func TestIdempotencyKeyReplaysAndConflicts(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("idem-u")
	env.verifyEmail(user)
	sess := env.login(user)

	key := "idem-" + env.sfx
	body := map[string]any{"handle": "idemorg" + env.sfx, "displayName": "Idem Org"}

	first := env.doWithHeaders(sess, http.MethodPost, "/api/v1/orgs", body,
		map[string]string{"Idempotency-Key": key})
	defer func() { _ = first.Body.Close() }()
	if first.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(first.Body)
		t.Fatalf("first create: got %d want 201 (%s)", first.StatusCode, raw)
	}
	var created struct {
		Id string `json:"id"`
	}
	if err := json.NewDecoder(first.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	// Same key, same body → the recorded response, replayed verbatim. Without
	// this the retry would collide on the handle and surface a 409 for an
	// operation that actually succeeded.
	second := env.doWithHeaders(sess, http.MethodPost, "/api/v1/orgs", body,
		map[string]string{"Idempotency-Key": key})
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("replay: got %d want 201", second.StatusCode)
	}
	if second.Header.Get("Idempotency-Replayed") != "true" {
		t.Fatal("a replayed response must say so")
	}
	var replayed struct {
		Id string `json:"id"`
	}
	if err := json.NewDecoder(second.Body).Decode(&replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.Id != created.Id {
		t.Fatalf("replay returned a different org: %s vs %s", replayed.Id, created.Id)
	}

	// Same key, different body → refuse. The key is a promise about one
	// request; answering with some other request's result would be worse.
	third := env.doWithHeaders(sess, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": "idemtwo" + env.sfx, "displayName": "Other"},
		map[string]string{"Idempotency-Key": key})
	_ = third.Body.Close()
	if third.StatusCode != http.StatusConflict {
		t.Fatalf("key reuse with a different body: got %d want 409", third.StatusCode)
	}

	// A failed request must not lock the key out.
	badKey := "idem-bad-" + env.sfx
	bad := env.doWithHeaders(sess, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": "NOT VALID", "displayName": "x"},
		map[string]string{"Idempotency-Key": badKey})
	_ = bad.Body.Close()
	if bad.StatusCode == http.StatusCreated {
		t.Fatal("an invalid handle must not create an org")
	}
	retry := env.doWithHeaders(sess, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": "idemthree" + env.sfx, "displayName": "Third"},
		map[string]string{"Idempotency-Key": badKey})
	_ = retry.Body.Close()
	if retry.StatusCode != http.StatusCreated {
		t.Fatalf("retry after a failed attempt: got %d want 201", retry.StatusCode)
	}
}

func TestCursorPagingEmitsLinkHeader(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("link-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "linkorg" + env.sfx
	env.createOrg(sess, orgH)
	var created struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
		"url": "https://example.test/hook", "events": []string{"version.published"},
	}, &created, http.StatusCreated)
	for i := 0; i < 3; i++ {
		env.doJSON(sess, http.MethodPost,
			"/api/v1/orgs/"+orgH+"/webhooks/"+created.Id+"/ping", nil, nil, http.StatusAccepted)
	}

	base := "/api/v1/orgs/" + orgH + "/webhooks/" + created.Id + "/deliveries"
	res := env.do(sess, http.MethodGet, base+"?limit=2", nil)
	var firstPage []struct {
		Id string `json:"id"`
	}
	decodeInto(t, res, &firstPage)
	link := res.Header.Get("Link")
	if !strings.Contains(link, `rel="next"`) {
		t.Fatalf("Link header missing rel=next: %q", link)
	}
	if len(firstPage) != 2 {
		t.Fatalf("page 1 has %d rows, want 2", len(firstPage))
	}

	// Following the cursor must not repeat rows.
	cursor := cursorFromLink(t, link)
	res2 := env.do(sess, http.MethodGet, base+"?limit=2&cursor="+cursor, nil)
	var secondPage []struct {
		Id string `json:"id"`
	}
	decodeInto(t, res2, &secondPage)
	if len(secondPage) != 1 {
		t.Fatalf("page 2 has %d rows, want the remaining 1", len(secondPage))
	}
	for _, a := range firstPage {
		if a.Id == secondPage[0].Id {
			t.Fatal("the cursor page repeated a row from page 1")
		}
	}

	// A corrupt cursor is reported, not silently ignored.
	bad := env.do(sess, http.MethodGet, base+"?cursor=not-a-cursor", nil)
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("corrupt cursor: got %d want 422", bad.StatusCode)
	}
}

// ---- M-18: review:act ----

func TestReviewSurfaceRequiresReviewActScope(t *testing.T) {
	env := newTestEnv(t)
	staffH := env.register("rev-st")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	sess := env.login(staffH)

	_, wrongPAT := env.mintPAT(sess, "no-review", "user:profile", "agent:read")
	_, rightPAT := env.mintPAT(sess, "review", "user:profile", "review:act")

	// The role is sufficient (platform staff) but the token is not: §12.3
	// scopes are the least-privilege gate on top of the role.
	res := env.do(caller{name: "pat-wrong", pat: wrongPAT},
		http.MethodGet, "/api/v1/review-queue?queue=platform", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("PAT without review:act: got %d want 403", res.StatusCode)
	}

	res = env.do(caller{name: "pat-right", pat: rightPAT},
		http.MethodGet, "/api/v1/review-queue?queue=platform", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PAT with review:act: got %d want 200", res.StatusCode)
	}

	// A session carries the user's full authority (§12.3): no scope needed.
	res = env.do(sess, http.MethodGet, "/api/v1/review-queue?queue=platform", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session review queue: got %d want 200", res.StatusCode)
	}
}

// GET /platform/ruleset-releases lists the release history for staff and
// refuses everyone else (agentry#63).
func TestRulesetReleaseList(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("rl-user")
	env.verifyEmail(user)
	plain := env.login(user)
	res := env.do(plain, http.MethodGet, "/api/v1/platform/ruleset-releases", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-staff list: got %d want 403", res.StatusCode)
	}
	staffH := env.register("rl-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/ruleset-releases",
		map[string]any{"semver": "9.9.1", "bundleDigest": "sha256:" + strings.Repeat("ab", 32), "notes": "console test"}, nil, http.StatusCreated)
	var list []struct {
		Semver string `json:"semver"`
		Notes  string `json:"notes"`
	}
	env.doJSON(staff, http.MethodGet, "/api/v1/platform/ruleset-releases", nil, &list, http.StatusOK)
	if len(list) == 0 || list[0].Semver != "9.9.1" || list[0].Notes != "console test" {
		t.Fatalf("list: %+v", list)
	}
}
