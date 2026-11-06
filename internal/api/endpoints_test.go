package api_test

// Endpoints covered here: stars and stats, agent
// deletion, the activity feed, tag browsing, webhook ping and the per-org
// endpoint cap, ruleset releases, and the platform audit view, plus the
// list conventions they all inherit.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
	"github.com/google/uuid"
)

// ---- stars + stats ----

func TestStarsAndStats(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("star-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "starred", "modes": []string{"autonomous"}, "visibility": "public",
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

	// Starring is idempotent in both directions: a retried PUT or
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

	// Stars are per account: a second account's star adds one and its
	// removal takes back that one alone, and a star of another agent is that
	// agent's own.
	otherH := env.register("star-oth")
	env.verifyEmail(otherH)
	otherSess := env.login(otherH)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "starred2", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	env.doJSON(otherSess, http.MethodPut, starPath, nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodPut, "/api/v1/user/stars/"+owner+"/starred2", nil, nil, http.StatusNoContent)
	env.doJSON(anonymous, http.MethodGet, statsPath, nil, &stats, http.StatusOK)
	if stats.Stars != 2 {
		t.Fatalf("stars = %d after two accounts starred, want 2", stats.Stars)
	}
	var stats2 struct {
		Stars int64 `json:"stars"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+owner+"/starred2/stats", nil, &stats2, http.StatusOK)
	if stats2.Stars != 1 {
		t.Fatalf("the other agent's stars = %d, want 1", stats2.Stars)
	}
	env.doJSON(otherSess, http.MethodDelete, starPath, nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodGet, statsPath, nil, &stats, http.StatusOK)
	if stats.Stars != 1 || stats.Starred == nil || !*stats.Starred {
		t.Fatalf("after the other account unstarred: %+v, want the first account's star alone", stats)
	}
	env.doJSON(otherSess, http.MethodGet, statsPath, nil, &stats, http.StatusOK)
	if stats.Stars != 1 || stats.Starred == nil || *stats.Starred {
		t.Fatalf("the account that unstarred is told %+v, want one star and none of its own", stats)
	}

	env.doJSON(sess, http.MethodDelete, starPath, nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodDelete, starPath, nil, nil, http.StatusNoContent)
	env.doJSON(anonymous, http.MethodGet, statsPath, nil, &stats, http.StatusOK)
	if stats.Stars != 0 {
		t.Fatalf("stars = %d after unstarring, want 0", stats.Stars)
	}
	env.doJSON(sess, http.MethodGet, statsPath, nil, &stats, http.StatusOK)
	if stats.Starred == nil || *stats.Starred {
		t.Fatalf("starred = %v after unstarring, want false", stats.Starred)
	}

	// Each change is audited once: a removal that removed nothing is not an
	// event.
	var stars, unstars int
	for _, a := range env.activityActions(t, sess) {
		switch a {
		case "agent.star":
			stars++
		case "agent.unstar":
			unstars++
		}
	}
	if stars == 0 || unstars != 1 {
		t.Fatalf("activity holds %d star and %d unstar events, want some and exactly one", stars, unstars)
	}

	// Anonymous callers cannot star.
	res := env.do(anonymous, http.MethodPut, starPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous star: got %d want 401", res.StatusCode)
	}
	res = env.do(anonymous, http.MethodDelete, starPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous unstar: got %d want 401", res.StatusCode)
	}
}

func TestStatsAndStarsHidePrivateAgents(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("star-priv")
	env.verifyEmail(owner)
	ownerSess := env.login(owner)
	env.doJSON(ownerSess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "hidden", "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)

	outsider := env.register("star-out")
	env.verifyEmail(outsider)
	outSess := env.login(outsider)

	// Existence privacy: a stranger gets 404, not 403.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/agents/" + owner + "/hidden/stats"},
		{http.MethodPut, "/api/v1/user/stars/" + owner + "/hidden"},
		{http.MethodDelete, "/api/v1/user/stars/" + owner + "/hidden"},
	} {
		res := env.do(outSess, tc.method, tc.path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s as an outsider: got %d want 404", tc.method, tc.path, res.StatusCode)
		}
	}
	res := env.do(anonymous, http.MethodGet, "/api/v1/agents/"+owner+"/hidden/stats", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("stats of a private agent as anonymous: got %d want 404", res.StatusCode)
	}
}

// ---- agent deletion ----

func TestDeleteAgentWithoutVersions(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("del-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "scratch", "modes": []string{"autonomous"},
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
	// The repo row goes with it, the reverse of create.
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

// ---- activity ----

func TestAgentActivityPublicVersusFull(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("act-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "watched", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	env.doJSON(sess, http.MethodPatch, "/api/v1/agents/"+owner+"/watched",
		map[string]any{"summary": "now with a summary"}, nil, http.StatusOK)

	path := "/api/v1/agents/" + owner + "/watched/activity"

	type activityPage struct {
		Events []struct {
			Action      string          `json:"action"`
			ActorHandle *string         `json:"actorHandle"`
			Detail      *map[string]any `json:"detail"`
			Version     *string         `json:"version"`
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

	// What a consumer needs to judge the package stays public: a release's
	// publication. The steps before it (submission, scanning, review) are
	// how the pipeline ran, and only the owning team sees them.
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	if status, body := env.uploadVersionCLI(owner, "watched", pat, skillFiles(owner, "watched", "1.0.0", nil)); status != http.StatusAccepted {
		t.Fatalf("publish: %d %s", status, body)
	}
	env.waitStatus(owner, "watched", "1.0.0", "published")
	env.doJSON(sess, http.MethodGet, path, nil, &full, http.StatusOK)
	env.doJSON(anonymous, http.MethodGet, path, nil, &public, http.StatusOK)
	count := func(p activityPage, action string) int {
		n := 0
		for _, e := range p.Events {
			if e.Action == action {
				n++
			}
		}
		return n
	}
	if got := count(public, "version.transition"); got != 1 {
		t.Fatalf("public activity holds %d version.transition events, want the one publication: %+v", got, public.Events)
	}
	if fullN, publicN := count(full, "version.transition"), count(public, "version.transition"); fullN <= publicN {
		t.Fatalf("the owner sees %d version.transition events and the public %d; the pipeline's own steps are the owner's alone", fullN, publicN)
	}
	for _, e := range public.Events {
		if e.Version == nil || *e.Version != "1.0.0" {
			t.Fatalf("a public event names no version: %+v", e)
		}
	}
}

// ---- tags ----

func TestTagListing(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("tag-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "tagged", "modes": []string{"autonomous"}, "visibility": "public",
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

	// The tag is read in lower case whatever case is asked for.
	env.doJSON(anonymous, http.MethodGet, "/api/v1/tags/"+strings.ToUpper(tag), nil, &page, http.StatusOK)
	if page.Tag != tag || len(page.Results) != 1 || page.Results[0].Name != "tagged" {
		t.Fatalf("tag in upper case: %q %+v, want %q and the agent", page.Tag, page.Results, tag)
	}

	// Only what anyone could install is listed: a private agent and a blocked
	// one carry the tag and are not listed; a second public agent is, newest
	// first, and a hit says what the search says of it.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "tagpriv", "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "tagblock", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "tagged2", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	for _, name := range []string{"tagpriv", "tagblock", "tagged2"} {
		env.publishVersions(t, sess, owner, name, []versionFiles{
			{"1.0.0", skillFiles(owner, name, "1.0.0", []string{tag})},
		})
	}
	staffH := env.register("tag-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	env.doJSON(env.login(staffH), http.MethodPost, "/api/v1/platform/agents/"+owner+"/tagblock/block",
		map[string]any{"reason": "fixture"}, nil, http.StatusNoContent)
	type tagPage struct {
		Tag     string `json:"tag"`
		Results []struct {
			Name            string   `json:"name"`
			Modes           []string `json:"modes"`
			QuarantineState *string  `json:"quarantineState"`
			Installs30d     *int     `json:"installs30d"`
		} `json:"results"`
	}
	tagListed := func(hits []struct {
		Name            string   `json:"name"`
		Modes           []string `json:"modes"`
		QuarantineState *string  `json:"quarantineState"`
		Installs30d     *int     `json:"installs30d"`
	}, name string) bool {
		for _, h := range hits {
			if h.Name == name {
				return true
			}
		}
		return false
	}
	var listed tagPage
	env.doJSON(anonymous, http.MethodGet, "/api/v1/tags/"+tag, nil, &listed, http.StatusOK)
	var listedNames []string
	for _, hit := range listed.Results {
		listedNames = append(listedNames, hit.Name)
	}
	// A blocked agent that kept its release, and an agent of an organization
	// that is suspended, are not listed either; space around the tag is not
	// part of it.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "tagflag", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	env.publishVersions(t, sess, owner, "tagflag", []versionFiles{
		{"1.0.0", skillFiles(owner, "tagflag", "1.0.0", []string{tag})},
	})
	tagOrg := "tagorg" + env.sfx
	tagOrgID := env.createOrg(sess, tagOrg)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": tagOrg, "name": "tagorgagent", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	env.publishVersions(t, sess, tagOrg, "tagorgagent", []versionFiles{
		{"1.0.0", skillFiles(tagOrg, "tagorgagent", "1.0.0", []string{tag})},
	})
	for _, name := range []string{"tagorgagent", "tagged2"} {
		var p tagPage
		env.doJSON(anonymous, http.MethodGet, "/api/v1/tags/%20"+tag+"%20", nil, &p, http.StatusOK)
		if p.Tag != tag || !tagListed(p.Results, name) {
			t.Fatalf("a tag with space around it: %q %v, want %q listing %s", p.Tag, p.Results, tag, name)
		}
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agents SET quarantine_state = 'blocked' WHERE name = 'tagflag' AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE orgs SET state = 'suspended' WHERE id = $1::uuid`, tagOrgID); err != nil {
		t.Fatal(err)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/tags/"+tag, nil, &listed, http.StatusOK)
	listedNames = listedNames[:0]
	for _, hit := range listed.Results {
		listedNames = append(listedNames, hit.Name)
	}
	if !reflect.DeepEqual(listedNames, []string{"tagged2", "tagged"}) {
		t.Fatalf("tag listing = %v, want the two public agents, newest first", listedNames)
	}
	if h := listed.Results[0]; !reflect.DeepEqual(h.Modes, []string{"autonomous"}) || h.QuarantineState == nil || *h.QuarantineState != "none" || h.Installs30d == nil || *h.Installs30d != 0 {
		t.Fatalf("tag hit = %+v", h)
	}

	// Paging follows the cursor: a full page carries the next link, the last
	// page none.
	res := env.do(anonymous, http.MethodGet, "/api/v1/tags/"+tag+"?limit=1", nil)
	var first, second tagPage
	decodeInto(t, res, &first)
	if len(first.Results) != 1 || first.Results[0].Name != "tagged2" || !strings.Contains(res.Header.Get("Link"), `rel="next"`) {
		t.Fatalf("first page = %+v, Link %q", first.Results, res.Header.Get("Link"))
	}
	res = env.do(anonymous, http.MethodGet, "/api/v1/tags/"+tag+"?limit=1&cursor="+cursorFromLink(t, res.Header.Get("Link")), nil)
	decodeInto(t, res, &second)
	if len(second.Results) != 1 || second.Results[0].Name != "tagged" {
		t.Fatalf("second page = %+v", second.Results)
	}
	res = env.do(anonymous, http.MethodGet, "/api/v1/tags/"+tag+"?limit=5", nil)
	decodeInto(t, res, &second)
	if len(second.Results) != 2 || res.Header.Get("Link") != "" {
		t.Fatalf("a short page = %+v, Link %q", second.Results, res.Header.Get("Link"))
	}
}

// ---- webhooks and ruleset releases ----

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
	// The ping is audited with the delivery it made.
	var pingAudited int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'webhook.ping' AND target_id = $1::uuid AND detail->>'deliveryId' = $2`,
		created.Id, delivery.Id).Scan(&pingAudited); err != nil {
		t.Fatal(err)
	}
	if pingAudited != 1 {
		t.Fatalf("the ping was audited %d times, want once, naming its delivery", pingAudited)
	}
	var requestedBy string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT payload->'data'->>'requestedBy' FROM webhook_deliveries WHERE id = $1::uuid`, delivery.Id).Scan(&requestedBy); err != nil {
		t.Fatal(err)
	}
	if requestedBy != owner {
		t.Fatalf("the ping payload names requester %q, want %s", requestedBy, owner)
	}
	// An endpoint is reached through its own organization only.
	strangerH := env.register("wh-str")
	env.verifyEmail(strangerH)
	stranger := env.login(strangerH)
	otherOrg := "whother" + env.sfx
	env.createOrg(stranger, otherOrg)
	for _, path := range []string{"/ping", "/deliveries"} {
		method := http.MethodPost
		if path == "/deliveries" {
			method = http.MethodGet
		}
		res := env.do(stranger, method, "/api/v1/orgs/"+otherOrg+"/webhooks/"+created.Id+path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s of another organization's endpoint: got %d want 404", path, res.StatusCode)
		}
	}
	var deliveries []struct {
		Id        string `json:"id"`
		EventType string `json:"eventType"`
		Attempt   int    `json:"attempt"`
	}
	env.doJSON(sess, http.MethodGet,
		"/api/v1/orgs/"+orgH+"/webhooks/"+created.Id+"/deliveries", nil, &deliveries, http.StatusOK)
	if len(deliveries) != 1 || deliveries[0].Id != delivery.Id {
		t.Fatalf("ping delivery not in the ledger: %+v", deliveries)
	}
	// The ledger says how many times a delivery was attempted.
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE webhook_deliveries SET attempt = 3 WHERE id = $1::uuid`, delivery.Id); err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodGet,
		"/api/v1/orgs/"+orgH+"/webhooks/"+created.Id+"/deliveries", nil, &deliveries, http.StatusOK)
	if len(deliveries) != 1 || deliveries[0].Attempt != 3 {
		t.Fatalf("delivery attempts in the ledger: %+v", deliveries)
	}

	// 20 endpoints per org. One exists; add 19 more, then expect a
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
	refusal, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(refusal), "maximum of 20 webhook endpoints") {
		t.Fatalf("the refusal does not name the maximum: %s", refusal)
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
	res = env.do(anonymous, http.MethodPost, "/api/v1/platform/ruleset-releases", map[string]any{})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous ruleset release: got %d want 401", res.StatusCode)
	}

	staffH := env.register("rs-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)

	// An empty body registers the deployment's own embedded bundle.
	var rel struct {
		Id           string  `json:"id"`
		Semver       string  `json:"semver"`
		BundleDigest string  `json:"bundleDigest"`
		Notes        *string `json:"notes"`
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

	// A new semver queues the catalogue's re-check, one job of each kind,
	// and registering it again queues nothing more. The registration is
	// audited with what it registered.
	ctx := context.Background()
	var queued, audited int
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM river_job WHERE kind IN ('scan.rescan_sweep', 'scan.redo_review_queue') AND args->>'rulesetSemver' = $1`,
		fresh.Semver).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 2 {
		t.Fatalf("%d re-check jobs queued for the new semver, want a rescan sweep and a review queue redo", queued)
	}
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'ruleset.release' AND detail->>'semver' = $1 AND detail->>'bundleDigest' = $2`,
		fresh.Semver, body["bundleDigest"]).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("the registration was audited %d times, want once", audited)
	}

	// A semver is MAJOR.MINOR.PATCH, with an optional pre-release or build
	// suffix; anything else is refused.
	for _, bad := range []string{"1.2", "v1.2.3", "1.2.3.4", "x1.2.3", "1.2.3 4", "1.2.3_rc"} {
		res := env.do(staff, http.MethodPost, "/api/v1/platform/ruleset-releases",
			map[string]any{"semver": bad, "bundleDigest": body["bundleDigest"]})
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("semver %q: got %d want 422", bad, res.StatusCode)
		}
	}
	for _, suffix := range []string{"-rc.1", "+build.5"} {
		env.doJSON(staff, http.MethodPost, "/api/v1/platform/ruleset-releases",
			map[string]any{"semver": "9.8." + env.sfxDigits() + suffix, "bundleDigest": body["bundleDigest"]}, nil, http.StatusCreated)
	}
	// Space around a semver is not part of it.
	var padded struct {
		Semver       string `json:"semver"`
		BundleDigest string `json:"bundleDigest"`
	}
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/ruleset-releases",
		map[string]any{"semver": "  9.6." + env.sfxDigits() + "  ", "bundleDigest": "  " + body["bundleDigest"].(string) + "  "}, &padded, http.StatusCreated)
	if padded.Semver != "9.6."+env.sfxDigits() || padded.BundleDigest != body["bundleDigest"] {
		t.Fatalf("a padded semver and digest were registered as %q and %q", padded.Semver, padded.BundleDigest)
	}

	// Naming only a semver registers the deployment's own bundle under it;
	// naming only a digest names the deployment's own semver, which is
	// registered already and answers its row.
	var partial struct {
		Semver       string  `json:"semver"`
		BundleDigest string  `json:"bundleDigest"`
		Notes        *string `json:"notes"`
	}
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/ruleset-releases",
		map[string]any{"semver": "9.7." + env.sfxDigits()}, &partial, http.StatusCreated)
	if partial.BundleDigest != rel.BundleDigest || partial.Notes == nil || rel.Notes == nil || *partial.Notes != *rel.Notes || *partial.Notes == "" {
		t.Fatalf("a semver alone: %+v, want the deployment's own digest %s and notes", partial, rel.BundleDigest)
	}
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/ruleset-releases",
		map[string]any{"bundleDigest": "sha256:" + strings.Repeat("cd", 32)}, &partial, http.StatusOK)
	if partial.Semver != rel.Semver || partial.BundleDigest != rel.BundleDigest {
		t.Fatalf("a digest alone: %+v, want the deployment's own row %+v", partial, rel)
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
		t.Fatal("staff access to the audit log must be audited itself")
	}
	res = env.do(anonymous, http.MethodGet, "/api/v1/platform/audit", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous platform audit: got %d want 401", res.StatusCode)
	}

	// The view filters by action and by organization, newest first and by
	// cursor, and each read records the filters it was given.
	type auditPage struct {
		Events []struct {
			Action      string  `json:"action"`
			ActorHandle *string `json:"actorHandle"`
		} `json:"events"`
		NextCursor *string `json:"nextCursor"`
	}
	orgH := "auditorg" + env.sfx
	env.createOrg(plain, orgH)
	env.doJSON(plain, http.MethodPatch, "/api/v1/orgs/"+orgH, map[string]any{"displayName": "Renamed"}, nil, http.StatusOK)
	var byAction, byOrg, both auditPage
	env.doJSON(staff, http.MethodGet, "/api/v1/platform/audit?action=ruleset.release&limit=200", nil, &byAction, http.StatusOK)
	if len(byAction.Events) == 0 {
		t.Fatal("no ruleset.release events under the action filter")
	}
	for _, e := range byAction.Events {
		if e.Action != "ruleset.release" {
			t.Fatalf("the action filter let %s through", e.Action)
		}
	}
	if a := byAction.Events[0].ActorHandle; a == nil || *a != staffH {
		t.Fatalf("the newest ruleset.release event names actor %v, want %s", a, staffH)
	}
	env.doJSON(staff, http.MethodGet, "/api/v1/platform/audit?org="+orgH+"&limit=200", nil, &byOrg, http.StatusOK)
	if len(byOrg.Events) == 0 {
		t.Fatal("no events under the organization filter")
	}
	for _, e := range byOrg.Events {
		if e.Action == "ruleset.release" {
			t.Fatalf("the organization filter let a platform event through: %s", e.Action)
		}
	}
	env.doJSON(staff, http.MethodGet, "/api/v1/platform/audit?org="+orgH+"&action=ruleset.release", nil, &both, http.StatusOK)
	if len(both.Events) != 0 {
		t.Fatalf("an organization with no ruleset events has %d of them", len(both.Events))
	}
	readsBefore := platformReads(t, env)
	res = env.do(staff, http.MethodGet, "/api/v1/platform/audit?org=no-such-org-"+env.sfx, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("audit of an unknown organization: got %d want 404", res.StatusCode)
	}
	if got := platformReads(t, env); got != readsBefore {
		t.Fatalf("a refused read was audited: %d platform reads before, %d after", readsBefore, got)
	}
	var full, one, two auditPage
	resFull := env.do(staff, http.MethodGet, "/api/v1/platform/audit?org="+orgH+"&limit=100", nil)
	decodeInto(t, resFull, &full)
	if full.NextCursor != nil || resFull.Header.Get("Link") != "" || len(full.Events) < 2 {
		t.Fatalf("a page holding everything: %d events, next %v, Link %q", len(full.Events), full.NextCursor, resFull.Header.Get("Link"))
	}
	resOne := env.do(staff, http.MethodGet, "/api/v1/platform/audit?org="+orgH+"&limit=1", nil)
	decodeInto(t, resOne, &one)
	if len(one.Events) != 1 || one.NextCursor == nil || !strings.Contains(resOne.Header.Get("Link"), `rel="next"`) || one.Events[0].Action != full.Events[0].Action {
		t.Fatalf("first page of one: %+v next %v Link %q", one.Events, one.NextCursor, resOne.Header.Get("Link"))
	}
	resTwo := env.do(staff, http.MethodGet, "/api/v1/platform/audit?org="+orgH+"&limit=1&cursor="+*one.NextCursor, nil)
	decodeInto(t, resTwo, &two)
	if len(two.Events) != 1 || two.Events[0].Action != full.Events[1].Action {
		t.Fatalf("second page of one: %+v, want the feed's second event %s", two.Events, full.Events[1].Action)
	}
	var recorded int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'audit.platform_read'
		   AND detail->>'action' = 'ruleset.release' AND detail->>'org' = $1 AND detail->>'limit' = '50'`, orgH).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 {
		t.Fatalf("the read with both filters was recorded %d times, want once, with the filters and the page size", recorded)
	}
}

// ---- list conventions ----

// platformReads counts the staff reads of the platform audit log recorded so
// far.
func platformReads(t *testing.T, env *testEnv) int {
	t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'audit.platform_read'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestListParamsAreClampedNotRejected(t *testing.T) {
	env := newTestEnv(t)
	staffH := env.register("clamp-st")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)

	// A negative limit must not reach LIMIT/OFFSET verbatim (a 500).
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

// enumRefusal reads a refusal of a value outside an enum: its status and
// the field the problem names.
func enumRefusal(t *testing.T, res *http.Response) (int, string) {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	var p struct {
		Type   string `json:"type"`
		Errors []struct {
			Field string `json:"field"`
		} `json:"errors"`
	}
	_ = json.NewDecoder(res.Body).Decode(&p)
	if !strings.HasSuffix(p.Type, "/validation") || len(p.Errors) != 1 {
		return res.StatusCode, ""
	}
	return res.StatusCode, p.Errors[0].Field
}

// A value outside the enum the contract gives a parameter or field is the
// caller's error: 422 naming the field, never a 500 and never a filter
// silently ignored. A value inside it is still taken.
func TestAValueOutsideAnEnumIsRefused(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("enum-o")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "enumed", "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)
	staffH := env.register("enum-st")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)

	for _, c := range []struct {
		who         caller
		path, field string
	}{
		{anonymous, "/api/v1/agents?namespace=" + owner + "&state=gone", "state"},
		{anonymous, "/api/v1/agents?namespace=" + owner + "&forks=some", "forks"},
		{anonymous, "/api/v1/agents?namespace=" + owner + "&sort=popular", "sort"},
		{anonymous, "/api/v1/search?q=&sort=popular", "sort"},
		{staff, "/api/v1/platform/abuse-reports?state=closed", "state"},
	} {
		if code, field := enumRefusal(t, env.do(c.who, http.MethodGet, c.path, nil)); code != http.StatusUnprocessableEntity || field != c.field {
			t.Fatalf("GET %s: %d naming %q, want 422 naming %q", c.path, code, field, c.field)
		}
	}
	for _, c := range []struct {
		who  caller
		path string
	}{
		{anonymous, "/api/v1/agents?namespace=" + owner + "&state=retired"},
		{anonymous, "/api/v1/agents?namespace=" + owner + "&forks=only"},
		{anonymous, "/api/v1/agents?namespace=" + owner + "&sort=submitted"},
		{anonymous, "/api/v1/search?q=&sort=newest"},
		{anonymous, "/api/v1/search?q=&sort="},
		{staff, "/api/v1/platform/abuse-reports?state=dismissed"},
	} {
		res := env.do(c.who, http.MethodGet, c.path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: got %d want 200", c.path, res.StatusCode)
		}
	}

	path := "/api/v1/agents/" + owner + "/enumed"
	if code, field := enumRefusal(t, env.do(sess, http.MethodPatch, path, map[string]any{"visibility": "unlisted"})); code != http.StatusUnprocessableEntity || field != "visibility" {
		t.Fatalf("PATCH visibility unlisted: %d naming %q, want 422 naming visibility", code, field)
	}
	var got struct {
		Visibility string `json:"visibility"`
	}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Visibility != "private" {
		t.Fatalf("a refused visibility changed the agent to %q", got.Visibility)
	}
}

func TestSearchFacets(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("facet-o")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "faceted", "modes": []string{"autonomous"}, "visibility": "public",
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
			Name            string   `json:"name"`
			Summary         string   `json:"summary"`
			Modes           []string `json:"modes"`
			QuarantineState *string  `json:"quarantineState"`
			Builtin         bool     `json:"builtin"`
			Installs30d     *int     `json:"installs30d"`
		} `json:"results"`
		Facets map[string]map[string]int `json:"facets"`
		Total  *int                      `json:"total"`
	}
	has := func(r results, name string) bool {
		for _, h := range r.Results {
			if h.Name == name {
				return true
			}
		}
		return false
	}

	// A public agent with nothing published is not a result, and is not
	// counted by a facet either: the mode count matches the total.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "faceted-empty", "modes": []string{"autonomous"}, "visibility": "public",
		"summary": q,
	}, nil, http.StatusCreated)
	var all results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q, nil, &all, http.StatusOK)
	if has(all, "faceted-empty") || all.Total == nil || *all.Total != 1 || all.Facets["mode"]["autonomous"] != 1 {
		t.Fatalf("an agent with nothing published: results %+v, total %v, mode facet %+v; want one result counted once", all.Results, all.Total, all.Facets["mode"])
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
	if hit.Facets["license"]["Apache-2.0"] != 1 || hit.Facets["mode"]["autonomous"] != 1 {
		t.Fatalf("facet counts for the query: %+v, want one agent under license Apache-2.0 and mode autonomous", hit.Facets)
	}
	// A hit says what the agent is.
	if h := hit.Results[0]; h.Summary != q || !reflect.DeepEqual(h.Modes, []string{"autonomous"}) || h.QuarantineState == nil || *h.QuarantineState != "none" ||
		h.Builtin || h.Installs30d == nil || *h.Installs30d != 0 {
		t.Fatalf("search hit = %+v", h)
	}
	// The license is compared without regard to case or the space around it.
	for _, lic := range []string{"apache-2.0", "%20Apache-2.0%20"} {
		var folded results
		env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&license="+lic, nil, &folded, http.StatusOK)
		if len(folded.Results) != 1 {
			t.Fatalf("license=%s matched %d agents, want 1", lic, len(folded.Results))
		}
	}
	// The run mode filters: the agent supports autonomous and not interactive.
	var byMode results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&mode=autonomous", nil, &byMode, http.StatusOK)
	if len(byMode.Results) != 1 {
		t.Fatalf("mode=autonomous matched %d agents, want 1", len(byMode.Results))
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&mode=interactive", nil, &byMode, http.StatusOK)
	if len(byMode.Results) != 0 {
		t.Fatalf("mode=interactive matched %d agents, want 0", len(byMode.Results))
	}

	// A license nobody declared matches nothing.
	var miss results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&license=WTFPL", nil, &miss, http.StatusOK)
	if len(miss.Results) != 0 {
		t.Fatalf("license=WTFPL matched %d agents", len(miss.Results))
	}
	// The facets describe the query, not the filter: the licence that
	// matched nothing still shows what the query would find.
	if miss.Facets["license"]["Apache-2.0"] != 1 {
		t.Fatalf("facets under a filter that matched nothing: %+v", miss.Facets)
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

	// A capability stored as null, or as an object whose members are all
	// null, is not one the agent asks for.
	for _, c := range []string{"exec", "filesystem"} {
		env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&capability="+c, nil, &caps, http.StatusOK)
		if len(caps.Results) != 0 {
			t.Fatalf("capability=%s matched an agent that declares none: %+v", c, caps.Results)
		}
	}

	// capability=targetHosts matches only a release that declares a target
	// host, and a target host is not network egress.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "facethost", "modes": []string{"autonomous"}, "visibility": "public",
		"summary": q,
	}, nil, http.StatusCreated)
	files := skillFiles(owner, "facethost", "1.0.0", nil)
	files["agent.yaml"] += `intake:
  - id: server
    prompt: "The server to set up"
    type: host
    required: true
capabilities:
  targetHosts: [server]
`
	status, body = env.uploadVersionCLI(owner, "facethost", pat, files)
	if status != http.StatusAccepted {
		t.Fatalf("publish a target host release: %d %s", status, body)
	}
	env.waitStatus(owner, "facethost", "1.0.0", "published")
	var hosts results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&capability=targetHosts", nil, &hosts, http.StatusOK)
	if len(hosts.Results) != 1 || hosts.Results[0].Name != "facethost" {
		t.Fatalf("capability=targetHosts = %+v; want facethost alone", hosts.Results)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&capability=network", nil, &caps, http.StatusOK)
	if len(caps.Results) != 0 {
		t.Fatalf("capability=network matched a target host release: %+v", caps.Results)
	}

	// capability=browser matches only a release that declares a browser,
	// and a browser is not network egress. A site-scoped browser publishes
	// under the baseline.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "facetbrowser", "modes": []string{"autonomous"}, "visibility": "public",
		"summary": q,
	}, nil, http.StatusCreated)
	files = skillFiles(owner, "facetbrowser", "1.0.0", nil)
	files["agent.yaml"] += `intake:
  - id: site
    prompt: "Which site should I test?"
    type: url
    required: true
capabilities:
  browser:
    sites: [site]
    hosts: [fonts.googleapis.com]
`
	status, body = env.uploadVersionCLI(owner, "facetbrowser", pat, files)
	if status != http.StatusAccepted {
		t.Fatalf("publish a browser release: %d %s", status, body)
	}
	env.waitStatus(owner, "facetbrowser", "1.0.0", "published")
	var browsers results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&capability=browser", nil, &browsers, http.StatusOK)
	if len(browsers.Results) != 1 || browsers.Results[0].Name != "facetbrowser" {
		t.Fatalf("capability=browser = %+v; want facetbrowser alone", browsers.Results)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&capability=network", nil, &caps, http.StatusOK)
	if len(caps.Results) != 0 {
		t.Fatalf("capability=network matched a browser release: %+v", caps.Results)
	}

	// capability=desktop matches only a release that uses the person's own
	// computer, which publishes under the baseline.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "facetdesktop", "modes": []string{"autonomous"}, "visibility": "public",
		"summary": q,
	}, nil, http.StatusCreated)
	files = skillFiles(owner, "facetdesktop", "1.0.0", nil)
	files["agent.yaml"] += `capabilities:
  desktop:
    servers:
      - id: blender
        tools: [get_scene_info, look]
    computerUse: app
`
	status, body = env.uploadVersionCLI(owner, "facetdesktop", pat, files)
	if status != http.StatusAccepted {
		t.Fatalf("publish a desktop release: %d %s", status, body)
	}
	env.waitStatus(owner, "facetdesktop", "1.0.0", "published")
	var desktops results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&capability=desktop", nil, &desktops, http.StatusOK)
	if len(desktops.Results) != 1 || desktops.Results[0].Name != "facetdesktop" {
		t.Fatalf("capability=desktop = %+v; want facetdesktop alone", desktops.Results)
	}

	// capability=network matches the release that declares network egress, and
	// only that one, however the capability is spaced.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "facetnet", "modes": []string{"autonomous"}, "visibility": "public",
		"summary": q,
	}, nil, http.StatusCreated)
	status, body = env.uploadVersionCLI(owner, "facetnet", pat, installCapsFiles(owner, "facetnet", "1.0.0", []string{"api.example"}, nil))
	if status != http.StatusAccepted {
		t.Fatalf("publish a network release: %d %s", status, body)
	}
	env.waitStatus(owner, "facetnet", "1.0.0", "published")
	for _, c := range []string{"network", "%20network%20"} {
		var nets results
		env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&capability="+c, nil, &nets, http.StatusOK)
		if len(nets.Results) != 1 || nets.Results[0].Name != "facetnet" {
			t.Fatalf("capability=%s = %+v; want facetnet alone", c, nets.Results)
		}
	}

	// A built-in agent says so.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agents SET builtin = true WHERE name = 'facetnet' AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`, owner); err != nil {
		t.Fatal(err)
	}
	var builtin results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&capability=network", nil, &builtin, http.StatusOK)
	if len(builtin.Results) != 1 || !builtin.Results[0].Builtin {
		t.Fatalf("a built-in agent in search: %+v", builtin.Results)
	}

	// verified= keeps an organization's agent once the organization has a
	// verified domain; an organization that is suspended or erased is absent
	// from search, and one in its decommission hold is read.
	orgH := "facetorg" + env.sfx
	orgID := env.createOrg(sess, orgH)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": orgH, "name": "facetorgagent", "modes": []string{"autonomous"}, "visibility": "public",
		"summary": q,
	}, nil, http.StatusCreated)
	status, body = env.uploadVersionCLI(orgH, "facetorgagent", pat, skillFiles(orgH, "facetorgagent", "1.0.0", nil))
	if status != http.StatusAccepted {
		t.Fatalf("publish an organization's release: %d %s", status, body)
	}
	env.waitStatus(orgH, "facetorgagent", "1.0.0", "published")
	var orgs results
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&verified=true", nil, &orgs, http.StatusOK)
	if len(orgs.Results) != 0 || orgs.Total == nil || *orgs.Total != 0 {
		t.Fatalf("verified=true matched an organization with no verified domain: %+v total %v", orgs.Results, orgs.Total)
	}
	// A domain claimed and not yet proved is no verification.
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO domain_claims (id, org_id, domain, verification_token) VALUES (gen_random_uuid(), $1::uuid, $2, 'pending')`,
		orgID, "pending"+env.sfx+".example.test"); err != nil {
		t.Fatal(err)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&verified=true", nil, &orgs, http.StatusOK)
	if len(orgs.Results) != 0 || orgs.Total == nil || *orgs.Total != 0 {
		t.Fatalf("verified=true matched an organization whose only claim is unproved: %+v total %v", orgs.Results, orgs.Total)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q, nil, &orgs, http.StatusOK)
	if !has(orgs, "facetorgagent") {
		t.Fatalf("an active organization's agent is missing from search: %+v", orgs.Results)
	}
	env.verifyOrgDomain(orgH, "facet"+env.sfx+".example.test")
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q+"&verified=true", nil, &orgs, http.StatusOK)
	if len(orgs.Results) != 1 || orgs.Results[0].Name != "facetorgagent" || orgs.Total == nil || *orgs.Total != 1 {
		t.Fatalf("verified=true = %+v total %v; want the verified organization's agent alone", orgs.Results, orgs.Total)
	}
	for state, listed := range map[string]bool{"decommissioning": true, "suspended": false} {
		if _, err := env.st.Pool().Exec(context.Background(), `UPDATE orgs SET state = $2 WHERE id = $1::uuid`, orgID, state); err != nil {
			t.Fatal(err)
		}
		env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+q, nil, &orgs, http.StatusOK)
		if has(orgs, "facetorgagent") != listed {
			t.Fatalf("an organization that is %s: its agent listed = %v, want %v", state, has(orgs, "facetorgagent"), listed)
		}
		if orgs.Total == nil || *orgs.Total != len(orgs.Results) {
			t.Fatalf("an organization that is %s: total %v does not count the %d listed hits", state, orgs.Total, len(orgs.Results))
		}
	}
}

func TestRateLimitHeadersOnEveryResponse(t *testing.T) {
	env := newTestEnv(t)
	res := env.do(anonymous, http.MethodGet, "/api/v1/meta", nil)
	defer func() { _ = res.Body.Close() }()
	for _, h := range []string{"RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"} {
		if res.Header.Get(h) == "" {
			t.Fatalf("%s missing from a 200 response", h)
		}
	}
	if res.Header.Get("Retry-After") != "" {
		t.Fatal("Retry-After must appear only when a request is refused")
	}
	// The numbers: the anonymous class's whole budget less this request, and
	// at least a second until the next token.
	if got := res.Header.Get("RateLimit-Limit"); got != "100000" {
		t.Fatalf("RateLimit-Limit = %q, want the anonymous budget 100000", got)
	}
	if got := res.Header.Get("RateLimit-Remaining"); got != "99999" {
		t.Fatalf("RateLimit-Remaining = %q, want 99999 after one request", got)
	}
	if got := res.Header.Get("RateLimit-Reset"); got != "1" {
		t.Fatalf("RateLimit-Reset = %q, want 1", got)
	}

	// A request past the budget is refused with 429, the headers say so, and
	// Retry-After names the wait.
	tight := newTestEnvCfg(t, func(c *config.Config) { c.Limits.AnonymousPerMin = 1 })
	ok := tight.do(anonymous, http.MethodGet, "/api/v1/meta", nil)
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusOK || ok.Header.Get("RateLimit-Limit") != "1" || ok.Header.Get("RateLimit-Remaining") != "0" || ok.Header.Get("Retry-After") != "" {
		t.Fatalf("the request within the budget: %d %v", ok.StatusCode, ok.Header)
	}
	refused := tight.do(anonymous, http.MethodGet, "/api/v1/meta", nil)
	_ = refused.Body.Close()
	if refused.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the request past the budget: got %d want 429", refused.StatusCode)
	}
	wait, err := strconv.Atoi(refused.Header.Get("Retry-After"))
	if err != nil || wait < 1 || wait > 60 || refused.Header.Get("RateLimit-Reset") != refused.Header.Get("Retry-After") ||
		refused.Header.Get("RateLimit-Limit") != "1" || refused.Header.Get("RateLimit-Remaining") != "0" {
		t.Fatalf("headers of a refusal: %v", refused.Header)
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
	if second.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(second.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("a replay is typed as json and never cached: Cache-Control %q, Content-Type %q",
			second.Header.Get("Cache-Control"), second.Header.Get("Content-Type"))
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
	thirdBody, _ := io.ReadAll(third.Body)
	_ = third.Body.Close()
	if third.StatusCode != http.StatusConflict || !strings.Contains(string(thirdBody), "already carried a different request body") {
		t.Fatalf("key reuse with a different body: got %d %s, want 409 naming the different body", third.StatusCode, thirdBody)
	}

	// A failed request must not lock the key out. A second account makes
	// the attempts: the first is now an admin of the organization it
	// created, and a person belongs to one organization at a time.
	otherH := env.register("idem-other")
	env.verifyEmail(otherH)
	other := env.login(otherH)
	badKey := "idem-bad-" + env.sfx
	bad := env.doWithHeaders(other, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": "NOT VALID", "displayName": "x"},
		map[string]string{"Idempotency-Key": badKey})
	badBody, _ := io.ReadAll(bad.Body)
	_ = bad.Body.Close()
	if bad.StatusCode == http.StatusCreated {
		t.Fatal("an invalid handle must not create an org")
	}
	retry := env.doWithHeaders(other, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": "idemthree" + env.sfx, "displayName": "Third"},
		map[string]string{"Idempotency-Key": badKey})
	_ = retry.Body.Close()
	if retry.StatusCode != http.StatusCreated {
		t.Fatalf("retry after a failed attempt: got %d want 201", retry.StatusCode)
	}

	// The refusal states the whole handle rule, as the handle grammar has it.
	if want := "An org handle is 1-39 lowercase letters, digits and hyphens, starting and ending with a letter or digit."; bad.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(badBody), want) {
		t.Fatalf("an invalid handle: got %d %s, want 422 stating the rule %q", bad.StatusCode, badBody, want)
	}

	// A key is the caller's own: another account sending the same key and a
	// different body is a first request, not a conflict.
	fourthH := env.register("idem-four")
	env.verifyEmail(fourthH)
	fourth := env.login(fourthH)
	own := env.doWithHeaders(fourth, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": "idemfour" + env.sfx, "displayName": "Fourth"},
		map[string]string{"Idempotency-Key": key})
	_ = own.Body.Close()
	if own.StatusCode != http.StatusCreated || own.Header.Get("Idempotency-Replayed") != "" {
		t.Fatalf("another account's use of the same key: got %d replayed=%q, want a fresh 201", own.StatusCode, own.Header.Get("Idempotency-Replayed"))
	}

	// A key is at most 255 characters: 255 is a request, 256 is refused
	// before anything is done.
	fifthH := env.register("idem-five")
	env.verifyEmail(fifthH)
	fifth := env.login(fifthH)
	tooLong := env.doWithHeaders(fifth, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": "idemfive" + env.sfx, "displayName": "Fifth"},
		map[string]string{"Idempotency-Key": strings.Repeat("k", 256)})
	_ = tooLong.Body.Close()
	if tooLong.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a 256-character key: got %d want 422", tooLong.StatusCode)
	}
	longest := env.doWithHeaders(fifth, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": "idemfive" + env.sfx, "displayName": "Fifth"},
		map[string]string{"Idempotency-Key": strings.Repeat("k", 255)})
	_ = longest.Body.Close()
	if longest.StatusCode != http.StatusCreated {
		t.Fatalf("a 255-character key: got %d want 201", longest.StatusCode)
	}

	// A caller with no credential has nothing to key on: the route answers as
	// it would without the header.
	anon := env.doWithHeaders(anonymous, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": "idemanon" + env.sfx, "displayName": "Anon"},
		map[string]string{"Idempotency-Key": "idem-anon-" + env.sfx})
	_ = anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous request with a key: got %d want 401", anon.StatusCode)
	}

	// A retry that finds the first attempt still running is refused rather
	// than raced: the claim exists and holds no response yet.
	sixthH := env.register("idem-six")
	env.verifyEmail(sixthH)
	sixth := env.login(sixthH)
	pending := map[string]any{"handle": "idemsix" + env.sfx, "displayName": "Sixth"}
	raw, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO idempotency_keys (key, user_id, endpoint, request_hash, expires_at)
		 SELECT $2, id, 'POST /orgs', $3, now() + interval '1 hour' FROM handles WHERE handle = $1`,
		sixthH, "idem-flight-"+env.sfx, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	flight := env.doWithHeaders(sixth, http.MethodPost, "/api/v1/orgs", pending,
		map[string]string{"Idempotency-Key": "idem-flight-" + env.sfx})
	flightBody, _ := io.ReadAll(flight.Body)
	_ = flight.Body.Close()
	if flight.StatusCode != http.StatusConflict || !strings.Contains(string(flightBody), "still in flight") {
		t.Fatalf("a retry while the first attempt runs: got %d %s, want 409 naming the request in flight", flight.StatusCode, flightBody)
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
	if res2.Header.Get("Link") != "" {
		t.Fatalf("the last page carries a next link: %q", res2.Header.Get("Link"))
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

// ---- review:act ----

func TestReviewSurfaceRequiresReviewActScope(t *testing.T) {
	env := newTestEnv(t)
	staffH := env.register("rev-st")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	sess := env.login(staffH)

	_, wrongPAT := env.mintPAT(sess, "no-review", "user:profile", "agent:read")
	_, rightPAT := env.mintPAT(sess, "review", "user:profile", "review:act")

	// The role is sufficient (platform staff) but the token is not:
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

	// A session carries the user's full authority: no scope needed.
	res = env.do(sess, http.MethodGet, "/api/v1/review-queue?queue=platform", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session review queue: got %d want 200", res.StatusCode)
	}

	// The whole review surface is behind the scope: the items, their files
	// and decisions, and the findings' verdicts. A token that carries it gets
	// past the scope (and answers 404 for an item that does not exist); one
	// that does not is refused first, naming the scope.
	missing := uuid.NewString()
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/review-items/" + missing, nil},
		{http.MethodGet, "/api/v1/review-items/" + missing + "/files", nil},
		{http.MethodGet, "/api/v1/review-items/" + missing + "/file?path=SKILL.md", nil},
		{http.MethodPost, "/api/v1/review-items/" + missing + "/decision", map[string]any{"decision": "approve", "rationale": "x"}},
		{http.MethodPost, "/api/v1/findings/" + missing + "/verdict", map[string]any{"verdict": "dismissed_false_positive", "reason": "x"}},
	} {
		res = env.do(caller{name: "pat-wrong", pat: wrongPAT}, c.method, c.path, c.body)
		refusal, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusForbidden || !strings.Contains(string(refusal), "review:act") {
			t.Fatalf("%s %s with a token lacking review:act: got %d %s, want 403 naming the scope", c.method, c.path, res.StatusCode, refusal)
		}
		res = env.do(caller{name: "pat-right", pat: rightPAT}, c.method, c.path, c.body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s with review:act: got %d, want 404 for an item that does not exist", c.method, c.path, res.StatusCode)
		}
	}
}

// GET /platform/ruleset-releases lists the release history for staff and
// refuses everyone else.
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
	res = env.do(anonymous, http.MethodGet, "/api/v1/platform/ruleset-releases", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous list: got %d want 401", res.StatusCode)
	}
	// Notes are kept without the space around them, and the newest release is first.
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/ruleset-releases",
		map[string]any{"semver": "9.9.2", "bundleDigest": "sha256:" + strings.Repeat("ab", 32), "notes": "  padded notes  "}, nil, http.StatusCreated)
	env.doJSON(staff, http.MethodGet, "/api/v1/platform/ruleset-releases", nil, &list, http.StatusOK)
	if len(list) < 2 || list[0].Semver != "9.9.2" || list[0].Notes != "padded notes" || list[1].Semver != "9.9.1" {
		t.Fatalf("list after a second release: %+v", list)
	}
}
