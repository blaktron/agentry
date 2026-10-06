package api_test

// Retire, Restore and the tombstone Delete (plan forks-and-publisher.md M1,
// agentry#942; D1–D4, D13).

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
)

type lifecycleAgent struct {
	Visibility      string     `json:"visibility"`
	RetiredAt       *time.Time `json:"retiredAt"`
	Installs30d     *int       `json:"installs30d"`
	LastSubmittedAt *time.Time `json:"lastSubmittedAt"`
	Name            string     `json:"name"`
}

// publishedAgent creates a public agent in owner's namespace and publishes
// 1.0.0 through the pipeline, returning a publish-scoped token.
func (env *testEnv) publishedAgent(sess caller, owner, name string) string {
	env.t.Helper()
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": name, "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub-"+name, "agent:publish", "agent:read")
	status, body := env.uploadVersionCLI(owner, name, pat, skillFiles(owner, name, "1.0.0", nil))
	if status != http.StatusAccepted {
		env.t.Fatalf("publish %s: %d %s", name, status, body)
	}
	env.waitStatus(owner, name, "1.0.0", "published")
	return pat
}

func statusOf(t *testing.T, res *http.Response) int {
	t.Helper()
	_ = res.Body.Close()
	return res.StatusCode
}

// TestRetireAndRestore: a retired public agent is private (absent to a
// stranger and from search), takes no submission and cannot be made public
// by PATCH; the list filters it by state; Restore brings it back public
// with its version intact, and a second Restore is refused.
func TestRetireAndRestore(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("ret-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	stranger := env.login(env.register("ret-str"))
	pat := env.publishedAgent(sess, owner, "shelved")
	path := "/api/v1/agents/" + owner + "/shelved"

	var a lifecycleAgent
	env.doJSON(sess, http.MethodPost, path+"/retire", nil, &a, http.StatusOK)
	if a.Visibility != "private" || a.RetiredAt == nil {
		t.Fatalf("retired agent: visibility %q retiredAt %v, want private and set", a.Visibility, a.RetiredAt)
	}
	// Retiring twice changes nothing.
	env.doJSON(sess, http.MethodPost, path+"/retire", nil, nil, http.StatusOK)

	if code := statusOf(t, env.do(stranger, http.MethodGet, path, nil)); code != http.StatusNotFound {
		t.Fatalf("a stranger reading a retired agent: got %d want 404", code)
	}
	if code := statusOf(t, env.do(anonymous, http.MethodGet, path+"/versions/1.0.0/download", nil)); code != http.StatusNotFound {
		t.Fatalf("anonymous download of a retired agent: got %d want 404", code)
	}
	var hits struct {
		Results []struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"results"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+owner, nil, &hits, http.StatusOK)
	for _, h := range hits.Results {
		// The search matches handles by similarity too, so another run's
		// namespace can carry a "shelved" of its own.
		if h.Namespace == owner && h.Name == "shelved" {
			t.Fatal("a retired agent is in search")
		}
	}

	// No submission, through any door.
	status, body := env.uploadVersionCLI(owner, "shelved", pat, skillFiles(owner, "shelved", "1.0.1", nil))
	if status != http.StatusConflict || !strings.Contains(body, "agent-retired") {
		t.Fatalf("submission to a retired agent: got %d %s, want 409 agent-retired", status, body)
	}
	if code, slug, _ := problemOf(t, env.do(sess, http.MethodPatch, path, map[string]any{"visibility": "public"})); code != http.StatusConflict || slug != "agent-retired" {
		t.Fatalf("PATCH public on a retired agent: %d %s, want 409 agent-retired", code, slug)
	}

	var retired, active []lifecycleAgent
	env.doJSON(sess, http.MethodGet, "/api/v1/agents?namespace="+owner+"&state=retired", nil, &retired, http.StatusOK)
	env.doJSON(sess, http.MethodGet, "/api/v1/agents?namespace="+owner+"&state=active", nil, &active, http.StatusOK)
	if len(retired) != 1 || retired[0].Name != "shelved" || retired[0].RetiredAt == nil {
		t.Fatalf("state=retired: %+v", retired)
	}
	if len(active) != 0 {
		t.Fatalf("state=active lists a retired agent: %+v", active)
	}
	if retired[0].LastSubmittedAt == nil || retired[0].Installs30d == nil {
		t.Fatalf("the list must carry lastSubmittedAt and installs30d: %+v", retired[0])
	}

	var restored lifecycleAgent
	env.doJSON(sess, http.MethodPost, path+"/restore", nil, &restored, http.StatusOK)
	if restored.Visibility != "public" || restored.RetiredAt != nil {
		t.Fatalf("restored agent: visibility %q retiredAt %v, want public and unset", restored.Visibility, restored.RetiredAt)
	}
	if code := statusOf(t, env.do(anonymous, http.MethodGet, path+"/versions/1.0.0/download", nil)); code != http.StatusOK {
		t.Fatalf("download after restore: got %d want 200", code)
	}
	if code, slug, _ := problemOf(t, env.do(sess, http.MethodPost, path+"/restore", nil)); code != http.StatusConflict || slug != "agent-not-retired" {
		t.Fatalf("restore of an agent not retired: %d %s, want 409 agent-not-retired", code, slug)
	}
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action IN ('agent.retire','agent.restore')
		   AND target_id = (SELECT a.id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'shelved')`,
		owner).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("audit: %d retire/restore events, want 2 (the repeat retire writes none)", n)
	}
}

// TestRetireNeedsTheNamespacesAdministrators: an organization's member
// holds publish, not the administrators' acts that change who can see an
// agent.
func TestRetireNeedsTheNamespacesAdministrators(t *testing.T) {
	env := newTestEnv(t)
	admin := env.register("ret-adm")
	env.verifyEmail(admin)
	adminSess := env.login(admin)
	org := "ret-org-" + env.sfxDigits()
	env.doJSON(adminSess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "Retire Org"}, nil, http.StatusCreated)
	member := env.register("ret-mem")
	env.joinOrg(adminSess, org, member)
	env.doJSON(adminSess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": org, "name": "kept", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	if code := statusOf(t, env.do(env.login(member), http.MethodPost, "/api/v1/agents/"+org+"/kept/retire", nil)); code != http.StatusForbidden {
		t.Fatalf("a member retiring: got %d want 403", code)
	}
	env.doJSON(adminSess, http.MethodPost, "/api/v1/agents/"+org+"/kept/retire", nil, nil, http.StatusOK)
}

// TestRetiredAgentsHoldNoPlaceUnderTheCap (D13): retiring is never refused
// by the private-agent cap, a retired agent frees its place, and Restore
// back to private takes it again under the cap.
func TestRetiredAgentsHoldNoPlaceUnderTheCap(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetEntitlements(cappedResolver{Resolver: entitlements.NewConfigResolver(config.Default().Limits), max: 1})
	})
	user := env.register("ret-cap")
	env.verifyEmail(user)
	sess := env.login(user)
	create := func(name, visibility string, want int) {
		t.Helper()
		res := env.do(sess, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": user, "name": name, "modes": []string{"autonomous"}, "visibility": visibility})
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("create %s %s: got %d want %d: %s", name, visibility, res.StatusCode, want, body)
		}
	}
	create("first", "private", http.StatusCreated)
	create("open", "public", http.StatusCreated)
	// At the cap, a public agent still retires: retired holds no place.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents/"+user+"/open/retire", nil, nil, http.StatusOK)
	// The private one retires and frees its place.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents/"+user+"/first/retire", nil, nil, http.StatusOK)
	create("second", "private", http.StatusCreated)
	// Back to private needs a place, and there is none.
	if code, slug, _ := problemOf(t, env.do(sess, http.MethodPost, "/api/v1/agents/"+user+"/first/restore", nil)); code != http.StatusUnprocessableEntity || slug != "private-agent-cap" {
		t.Fatalf("restore to private at the cap: %d %s, want 422 private-agent-cap", code, slug)
	}
	// Back to public needs none.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents/"+user+"/open/restore", nil, nil, http.StatusOK)
}

// TestDeleteAgentWithHistoryLeavesATombstone (D3, D4): an agent with a
// published version is deleted only with its name confirmed; afterwards
// every read by name is a 404 for everyone, its owner included, its version
// row stays (yanked, with the reason), the name is held, and platform staff
// can still act on it.
func TestDeleteAgentWithHistoryLeavesATombstone(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("del-pub")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.publishedAgent(sess, owner, "shipped")
	path := "/api/v1/agents/" + owner + "/shipped"

	for _, q := range []string{"", "?confirm=wrong"} {
		if code, slug, _ := problemOf(t, env.do(sess, http.MethodDelete, path+q, nil)); code != http.StatusUnprocessableEntity || slug != "confirm-name" {
			t.Fatalf("delete %q: %d %s, want 422 confirm-name", q, code, slug)
		}
	}
	env.doJSON(sess, http.MethodDelete, path+"?confirm=shipped", nil, nil, http.StatusNoContent)

	for _, c := range []caller{sess, anonymous} {
		for _, p := range []string{
			path, path + "/versions", path + "/versions/1.0.0/download", path + "/activity",
			"/api/v1/resolve?ref=" + owner + "/shipped@1.0.0",
		} {
			if code := statusOf(t, env.do(c, http.MethodGet, p, nil)); code != http.StatusNotFound {
				t.Fatalf("GET %s as %s after delete: got %d want 404", p, c.name, code)
			}
		}
	}
	var list []lifecycleAgent
	env.doJSON(sess, http.MethodGet, "/api/v1/agents?namespace="+owner, nil, &list, http.StatusOK)
	if len(list) != 0 {
		t.Fatalf("a deleted agent is listed: %+v", list)
	}

	// The version row stays, yanked, with the reason.
	var status, reason string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT av.status, coalesce(av.yank_reason, '') FROM agent_versions av
		 JOIN agents a ON a.id = av.agent_id JOIN handles h ON h.id = a.namespace_id
		 WHERE h.handle = $1 AND a.name = 'shipped' AND av.version = '1.0.0'`, owner).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "yanked" || reason == "" {
		t.Fatalf("version after delete: status %q reason %q, want yanked with a reason", status, reason)
	}

	// The name is held.
	if code, slug, _ := problemOf(t, env.do(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "shipped", "modes": []string{"autonomous"},
	})); code != http.StatusConflict || slug != "name-held" {
		t.Fatalf("re-create a deleted name: %d %s, want 409 name-held", code, slug)
	}

	// A held name places nothing under the quota or the cap: the
	// namespace's live count excludes it.
	var live int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM agents a JOIN handles h ON h.id = a.namespace_id
		 WHERE h.handle = $1 AND a.deleted_at IS NULL`, owner).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("live agents after delete: %d, want 0", live)
	}

	// Trust & safety still reach it.
	staffH := env.register("del-staff")
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)
	res := env.do(staff, http.MethodPost, "/api/v1/platform/agents/"+owner+"/shipped/quarantine",
		map[string]any{"reason": "found after deletion"})
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode == http.StatusNotFound || res.StatusCode >= 500 {
		t.Fatalf("staff quarantine of a deleted agent: got %d %s", res.StatusCode, raw)
	}

	var tomb int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'agent.delete' AND detail->>'tombstone' = 'true'
		   AND detail->>'name' = 'shipped' AND detail->>'namespace' = $1`, owner).Scan(&tomb); err != nil {
		t.Fatal(err)
	}
	if tomb != 1 {
		t.Fatalf("tombstone audit events: %d, want 1", tomb)
	}
}

// TestDeleteWaitsForAVersionInFlight: a version still in the pipeline or in
// review would be decided onto a deleted agent, so the delete waits.
func TestDeleteWaitsForAVersionInFlight(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("del-fly")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.publishedAgent(sess, owner, "pending")
	ctx := context.Background()
	// Stage the version as one a reviewer has yet to decide: status is a
	// state-machine field the immutability trigger lets move.
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE agent_versions av SET status = 'needs_review' FROM agents a JOIN handles h ON h.id = a.namespace_id
		 WHERE av.agent_id = a.id AND h.handle = $1 AND a.name = 'pending'`, owner); err != nil {
		t.Fatal(err)
	}
	if code := statusOf(t, env.do(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/pending?confirm=pending", nil)); code != http.StatusConflict {
		t.Fatalf("delete with a version in review: got %d want 409", code)
	}
}

// TestNamespaceListSearchesAndSorts: q matches name or summary as a
// literal substring, and sort=newest orders by creation.
func TestNamespaceListSearchesAndSorts(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("lst-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	for _, a := range []struct{ name, summary string }{
		{"alpha", "reads invoices"}, {"beta", "writes 100% of reports"}, {"gamma", "invoices too"},
	} {
		env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
			"namespace": owner, "name": a.name, "summary": a.summary, "modes": []string{"autonomous"},
		}, nil, http.StatusCreated)
	}
	names := func(query string) []string {
		t.Helper()
		var out []lifecycleAgent
		env.doJSON(sess, http.MethodGet, "/api/v1/agents?namespace="+owner+query, nil, &out, http.StatusOK)
		ns := make([]string, 0, len(out))
		for _, a := range out {
			ns = append(ns, a.Name)
		}
		return ns
	}
	if got := strings.Join(names("&q=invoice"), ","); got != "alpha,gamma" {
		t.Fatalf("q=invoice: %s, want alpha,gamma", got)
	}
	if got := strings.Join(names("&q=100%25"), ","); got != "beta" {
		t.Fatalf("q=100%%: %s, want beta (%% is literal)", got)
	}
	if got := strings.Join(names("&q=_"), ","); got != "" {
		t.Fatalf("q=_: %s, want nothing (_ is literal)", got)
	}
	if got := strings.Join(names("&sort=newest"), ","); got != "gamma,beta,alpha" {
		t.Fatalf("sort=newest: %s, want gamma,beta,alpha", got)
	}
}

// TestRestoreToPublicMeetsTheUnscannedRules: an organization's agent
// retired from public and taken off the pipeline while private comes back
// public only once the flag is cleared — the same refusal PATCH gives
// (DEV-115).
func TestRestoreToPublicMeetsTheUnscannedRules(t *testing.T) {
	env := newTestEnvWith(t, onTier(unscannedOn(true)))
	adminH := env.register("rst-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "rstorg" + env.sfx
	env.createOrg(admin, orgH)
	path := "/api/v1/agents/" + orgH + "/back"
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "back", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.doJSON(admin, http.MethodPost, path+"/retire", nil, nil, http.StatusOK)
	env.doJSON(admin, http.MethodPatch, path, map[string]any{"pipelineSkip": true}, nil, http.StatusOK)
	if code, slug, _ := problemOf(t, env.do(admin, http.MethodPost, path+"/restore", nil)); code != http.StatusConflict || slug != "agent-unscanned" {
		t.Fatalf("restore to public off the pipeline: %d %s, want 409 agent-unscanned", code, slug)
	}
	env.doJSON(admin, http.MethodPatch, path, map[string]any{"pipelineSkip": false}, nil, http.StatusOK)
	var a lifecycleAgent
	env.doJSON(admin, http.MethodPost, path+"/restore", nil, &a, http.StatusOK)
	if a.Visibility != "public" {
		t.Fatalf("restored: %q, want public", a.Visibility)
	}
}
