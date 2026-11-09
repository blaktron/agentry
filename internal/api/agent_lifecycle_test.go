package api_test

// Retire, Restore and the tombstone Delete.

import (
	"context"
	"encoding/json"
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
	// A retired agent is private, so a stranger's listing of the namespace
	// does not name it.
	var seen []lifecycleAgent
	env.doJSON(stranger, http.MethodGet, "/api/v1/agents?namespace="+owner, nil, &seen, http.StatusOK)
	if len(seen) != 0 {
		t.Fatalf("a stranger listing the namespace of a retired agent sees %+v", seen)
	}

	var restored lifecycleAgent
	env.doJSON(sess, http.MethodPost, path+"/restore", nil, &restored, http.StatusOK)
	if restored.Visibility != "public" || restored.RetiredAt != nil {
		t.Fatalf("restored agent: visibility %q retiredAt %v, want public and unset", restored.Visibility, restored.RetiredAt)
	}
	if code := statusOf(t, env.do(anonymous, http.MethodGet, path+"/versions/1.0.0/download", nil)); code != http.StatusOK {
		t.Fatalf("download after restore: got %d want 200", code)
	}
	env.doJSON(stranger, http.MethodGet, "/api/v1/agents?namespace="+owner, nil, &seen, http.StatusOK)
	if len(seen) != 1 || seen[0].Name != "shelved" {
		t.Fatalf("a stranger listing the namespace of a restored public agent sees %+v", seen)
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
	// One event of each kind, each naming the visibility the agent had.
	for _, action := range []string{"agent.retire", "agent.restore"} {
		var visibility string
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT coalesce(detail->>'visibility', '') FROM audit_events WHERE action = $2
			   AND target_id = (SELECT a.id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'shelved')`,
			owner, action).Scan(&visibility); err != nil {
			t.Fatalf("audit event %s: %v", action, err)
		}
		if visibility != "public" {
			t.Fatalf("audit event %s names visibility %q, want public", action, visibility)
		}
	}

	// A yank gives its reason: one to 500 characters. The version stays
	// until one is given, and a yanked version cannot be yanked again.
	yank := func(reason string) (int, string) {
		code, slug, _ := problemOf(t, env.do(sess, http.MethodPost, path+"/versions/1.0.0/yank", map[string]any{"reason": reason}))
		return code, slug
	}
	for _, reason := range []string{"", "   ", strings.Repeat("r", 501)} {
		if code, slug := yank(reason); code != http.StatusUnprocessableEntity || slug != "validation" {
			t.Fatalf("yank with a reason of %d characters: %d %s, want 422 validation", len(reason), code, slug)
		}
	}
	if code := statusOf(t, env.do(sess, http.MethodPost, path+"/versions/1.0.0/yank", map[string]any{"reason": strings.Repeat("r", 500)})); code != http.StatusNoContent {
		t.Fatalf("yank with a reason of 500 characters: %d, want 204", code)
	}
	if code, slug := yank("again"); code != http.StatusConflict || slug != "conflict" {
		t.Fatalf("yank of a yanked version: %d %s, want 409 conflict", code, slug)
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
	memberSess := env.login(member)
	if code := statusOf(t, env.do(memberSess, http.MethodPost, "/api/v1/agents/"+org+"/kept/retire", nil)); code != http.StatusForbidden {
		t.Fatalf("a member retiring: got %d want 403", code)
	}
	// Nor does a member change who can see the agent in any other way.
	if code := statusOf(t, env.do(memberSess, http.MethodPatch, "/api/v1/agents/"+org+"/kept", map[string]any{"visibility": "private"})); code != http.StatusForbidden {
		t.Fatalf("a member making the agent private: got %d want 403", code)
	}
	env.doJSON(adminSess, http.MethodPost, "/api/v1/agents/"+org+"/kept/retire", nil, nil, http.StatusOK)
	if code := statusOf(t, env.do(memberSess, http.MethodPost, "/api/v1/agents/"+org+"/kept/restore", nil)); code != http.StatusForbidden {
		t.Fatalf("a member restoring: got %d want 403", code)
	}
	if code := statusOf(t, env.do(memberSess, http.MethodDelete, "/api/v1/agents/"+org+"/kept?confirm=kept", nil)); code != http.StatusForbidden {
		t.Fatalf("a member deleting: got %d want 403", code)
	}
	env.doJSON(adminSess, http.MethodPost, "/api/v1/agents/"+org+"/kept/restore", nil, nil, http.StatusOK)
}

// TestRetiredAgentsHoldNoPlaceUnderTheCap: retiring is never refused
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

// TestDeleteAgentWithHistoryLeavesATombstone: an agent with a
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
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("staff quarantine of a deleted agent: got %d %s, want 204", res.StatusCode, raw)
	}
	var quarantine string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT a.quarantine_state FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'shipped'`, owner).Scan(&quarantine); err != nil {
		t.Fatal(err)
	}
	if quarantine != "quarantined" {
		t.Fatalf("a deleted agent after staff quarantined it is %q, want quarantined", quarantine)
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
	var yanked string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'versionsYanked' FROM audit_events WHERE action = 'agent.delete' AND detail->>'tombstone' = 'true'
		   AND detail->>'name' = 'shipped' AND detail->>'namespace' = $1`, owner).Scan(&yanked); err != nil {
		t.Fatal(err)
	}
	if yanked != "1" {
		t.Fatalf("the tombstone's audit event says %q versions yanked, want 1", yanked)
	}

	// A version held in quarantine is yanked with the rest: the agent
	// itself is not quarantined, so the delete goes ahead.
	env.publishedAgent(sess, owner, "held-back")
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agent_versions av SET status = 'quarantined' FROM agents a JOIN handles h ON h.id = a.namespace_id
		 WHERE av.agent_id = a.id AND h.handle = $1 AND a.name = 'held-back'`, owner); err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/held-back?confirm=held-back", nil, nil, http.StatusNoContent)
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT av.status FROM agent_versions av JOIN agents a ON a.id = av.agent_id JOIN handles h ON h.id = a.namespace_id
		 WHERE h.handle = $1 AND a.name = 'held-back'`, owner).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "yanked" {
		t.Fatalf("a quarantined version after its agent was deleted is %q, want yanked", status)
	}

	// Trust & safety records outlive the publisher's wish to delete: an
	// advisory, an abuse report or a quarantine each keep the agent, and
	// it stays readable.
	reporter := env.register("del-rep")
	env.verifyEmail(reporter)
	reporterSess := env.login(reporter)
	for _, tc := range []struct {
		name  string
		raise func(name string)
	}{
		{"advised", func(name string) {
			if _, err := env.st.Pool().Exec(context.Background(),
				`INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, published_at)
				 SELECT gen_random_uuid(), a.id, '<=1.0.0', 'high', 'held for the advisory', now()
				 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = $2`, owner, name); err != nil {
				t.Fatal(err)
			}
		}},
		{"reported", func(name string) {
			env.doJSON(reporterSess, http.MethodPost, "/api/v1/agents/"+owner+"/"+name+"/abuse-reports",
				map[string]any{"category": "spam", "detail": "a report keeps the agent in place"}, nil, http.StatusAccepted)
		}},
		{"flagged", func(name string) {
			env.doJSON(staff, http.MethodPost, "/api/v1/platform/agents/"+owner+"/"+name+"/quarantine",
				map[string]any{"reason": "held for review"}, nil, http.StatusNoContent)
		}},
	} {
		env.publishedAgent(sess, owner, tc.name)
		tc.raise(tc.name)
		code, slug, detail := problemOf(t, env.do(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/"+tc.name+"?confirm="+tc.name, nil))
		if code != http.StatusConflict || slug != "conflict" || !strings.Contains(detail, "trust & safety records") {
			t.Fatalf("deleting the %s agent: got %d %s %q, want 409 naming its trust & safety records", tc.name, code, slug, detail)
		}
		env.doJSON(sess, http.MethodGet, "/api/v1/agents/"+owner+"/"+tc.name, nil, nil, http.StatusOK)
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
	// Every state short of a verdict waits; a published version does not.
	for _, status := range []string{"scanning", "approved"} {
		if _, err := env.st.Pool().Exec(ctx,
			`UPDATE agent_versions av SET status = $2 FROM agents a JOIN handles h ON h.id = a.namespace_id
			 WHERE av.agent_id = a.id AND h.handle = $1 AND a.name = 'pending'`, owner, status); err != nil {
			t.Fatal(err)
		}
		if code := statusOf(t, env.do(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/pending?confirm=pending", nil)); code != http.StatusConflict {
			t.Fatalf("delete with a version %s: got %d want 409", status, code)
		}
		// The wait comes before the confirmation is asked for.
		if code := statusOf(t, env.do(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/pending", nil)); code != http.StatusConflict {
			t.Fatalf("delete with a version %s and no confirmation: got %d want 409", status, code)
		}
	}
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE agent_versions av SET status = 'published' FROM agents a JOIN handles h ON h.id = a.namespace_id
		 WHERE av.agent_id = a.id AND h.handle = $1 AND a.name = 'pending'`, owner); err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/pending?confirm=pending", nil, nil, http.StatusNoContent)

	// A version just submitted waits too. A row cannot go back to
	// submitted, so this one is recorded as such.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": owner, "name": "just-in", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO agent_versions (id, agent_id, version, manifest, capabilities, channel, submitted_by, source, status)
		 SELECT gen_random_uuid(), a.id, '1.0.0', '{}', '{}', 'stable', h.id, 'cli-upload', 'submitted'
		 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'just-in'`, owner); err != nil {
		t.Fatal(err)
	}
	if code := statusOf(t, env.do(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/just-in?confirm=just-in", nil)); code != http.StatusConflict {
		t.Fatalf("delete with a version just submitted: got %d want 409", code)
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

	// A term matches the name alone, in any case, and a backslash is as
	// literal as the other pattern characters.
	if got := strings.Join(names("&q=ALPH"), ","); got != "alpha" {
		t.Fatalf("q=ALPH: %s, want alpha (a name match, any case)", got)
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "pct-agent", "summary": "grows by 5%", "modes": []string{"autonomous"},
	}, nil, http.StatusCreated)
	if got := strings.Join(names("&q=%5C"), ","); got != "" {
		t.Fatalf("q=\\: %s, want nothing (a backslash is literal, not an escape for the percent sign closing a summary)", got)
	}
	// A term is at most 200 characters.
	if got := strings.Join(names("&q="+strings.Repeat("x", 200)), ","); got != "" {
		t.Fatalf("a 200-character term: %s, want nothing", got)
	}
	if code, slug, _ := problemOf(t, env.do(sess, http.MethodGet, "/api/v1/agents?namespace="+owner+"&q="+strings.Repeat("x", 201), nil)); code != http.StatusUnprocessableEntity || slug != "validation" {
		t.Fatalf("a 201-character term: %d %s, want 422 validation", code, slug)
	}

	// Three published agents, submitted in the order a, b, c, installed
	// b twice and a once: by name they read a,b,c, by installs b,a,c and
	// by last submission c,b,a.
	for _, name := range []string{"px-a", "px-b", "px-c"} {
		env.publishedAgent(sess, owner, name)
	}
	for _, name := range []string{"px-b", "px-b", "px-a"} {
		if code := statusOf(t, env.do(anonymous, http.MethodGet, "/api/v1/agents/"+owner+"/"+name+"/versions/1.0.0/download", nil)); code != http.StatusOK {
			t.Fatalf("download %s: %d", name, code)
		}
	}
	for sort, want := range map[string]string{"": "px-a,px-b,px-c", "&sort=name": "px-a,px-b,px-c", "&sort=installs": "px-b,px-a,px-c", "&sort=submitted": "px-c,px-b,px-a"} {
		if got := strings.Join(names("&q=px-"+sort), ","); got != want {
			t.Fatalf("sort%s: %s, want %s", sort, got, want)
		}
	}
}

// TestRestoreToPublicMeetsTheUnscannedRules: an organization's agent
// retired from public and taken off the pipeline while private comes back
// public only once the flag is cleared, the same refusal PATCH gives.
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

	// A version admitted unscanned that still stands holds a public agent
	// back from coming back too: one is enough, and the refusal counts it.
	env.publishedAgent(admin, orgH, "stands")
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agent_versions av SET scan_status = 'skipped' FROM agents a JOIN handles h ON h.id = a.namespace_id
		 WHERE av.agent_id = a.id AND h.handle = $1 AND a.name = 'stands'`, orgH); err != nil {
		t.Fatal(err)
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/agents/"+orgH+"/stands/retire", nil, nil, http.StatusOK)
	res := env.do(admin, http.MethodPost, "/api/v1/agents/"+orgH+"/stands/restore", nil)
	var p struct {
		Type      string `json:"type"`
		Unscanned int    `json:"unscanned"`
	}
	_ = json.NewDecoder(res.Body).Decode(&p)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusConflict || !strings.HasSuffix(p.Type, "/agent-unscanned") || p.Unscanned != 1 {
		t.Fatalf("restore to public with an unscanned version standing: %d %+v, want 409 agent-unscanned counting 1", res.StatusCode, p)
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agent_versions av SET scan_status = 'pipeline' FROM agents a JOIN handles h ON h.id = a.namespace_id
		 WHERE av.agent_id = a.id AND h.handle = $1 AND a.name = 'stands'`, orgH); err != nil {
		t.Fatal(err)
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/agents/"+orgH+"/stands/restore", nil, &a, http.StatusOK)
	if a.Visibility != "public" {
		t.Fatalf("restored with nothing unscanned standing: %q, want public", a.Visibility)
	}
}

// TestARetiredAgentSaysWhatRestoreGivesBack: a retired agent's read and its
// namespace's list carry the visibility it had when retired, which Restore
// gives back, public or private; an agent that is not retired carries none.
func TestARetiredAgentSaysWhatRestoreGivesBack(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("rv-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	env.publishedAgent(sess, owner, "was-public")
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": owner, "name": "was-private", "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)

	type agentOut struct {
		Name              string  `json:"name"`
		Visibility        string  `json:"visibility"`
		RetiredVisibility *string `json:"retiredVisibility"`
	}
	read := func(name string) agentOut {
		t.Helper()
		var a agentOut
		env.doJSON(sess, http.MethodGet, "/api/v1/agents/"+owner+"/"+name, nil, &a, http.StatusOK)
		return a
	}
	if a := read("was-public"); a.RetiredVisibility != nil {
		t.Fatalf("an agent that is not retired: retiredVisibility %q", *a.RetiredVisibility)
	}
	for name, want := range map[string]string{"was-public": "public", "was-private": "private"} {
		env.doJSON(sess, http.MethodPost, "/api/v1/agents/"+owner+"/"+name+"/retire", nil, nil, http.StatusOK)
		if a := read(name); a.Visibility != "private" || a.RetiredVisibility == nil || *a.RetiredVisibility != want {
			t.Fatalf("%s retired: visibility %q, retiredVisibility %v, want private and %s", name, a.Visibility, a.RetiredVisibility, want)
		}
	}
	var list []agentOut
	env.doJSON(sess, http.MethodGet, "/api/v1/agents?namespace="+owner, nil, &list, http.StatusOK)
	for _, a := range list {
		if a.RetiredVisibility == nil || (a.Name == "was-public") != (*a.RetiredVisibility == "public") {
			t.Fatalf("the list's %s: retiredVisibility %v", a.Name, a.RetiredVisibility)
		}
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/agents/"+owner+"/was-public/restore", nil, nil, http.StatusOK)
	if a := read("was-public"); a.Visibility != "public" || a.RetiredVisibility != nil {
		t.Fatalf("after Restore: visibility %q, retiredVisibility %v", a.Visibility, a.RetiredVisibility)
	}
}
