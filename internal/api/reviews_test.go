package api_test

// Review/policy/platform handler tests: the bespoke authorization the
// generic matrix can't express — platform-staff gating, org-reviewer gating,
// author-cannot-self-approve, and tighten-only policy.

import (
	"context"
	"net/http"
	"testing"
)

// platformStaff flips a user to platform staff directly (there is no API to
// grant it — SaaS provisions staff out of band; self-host = instance admin).
func (env *testEnv) makePlatformStaff(t *testing.T, handle string) {
	t.Helper()
	// The api layer reads PlatformStaff from a users column; set it.
	_, err := env.st.Pool().Exec(context.Background(),
		`UPDATE users SET platform_staff = true WHERE id = (SELECT id FROM handles WHERE handle = $1)`, handle)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReviewQueueAuthz(t *testing.T) {
	env := newTestEnv(t)
	// A plain authed user cannot read the platform queue.
	u := env.register("rvq")
	env.verifyEmail(u)
	sess := env.login(u)
	res := env.do(sess, http.MethodGet, "/api/v1/review-queue?queue=platform", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-staff platform queue: got %d want 403", res.StatusCode)
	}
	// Anonymous is 401.
	res = env.do(anonymous, http.MethodGet, "/api/v1/review-queue?queue=platform", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anon platform queue: got %d want 401", res.StatusCode)
	}
	// Platform staff can read it.
	env.makePlatformStaff(t, u)
	sess2 := env.login(u)
	res = env.do(sess2, http.MethodGet, "/api/v1/review-queue?queue=platform", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("staff platform queue: got %d want 200", res.StatusCode)
	}
}

func TestOrgReviewQueueRequiresReviewer(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("orv-own")
	env.verifyEmail(owner)
	ownerSess := env.login(owner)
	org := "orvorg" + env.sfx
	env.doJSON(ownerSess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "O"}, nil, http.StatusCreated)

	// A plain member cannot read the org review queue.
	member := env.register("orv-mem")
	env.joinOrg(ownerSess, org, member)
	memberSess := env.login(member)
	res := env.do(memberSess, http.MethodGet, "/api/v1/review-queue?queue=org&org="+org, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("member org queue: got %d want 403", res.StatusCode)
	}

	// An admin can: in an ordinary organization the admins are its
	// reviewers.
	env.doJSON(ownerSess, http.MethodPut, "/api/v1/orgs/"+org+"/members/"+member, map[string]any{"role": "admin"}, nil, http.StatusOK)
	adminSess := env.login(member)
	res = env.do(adminSess, http.MethodGet, "/api/v1/review-queue?queue=org&org="+org, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin org queue: got %d want 200", res.StatusCode)
	}

	// So can a security_reviewer row, which the API assigns only inside a
	// first-party organization; seeded directly here.
	env.doJSON(ownerSess, http.MethodPut, "/api/v1/orgs/"+org+"/members/"+member, map[string]any{"role": "member"}, nil, http.StatusOK)
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE memberships SET role = 'security_reviewer'
		 WHERE user_id = (SELECT id FROM handles WHERE handle = $1) AND org_id = (SELECT id FROM handles WHERE handle = $2)`, member, org); err != nil {
		t.Fatal(err)
	}
	reviewerSess := env.login(member)
	res = env.do(reviewerSess, http.MethodGet, "/api/v1/review-queue?queue=org&org="+org, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("reviewer org queue: got %d want 200", res.StatusCode)
	}
}

func TestOrgPolicyTightenOnly(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("pol-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	org := "polorg" + env.sfx
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "P"}, nil, http.StatusCreated)

	// Tightening is accepted, and the answer is the policy as it now stands:
	// the organization's knobs over the platform baseline's.
	var merged struct {
		MaxAutoPublishSeverity string `json:"maxAutoPublishSeverity"`
		RequireHumanReview     string `json:"requireHumanReview"`
		WildcardEgress         string `json:"wildcardEgress"`
	}
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+org+"/policy",
		map[string]any{"maxAutoPublishSeverity": "info", "requireHumanReview": "always"}, &merged, http.StatusOK)
	if merged.MaxAutoPublishSeverity != "info" || merged.RequireHumanReview != "always" || merged.WildcardEgress != "review" {
		t.Fatalf("merged policy = %+v, want info, always and the baseline's wildcardEgress", merged)
	}
	// The document sent is the one stored.
	var stored map[string]any
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+org+"/policy", nil, &stored, http.StatusOK)
	if len(stored) != 2 || stored["maxAutoPublishSeverity"] != "info" || stored["requireHumanReview"] != "always" {
		t.Fatalf("stored policy = %v", stored)
	}
	var audited int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'policy.update' AND org_id = (SELECT id FROM handles WHERE handle = $1)`, org).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("the policy change was audited %d times, want once", audited)
	}

	// Loosening is rejected.
	res := env.do(sess, http.MethodPut, "/api/v1/orgs/"+org+"/policy",
		map[string]any{"maxAutoPublishSeverity": "high"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("loosening policy: got %d want 422", res.StatusCode)
	}
	// A knob at exactly the baseline's own value is no loosening.
	baselineLevel := map[string]any{"maxAutoPublishSeverity": baselineSeverity(t, env)}
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+org+"/policy", baselineLevel, nil, http.StatusOK)
	// A document that does not parse, or names a severity there is not, is
	// refused and leaves the stored policy as it was.
	for _, bad := range []map[string]any{{"maxAutoPublishSeverity": "bogus"}, {"requireHumanReview": "sometimes"}} {
		res = env.do(sess, http.MethodPut, "/api/v1/orgs/"+org+"/policy", bad)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("policy %v: got %d want 422", bad, res.StatusCode)
		}
	}
	stored = nil
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+org+"/policy", nil, &stored, http.StatusOK)
	if len(stored) != 1 || stored["maxAutoPublishSeverity"] != baselineLevel["maxAutoPublishSeverity"] {
		t.Fatalf("stored policy after refused documents = %v, want the last accepted one", stored)
	}

	// Platform baseline is world-readable, and says what an organization may
	// only tighten.
	var baseline struct {
		MaxAutoPublishSeverity string `json:"maxAutoPublishSeverity"`
		RequireHumanReview     string `json:"requireHumanReview"`
		WildcardEgress         string `json:"wildcardEgress"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/platform/policy", nil, &baseline, http.StatusOK)
	if baseline.MaxAutoPublishSeverity == "" || baseline.RequireHumanReview != "never" || baseline.WildcardEgress != "review" {
		t.Fatalf("platform policy = %+v", baseline)
	}
}

// A baseline the platform stores is the one read back and the one an
// organization may only tighten, whichever knob it loosens.
func TestOrgPolicyTightensAStoredBaseline(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("bpol-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	org := "bpolorg" + env.sfx
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "B"}, nil, http.StatusCreated)

	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx, `DELETE FROM policies WHERE org_id IS NULL`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = env.st.Pool().Exec(context.Background(), `DELETE FROM policies WHERE org_id IS NULL`) })
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO policies (id, org_id, document, version)
		 VALUES (gen_random_uuid(), NULL, '{"maxAutoPublishSeverity":"low","requireHumanReview":"always","wildcardEgress":"reject"}'::jsonb, 1)`); err != nil {
		t.Fatal(err)
	}
	var baseline map[string]any
	env.doJSON(anonymous, http.MethodGet, "/api/v1/platform/policy", nil, &baseline, http.StatusOK)
	if baseline["maxAutoPublishSeverity"] != "low" || baseline["requireHumanReview"] != "always" || baseline["wildcardEgress"] != "reject" {
		t.Fatalf("stored baseline served as %v", baseline)
	}
	for _, loosening := range []map[string]any{
		{"maxAutoPublishSeverity": "medium"},
		{"requireHumanReview": "never"},
		{"wildcardEgress": "review"},
	} {
		res := env.do(sess, http.MethodPut, "/api/v1/orgs/"+org+"/policy", loosening)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("policy %v against the stored baseline: got %d want 422", loosening, res.StatusCode)
		}
	}
	var merged struct {
		MaxAutoPublishSeverity string `json:"maxAutoPublishSeverity"`
		RequireHumanReview     string `json:"requireHumanReview"`
		WildcardEgress         string `json:"wildcardEgress"`
	}
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+org+"/policy",
		map[string]any{"maxAutoPublishSeverity": "info", "wildcardEgress": "reject"}, &merged, http.StatusOK)
	if merged.MaxAutoPublishSeverity != "info" || merged.RequireHumanReview != "always" || merged.WildcardEgress != "reject" {
		t.Fatalf("merged policy = %+v, want info over the stored baseline's always and reject", merged)
	}
}

// baselineSeverity is the platform baseline's own auto-publish severity.
func baselineSeverity(t *testing.T, env *testEnv) string {
	t.Helper()
	var baseline struct {
		MaxAutoPublishSeverity string `json:"maxAutoPublishSeverity"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/platform/policy", nil, &baseline, http.StatusOK)
	return baseline.MaxAutoPublishSeverity
}

func TestPlatformActionRequiresStaff(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("pa-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	// Create a public agent to act on.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": owner, "name": "pa-agent", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)

	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	if status, body := env.uploadVersionCLI(owner, "pa-agent", pat, skillFiles(owner, "pa-agent", "1.0.0", nil)); status != http.StatusAccepted {
		t.Fatalf("publish: %d %s", status, body)
	}
	env.waitStatus(owner, "pa-agent", "1.0.0", "published")

	// Non-staff cannot quarantine, and nobody signed out can either.
	res := env.do(sess, http.MethodPost, "/api/v1/platform/agents/"+owner+"/pa-agent/quarantine",
		map[string]any{"reason": "test"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-staff quarantine: got %d want 403", res.StatusCode)
	}
	res = env.do(anonymous, http.MethodPost, "/api/v1/platform/agents/"+owner+"/pa-agent/quarantine",
		map[string]any{"reason": "test"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous quarantine: got %d want 401", res.StatusCode)
	}
	// An agent that does not exist is a 404 to staff.
	env.makePlatformStaff(t, owner)
	staffSess := env.login(owner)
	res = env.do(staffSess, http.MethodPost, "/api/v1/platform/agents/"+owner+"/no-such-agent/quarantine",
		map[string]any{"reason": "test"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("quarantine of an unknown agent: got %d want 404", res.StatusCode)
	}

	// Staff can.
	res = env.do(staffSess, http.MethodPost, "/api/v1/platform/agents/"+owner+"/pa-agent/quarantine",
		map[string]any{"reason": "malware confirmed"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("staff quarantine: got %d want 204", res.StatusCode)
	}
	// The agent is now quarantined.
	var agent struct {
		QuarantineState string `json:"quarantineState"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+owner+"/pa-agent", nil, &agent, http.StatusOK)
	if agent.QuarantineState != "quarantined" {
		t.Fatalf("quarantine state = %s", agent.QuarantineState)
	}
	// The act reaches the release a consumer would install, not the flag
	// alone, and the reason is on the record.
	versionStatus := func() string {
		t.Helper()
		var v struct {
			Status string `json:"status"`
		}
		env.doJSON(staffSess, http.MethodGet, "/api/v1/agents/"+owner+"/pa-agent/versions/1.0.0", nil, &v, http.StatusOK)
		return v.Status
	}
	if got := versionStatus(); got != "quarantined" {
		t.Fatalf("version status after quarantine = %s, want quarantined", got)
	}
	var reason string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'reason' FROM audit_events WHERE action = 'agent.quarantine' AND target_id = (SELECT a.id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'pa-agent')`,
		owner).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "malware confirmed" {
		t.Fatalf("audited reason = %q", reason)
	}

	// Blocking disables the release; reinstating clears the flag and asks for
	// a fresh scan of each release, which the answer counts.
	env.doJSON(staffSess, http.MethodPost, "/api/v1/platform/agents/"+owner+"/pa-agent/block",
		map[string]any{"reason": "confirmed"}, nil, http.StatusNoContent)
	if got := versionStatus(); got != "blocked" {
		t.Fatalf("version status after block = %s, want blocked", got)
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT quarantine_state FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'pa-agent'`, owner).Scan(&reason); err != nil || reason != "blocked" {
		t.Fatalf("agent flag after block = %q (%v), want blocked", reason, err)
	}
	var reinstated struct {
		Queued int `json:"queued"`
	}
	env.doJSON(staffSess, http.MethodPost, "/api/v1/platform/agents/"+owner+"/pa-agent/reinstate",
		map[string]any{"reason": "false alarm"}, &reinstated, http.StatusAccepted)
	if reinstated.Queued != 1 {
		t.Fatalf("reinstate queued %d scans, want 1", reinstated.Queued)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+owner+"/pa-agent", nil, &agent, http.StatusOK)
	if agent.QuarantineState != "none" {
		t.Fatalf("quarantine state after reinstate = %s, want none", agent.QuarantineState)
	}
}
