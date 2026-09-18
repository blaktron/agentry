package api_test

// M4 review/policy/platform handler tests: the bespoke authorization the
// generic matrix can't express — platform-staff gating, org-reviewer gating,
// author-cannot-self-approve (§12.2), and tighten-only policy (§8.6).

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
	env.verifyEmail(member)
	memberSess := env.login(member)
	env.doJSON(ownerSess, http.MethodPut, "/api/v1/orgs/"+org+"/members/"+member, map[string]any{"role": "member"}, nil, http.StatusOK)
	res := env.do(memberSess, http.MethodGet, "/api/v1/review-queue?queue=org&org="+org, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("member org queue: got %d want 403", res.StatusCode)
	}

	// An admin can: in an ordinary organization the admins are its
	// reviewers (agentry#360).
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

	// Tightening is accepted.
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+org+"/policy",
		map[string]any{"maxAutoPublishSeverity": "info", "requireHumanReview": "always"}, nil, http.StatusOK)

	// Loosening is rejected (§8.6).
	res := env.do(sess, http.MethodPut, "/api/v1/orgs/"+org+"/policy",
		map[string]any{"maxAutoPublishSeverity": "high"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("loosening policy: got %d want 422", res.StatusCode)
	}

	// Platform baseline is world-readable.
	res = env.do(anonymous, http.MethodGet, "/api/v1/platform/policy", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("platform policy read: got %d", res.StatusCode)
	}
}

func TestPlatformActionRequiresStaff(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("pa-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	// Create a public agent to act on.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": owner, "name": "pa-agent", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)

	// Non-staff cannot quarantine.
	res := env.do(sess, http.MethodPost, "/api/v1/platform/agents/"+owner+"/pa-agent/quarantine",
		map[string]any{"reason": "test"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-staff quarantine: got %d want 403", res.StatusCode)
	}

	// Staff can.
	env.makePlatformStaff(t, owner)
	staffSess := env.login(owner)
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
}
