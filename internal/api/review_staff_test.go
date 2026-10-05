package api_test

// Platform staff review any QuickAgent in review (agentry#912, DEV-213):
// their own versions, on either queue, and any organization's queue. The
// author rule (§12.2) still holds for everyone else, an organization's
// admin included, and a staff decision on their own version is marked in
// its audit event.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// decisionAudit is the detail of the review-decision audit event on an
// item, read from the store.
func (env *testEnv) decisionAudit(t *testing.T, itemID string) map[string]any {
	t.Helper()
	var raw []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail FROM audit_events WHERE target_kind = 'review_item' AND target_id = $1::uuid
		 ORDER BY occurred_at DESC LIMIT 1`, itemID).Scan(&raw); err != nil {
		t.Fatalf("no audit event for review item %s: %v", itemID, err)
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestStaffDecideTheirOwnPlatformItem: a platform-queue version its
// submitter decides as platform staff is published, and the audit event
// says it was a self-decision; another staff member's decision is not
// marked.
func TestStaffDecideTheirOwnPlatformItem(t *testing.T) {
	env := newTestEnv(t)
	author, itemID, _ := setupReviewItem(t, env, "own")
	env.makePlatformStaff(t, author)
	authorSess := env.login(author)

	env.doJSON(authorSess, http.MethodPost, "/api/v1/review-items/"+itemID+"/decision",
		map[string]any{"decision": "approve", "rationale": "the built-in package, reviewed by its publisher"}, nil, http.StatusNoContent)
	env.waitStatus(author, "risky", "1.0.0", "published")
	if d := env.decisionAudit(t, itemID); d["self_decision"] != true || d["decision"] != "approved" {
		t.Fatalf("the audit detail of a staff self-decision: %v", d)
	}

	// Another staff member's decision carries no mark.
	other, otherItem, staffSess := setupReviewItem(t, env, "oth")
	env.doJSON(staffSess, http.MethodPost, "/api/v1/review-items/"+otherItem+"/decision",
		map[string]any{"decision": "reject", "rationale": "confirmed injection payload"}, nil, http.StatusNoContent)
	env.waitStatus(other, "risky", "1.0.0", "rejected")
	if d := env.decisionAudit(t, otherItem); d["self_decision"] != nil {
		t.Fatalf("a decision on another's version is marked: %v", d)
	}
}

// TestStaffReviewAnyOrganizationsQueue: an organization's queue item is
// read, listed and decided by platform staff who are not its members; its
// author, the organization's admin, still cannot decide it, nor can a
// plain member read it.
func TestStaffReviewAnyOrganizationsQueue(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("sorg-own")
	env.verifyEmail(owner)
	ownerSess := env.login(owner)
	org := "sorg" + env.sfx
	env.createOrg(ownerSess, org)
	// Every version of this organization waits for a person (§8.6
	// tighten-only policy), so a clean one lands on its own queue.
	env.doJSON(ownerSess, http.MethodPut, "/api/v1/orgs/"+org+"/policy",
		map[string]any{"maxAutoPublishSeverity": "info", "requireHumanReview": "always"}, nil, http.StatusOK)
	env.doJSON(ownerSess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": org, "name": "clean", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(ownerSess, "pub", "agent:publish", "agent:read", "repo:read")
	files := map[string]string{
		"agent.yaml": skillYAML(org, "clean", "1.0.0"),
		"README.md":  "# clean\n",
		"SKILL.md":   "Summarize the meeting notes in /inputs as a list of decisions and action items.\n",
		"LICENSE":    "Apache-2.0\n",
	}
	if status, body := env.uploadVersionCLI(org, "clean", pat, files); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	env.waitStatus(org, "clean", "1.0.0", "needs_review")
	t.Cleanup(func() {
		_, _ = env.st.Pool().Exec(context.Background(),
			`UPDATE review_items SET state = 'rejected', decided_at = now()
			 WHERE state = 'pending' AND version_id IN (
			   SELECT v.id FROM agent_versions v JOIN agents a ON a.id = v.agent_id
			   JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1)`, org)
	})

	staffH := env.register("sorg-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)
	memberH := env.register("sorg-mem")
	env.verifyEmail(memberH)
	env.seedMembership(org, memberH, "member", "active")
	member := env.login(memberH)

	type item struct {
		Id        string `json:"id"`
		Queue     string `json:"queue"`
		Namespace string `json:"namespace"`
	}
	find := func(items []item) string {
		for _, it := range items {
			if it.Namespace == org {
				if it.Queue != "org" {
					t.Fatalf("the item is on the %s queue, want org", it.Queue)
				}
				return it.Id
			}
		}
		return ""
	}
	// Staff list this organization's queue, and every organization's by
	// naming none.
	var named, all []item
	env.doJSON(staff, http.MethodGet, "/api/v1/review-queue?queue=org&org="+org+"&limit=100", nil, &named, http.StatusOK)
	env.doJSON(staff, http.MethodGet, "/api/v1/review-queue?queue=org&limit=100", nil, &all, http.StatusOK)
	itemID := find(named)
	if itemID == "" || find(all) != itemID {
		t.Fatalf("staff do not see the organization's item: named %v, all %v", named, all)
	}
	// Anyone else still names an organization, and only its reviewers see it.
	for _, c := range []caller{ownerSess, member} {
		res := env.do(c, http.MethodGet, "/api/v1/review-queue?queue=org", nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("the org queue without an organization, not staff: %d, want 422", res.StatusCode)
		}
	}
	for _, path := range []string{"/api/v1/review-queue?queue=org&org=" + org, "/api/v1/review-items/" + itemID} {
		res := env.do(member, http.MethodGet, path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("a plain member reads %s: %d, want 403", path, res.StatusCode)
		}
	}
	env.doJSON(staff, http.MethodGet, "/api/v1/review-items/"+itemID, nil, nil, http.StatusOK)

	// The author is the organization's admin and not staff: refused.
	res := env.do(ownerSess, http.MethodPost, "/api/v1/review-items/"+itemID+"/decision",
		map[string]any{"decision": "approve", "rationale": "mine"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a non-staff author decides their own version: %d, want 403", res.StatusCode)
	}

	// Staff who are not its members decide it.
	env.doJSON(staff, http.MethodPost, "/api/v1/review-items/"+itemID+"/decision",
		map[string]any{"decision": "approve", "rationale": "reviewed by platform staff"}, nil, http.StatusNoContent)
	env.waitStatus(org, "clean", "1.0.0", "published")
}
