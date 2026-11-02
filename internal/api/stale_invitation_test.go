package api_test

import (
	"context"
	"net/http"
	"testing"
)

// An invitation sent while a person was pending can be accepted after
// another door made them a member. The accept answers that they are
// already a member and changes nothing: the role the invitation carried is
// not applied over the one they hold, so it can neither leave the
// organization without an admin nor raise a member to admin. A role change
// goes only through the role-change route and its guards.
func TestAStaleInvitationLeavesAnActiveMembersRole(t *testing.T) {
	env := newTestEnv(t)
	roleOf := func(org, handle string) string {
		t.Helper()
		var role string
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT m.role FROM memberships m
			 JOIN handles o ON o.id = m.org_id JOIN handles u ON u.id = m.user_id
			 WHERE o.handle = $1 AND u.handle = $2 AND m.state = 'active'`, org, handle).Scan(&role); err != nil {
			t.Fatalf("%s's role in %s: %v", handle, org, err)
		}
		return role
	}
	admins := func(org string) int {
		t.Helper()
		var n int
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT count(*) FROM memberships m JOIN handles h ON h.id = m.org_id
			 WHERE h.handle = $1 AND m.role = 'admin' AND m.state = 'active'`, org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("a member invitation does not demote the last admin", func(t *testing.T) {
		aH := env.register("si-a")
		env.verifyEmail(aH)
		a := env.login(aH)
		org := "siorg" + env.sfx
		env.createOrg(a, org)
		xH := env.register("si-x")
		env.verifyEmail(xH)
		env.seedMembership(org, xH, "member", "pending")
		token := inviteTo(t, env, a, org, xH+"@example.test")
		env.doJSON(a, http.MethodPost, "/api/v1/orgs/"+org+"/members/"+xH+"/approve", map[string]any{"role": "admin"}, nil, http.StatusOK)
		env.doJSON(a, http.MethodPut, "/api/v1/orgs/"+org+"/members/"+aH, map[string]any{"role": "member"}, nil, http.StatusOK)

		code, _, detail := problemOf(t, env.do(env.login(xH), http.MethodPost, "/api/v1/invitations/"+token, nil))
		if code != http.StatusConflict || detail != "You are already a member of "+org+"." {
			t.Fatalf("the last admin accepting a stale member invitation: %d %q, want 409 already a member", code, detail)
		}
		if got := roleOf(org, xH); got != "admin" {
			t.Fatalf("the last admin's role after a stale member invitation: %s, want admin", got)
		}
		if n := admins(org); n != 1 {
			t.Fatalf("admins after a stale member invitation: %d, want 1", n)
		}
	})

	t.Run("an admin invitation does not raise a member", func(t *testing.T) {
		aH := env.register("sj-a")
		env.verifyEmail(aH)
		a := env.login(aH)
		org := "sjorg" + env.sfx
		env.createOrg(a, org)
		xH := env.register("sj-x")
		env.verifyEmail(xH)
		env.seedMembership(org, xH, "member", "pending")
		var inv struct {
			Token string `json:"token"`
		}
		env.doJSON(a, http.MethodPost, "/api/v1/orgs/"+org+"/invitations", map[string]any{"email": xH + "@example.test", "role": "admin"}, &inv, http.StatusCreated)
		env.doJSON(a, http.MethodPost, "/api/v1/orgs/"+org+"/members/"+xH+"/approve", map[string]any{"role": "member"}, nil, http.StatusOK)

		code, _, detail := problemOf(t, env.do(env.login(xH), http.MethodPost, "/api/v1/invitations/"+inv.Token, nil))
		if code != http.StatusConflict || detail != "You are already a member of "+org+"." {
			t.Fatalf("a member accepting a stale admin invitation: %d %q, want 409 already a member", code, detail)
		}
		if got := roleOf(org, xH); got != "member" {
			t.Fatalf("a member's role after a stale admin invitation: %s, want member", got)
		}
	})
}
