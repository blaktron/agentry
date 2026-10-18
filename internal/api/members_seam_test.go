package api_test

// The membership door an extension reaches (pkg/extension.Deps.Members): a
// directory extension names whom an organization's identity provider
// provisioned and deprovisioned, and the core does what that means. A
// provisioned person is only ever a pending member; a deprovisioned one
// loses the membership, the organization's tokens, every session and every
// remembered browser, except that the last admin keeps the membership.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
)

// membership is the person's state in the organization, "" for none.
func (env *testEnv) membership(orgID, userID uuid.UUID) string {
	env.t.Helper()
	var state string
	err := env.st.Pool().QueryRow(context.Background(),
		`SELECT state FROM memberships WHERE org_id = $1 AND user_id = $2`, orgID, userID).Scan(&state)
	if err != nil {
		return ""
	}
	return state
}

func TestTheMembersSeamProvisionsAPendingMemberOnly(t *testing.T) {
	env := newTestEnvWith(t, cappedSeats(1))
	ctx := context.Background()
	adminH := env.register("mp-admin")
	admin := env.login(adminH)
	orgH := "mporg" + env.sfx
	orgID := uuid.MustParse(env.createOrg(admin, orgH))

	// A newcomer: the account is made at the address, which is taken as
	// verified, and the membership is pending, past the seat cap of one the
	// creator already holds.
	email := "newcomer-" + env.sfx + "@mp.example"
	userID, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: email, UserName: email, DisplayName: "New Comer"})
	if err != nil {
		t.Fatalf("provision a newcomer: %v", err)
	}
	if got := env.membership(orgID, userID); got != "pending" {
		t.Fatalf("a provisioned newcomer is %q, want pending", got)
	}
	var verified bool
	if err := env.st.Pool().QueryRow(ctx, `SELECT email_verified_at IS NOT NULL FROM users WHERE id = $1`, userID).Scan(&verified); err != nil || !verified {
		t.Fatalf("the newcomer's address verified = %v (%v), want true", verified, err)
	}
	// The same person again: the same account, still pending.
	again, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: email})
	if err != nil || again != userID {
		t.Fatalf("provisioning again = %s, %v; want the same account", again, err)
	}
	// Approving them meets the seat wall, as every membership door does.
	var handle string
	if err := env.st.Pool().QueryRow(ctx, `SELECT handle FROM handles WHERE id = $1`, userID).Scan(&handle); err != nil {
		t.Fatal(err)
	}
	res := env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+handle+"/approve", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusForbidden || slug != "seat-allowance" {
		t.Fatalf("approving a provisioned member past the cap: %d %s, want 403 seat-allowance", code, slug)
	}

	// An active member stays active.
	adminID := uuid.MustParse(env.userID(adminH))
	var adminEmail string
	if err := env.st.Pool().QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, adminID).Scan(&adminEmail); err != nil {
		t.Fatal(err)
	}
	if got, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: adminEmail}); err != nil || got != adminID {
		t.Fatalf("provisioning the admin = %s, %v; want their own account", got, err)
	}
	if got := env.membership(orgID, adminID); got != "active" {
		t.Fatalf("provisioning an active member left them %q, want active", got)
	}

	// The audit row names the extension.
	var n int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'scim.user_provision'
		AND org_id = $1 AND target_id = $2 AND actor_kind = 'system' AND detail->>'extension' = 'probe'`, orgID, userID).Scan(&n); err != nil || n == 0 {
		t.Fatalf("provisioning audit rows naming the extension = %d (%v), want at least one", n, err)
	}

	// An account that holds an address without having proved it is not
	// where the organization's membership goes.
	claimH := env.registerEmail("mp-claim", "claimed-"+env.sfx+"@mp.example")
	if _, err := env.st.Pool().Exec(ctx, `UPDATE users SET email_verified_at = NULL WHERE id = (SELECT id FROM handles WHERE handle = $1)`, claimH); err != nil {
		t.Fatal(err)
	}
	if _, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: "claimed-" + env.sfx + "@mp.example"}); !errors.Is(err, api.ErrAddressUnproven) {
		t.Fatalf("provisioning onto an unproven account: %v, want ErrAddressUnproven", err)
	}
	if got := env.membership(orgID, uuid.MustParse(env.userID(claimH))); got != "" {
		t.Fatalf("the unproven account's membership is %q, want none", got)
	}

	// A suspended organization provisions nobody.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = 'suspended' WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: "later-" + env.sfx + "@mp.example"}); !errors.Is(err, api.ErrOrgNotProvisionable) {
		t.Fatalf("provisioning into a suspended organization: %v, want ErrOrgNotProvisionable", err)
	}
	if _, err := env.srvObj.ProvisionMember(ctx, "probe", uuid.New(), api.ProvisionedMember{Email: email}); !errors.Is(err, api.ErrOrgNotProvisionable) {
		t.Fatalf("provisioning into an unknown organization: %v, want ErrOrgNotProvisionable", err)
	}
}

func TestTheMembersSeamDeprovisionTakesEverythingAway(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	adminH := env.register("md-admin")
	admin := env.login(adminH)
	orgH := "mdorg" + env.sfx
	orgID := uuid.MustParse(env.createOrg(admin, orgH))
	// A person belongs to one organization at a time, so another admin
	// makes the second one.
	otherOrgID := uuid.MustParse(env.createOrg(env.login(env.register("md-other")), "mdother"+env.sfx))

	memberH := env.register("md-member")
	env.seedMembership(orgH, memberH, "member", "active")
	memberID := uuid.MustParse(env.userID(memberH))
	bound := env.insertPAT(memberID.String(), orgID.String(), "user:profile")
	elsewhere := env.insertPAT(memberID.String(), otherOrgID.String(), "user:profile")
	session := env.insertSession(memberID.String())
	device := insertTrustedDevice(t, env, memberID.String())

	kept, err := env.srvObj.DeprovisionMember(ctx, "probe", orgID, memberID)
	if err != nil || kept {
		t.Fatalf("deprovision a member = kept %v, %v; want the membership gone", kept, err)
	}
	if got := env.membership(orgID, memberID); got != "" {
		t.Fatalf("after deprovisioning the membership is %q, want none", got)
	}
	for name, c := range map[string]caller{"the organization's token": {name: "bound", pat: bound}, "a session": {name: "sess", session: session}} {
		res := env.do(c, http.MethodGet, "/api/v1/user", nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s after deprovisioning: %d, want 401", name, res.StatusCode)
		}
	}
	if got := deviceState(t, env, device); got != "revoked" {
		t.Fatalf("the remembered browser after deprovisioning is %s, want revoked", got)
	}
	// A token bound to another organization is that organization's to keep.
	res := env.do(caller{name: "elsewhere", pat: elsewhere}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a token bound to another organization after deprovisioning: %d, want 200", res.StatusCode)
	}
	// Again: nothing more to take, and no error.
	if kept, err := env.srvObj.DeprovisionMember(ctx, "probe", orgID, memberID); err != nil || kept {
		t.Fatalf("deprovisioning again = kept %v, %v; want a quiet no-op", kept, err)
	}
	var n int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'scim.user_deactivate'
		AND org_id = $1 AND target_id = $2 AND detail->>'extension' = 'probe'`, orgID, memberID).Scan(&n); err != nil || n == 0 {
		t.Fatalf("deprovisioning audit rows naming the extension = %d (%v), want at least one", n, err)
	}

	// The last admin keeps the membership, so the organization keeps
	// someone who can act, and loses every credential all the same.
	adminID := uuid.MustParse(env.userID(adminH))
	adminDevice := insertTrustedDevice(t, env, adminID.String())
	adminBound := env.insertPAT(adminID.String(), orgID.String(), "user:profile")
	kept, err = env.srvObj.DeprovisionMember(ctx, "probe", orgID, adminID)
	if err != nil || !kept {
		t.Fatalf("deprovision the last admin = kept %v, %v; want the membership kept", kept, err)
	}
	if got := env.membership(orgID, adminID); got != "active" {
		t.Fatalf("the last admin after deprovisioning is %q, want active", got)
	}
	res = env.do(admin, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the last admin's session after deprovisioning: %d, want 401", res.StatusCode)
	}
	res = env.do(caller{name: "admin-bound", pat: adminBound}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the last admin's organization token after deprovisioning: %d, want 401", res.StatusCode)
	}
	if got := deviceState(t, env, adminDevice); got != "revoked" {
		t.Fatalf("the last admin's remembered browser after deprovisioning is %s, want revoked", got)
	}
}
