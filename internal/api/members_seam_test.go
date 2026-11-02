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
	"strings"
	"sync"
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
	var mu sync.Mutex
	var registered []api.Event
	env := newTestEnvWith(t, cappedSeats(1), func(s *api.Server) {
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "user.registered" {
				mu.Lock()
				registered = append(registered, ev)
				mu.Unlock()
			}
		})
	})
	registeredFor := func(userID uuid.UUID) []api.Event {
		mu.Lock()
		defer mu.Unlock()
		var out []api.Event
		for _, ev := range registered {
			if ev.UserID == userID {
				out = append(out, ev)
			}
		}
		return out
	}
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
	// What the directory sent is what the core keeps: the member role,
	// marked as provisioned, under the display name given.
	var role, displayName string
	var viaSCIM bool
	if err := env.st.Pool().QueryRow(ctx, `SELECT m.role, m.via_scim, u.display_name FROM memberships m JOIN users u ON u.id = m.user_id
		WHERE m.org_id = $1 AND m.user_id = $2`, orgID, userID).Scan(&role, &viaSCIM, &displayName); err != nil {
		t.Fatal(err)
	}
	if role != "member" || !viaSCIM || displayName != "New Comer" {
		t.Fatalf("the provisioned newcomer is role %q via_scim %v named %q, want a provisioned member named %q", role, viaSCIM, displayName, "New Comer")
	}
	// The same person again: the same account, still pending.
	again, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: email})
	if err != nil || again != userID {
		t.Fatalf("provisioning again = %s, %v; want the same account", again, err)
	}
	// An address is matched as the account holds it: lower case, without
	// the white space around it.
	if got, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: " \t" + strings.ToUpper(email) + " "}); err != nil || got != userID {
		t.Fatalf("provisioning the address in capitals with white space = %s, %v; want the same account", got, err)
	}
	// What is not an address makes no account.
	for _, bad := range []string{"", "   ", "no-at-sign", "two@at@signs.example", "@mp.example", "nobody@"} {
		got, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: bad})
		if err == nil || err.Error() != "api: a provisioned member needs an address" || got != uuid.Nil {
			t.Fatalf("provisioning %q = %s, %v; want the refusal that a provisioned member needs an address", bad, got, err)
		}
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
	// A new account is announced once, to the extensions, with the door it
	// came through and the address taken as verified; the account found
	// again is not announced a second time.
	heard := registeredFor(userID)
	if len(heard) != 1 || heard[0].OrgID != orgID || heard[0].Payload["via"] != "probe" ||
		heard[0].Payload["email"] != email || heard[0].Payload["emailVerified"] != true || heard[0].Payload["handle"] != handle {
		t.Fatalf("user.registered events for the newcomer = %+v, want one naming the extension, the address, its handle and the organization", heard)
	}

	// A directory's user name seeds the handle, and a blank display name
	// falls back to it.
	// The address is kept in lower case, whatever case the directory sent.
	dirEmail := "dirperson-" + env.sfx + "@mp.example"
	dirID, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: "DirPerson-" + env.sfx + "@MP.Example", UserName: "dir-" + env.sfx})
	if err != nil {
		t.Fatalf("provision a person with a user name: %v", err)
	}
	var dirHandle, dirName, dirKept string
	if err := env.st.Pool().QueryRow(ctx, `SELECT h.handle, u.display_name, u.email::text FROM handles h JOIN users u ON u.id = h.id WHERE h.id = $1`, dirID).Scan(&dirHandle, &dirName, &dirKept); err != nil {
		t.Fatal(err)
	}
	if dirKept != dirEmail {
		t.Fatalf("the address provisioned in mixed case is kept as %q, want %q", dirKept, dirEmail)
	}
	if dirHandle != "dir-"+env.sfx || dirName != dirHandle {
		t.Fatalf("the person provisioned as user name %q has handle %q and display name %q, want that handle in both", "dir-"+env.sfx, dirHandle, dirName)
	}

	// An account that proved its address is found, not made again: the
	// membership is pending, the member role, marked as provisioned, and
	// nothing is announced for an account that already existed.
	knownH := env.registerEmail("mp-known", "known-"+env.sfx+"@mp.example")
	knownID := uuid.MustParse(env.userID(knownH))
	announced := len(registeredFor(knownID))
	if got, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: "known-" + env.sfx + "@mp.example"}); err != nil || got != knownID {
		t.Fatalf("provisioning a registered person = %s, %v; want their own account", got, err)
	}
	var knownRole string
	var knownVia bool
	if err := env.st.Pool().QueryRow(ctx, `SELECT role, via_scim FROM memberships WHERE org_id = $1 AND user_id = $2`, orgID, knownID).Scan(&knownRole, &knownVia); err != nil {
		t.Fatal(err)
	}
	if got := env.membership(orgID, knownID); got != "pending" || knownRole != "member" || !knownVia {
		t.Fatalf("a provisioned registered person is %q role %q via_scim %v, want a pending provisioned member", got, knownRole, knownVia)
	}
	if got := registeredFor(knownID); len(got) != announced {
		t.Fatalf("user.registered events for an account that already existed went from %d to %d, want no new one", announced, len(got))
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

	// An organization that is suspended, in its decommission hold or erased
	// provisions nobody, and no account is made for the address.
	for _, state := range []string{"suspended", "decommissioning", "decommissioned"} {
		if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = $2 WHERE id = $1`, orgID, state); err != nil {
			t.Fatal(err)
		}
		if _, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: "later-" + env.sfx + "@mp.example"}); !errors.Is(err, api.ErrOrgNotProvisionable) {
			t.Fatalf("provisioning into an organization that is %s: %v, want ErrOrgNotProvisionable", state, err)
		}
	}
	var made int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, "later-"+env.sfx+"@mp.example").Scan(&made); err != nil || made != 0 {
		t.Fatalf("accounts made for refused provisioning = %d (%v), want none", made, err)
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
	// The admin's credentials are another person's: taking the member's
	// away leaves them standing.
	adminID := uuid.MustParse(env.userID(adminH))
	adminDevice := insertTrustedDevice(t, env, adminID.String())
	adminBound := env.insertPAT(adminID.String(), orgID.String(), "user:profile")

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
	// Nobody else's session, token or remembered browser goes with them.
	for name, c := range map[string]caller{"the admin's session": admin, "the admin's organization token": {name: "admin-bound", pat: adminBound}} {
		res := env.do(c, http.MethodGet, "/api/v1/user", nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s after another member was deprovisioned: %d, want 200", name, res.StatusCode)
		}
	}
	if got := deviceState(t, env, adminDevice); got != "live" {
		t.Fatalf("the admin's remembered browser after another member was deprovisioned is %s, want live", got)
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
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'scim.user_deactivate'
		AND org_id = $1 AND target_id = $2 AND detail ? 'lastAdminKept'`, orgID, memberID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a removed member's audit rows claiming the last admin was kept = %d (%v), want none", n, err)
	}

	// Someone who is not a member loses their sessions and remembered
	// browsers all the same.
	outsiderH := env.register("md-outsider")
	outsiderID := uuid.MustParse(env.userID(outsiderH))
	outsiderSession := env.insertSession(outsiderID.String())
	outsiderDevice := insertTrustedDevice(t, env, outsiderID.String())
	if kept, err := env.srvObj.DeprovisionMember(ctx, "probe", orgID, outsiderID); err != nil || kept {
		t.Fatalf("deprovision someone who is not a member = kept %v, %v; want no error and nothing kept", kept, err)
	}
	res = env.do(caller{name: "outsider", session: outsiderSession}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a non-member's session after deprovisioning: %d, want 401", res.StatusCode)
	}
	if got := deviceState(t, env, outsiderDevice); got != "revoked" {
		t.Fatalf("a non-member's remembered browser after deprovisioning is %s, want revoked", got)
	}

	// An organization suspended, or in its decommission hold, still takes
	// access away: it is never frozen.
	for _, state := range []string{"suspended", "decommissioning"} {
		heldH := env.register("md-held-" + state)
		env.seedMembership(orgH, heldH, "member", "active")
		heldID := uuid.MustParse(env.userID(heldH))
		if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = $2 WHERE id = $1`, orgID, state); err != nil {
			t.Fatal(err)
		}
		if kept, err := env.srvObj.DeprovisionMember(ctx, "probe", orgID, heldID); err != nil || kept {
			t.Fatalf("deprovision a member of an organization that is %s = kept %v, %v; want the membership gone", state, kept, err)
		}
		if got := env.membership(orgID, heldID); got != "" {
			t.Fatalf("a member of an organization that is %s after deprovisioning is %q, want none", state, got)
		}
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = 'active' WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}

	// An admin is removed like anyone while another can still act.
	secondH := env.register("md-second")
	env.seedMembership(orgH, secondH, "admin", "active")
	secondID := uuid.MustParse(env.userID(secondH))
	if kept, err := env.srvObj.DeprovisionMember(ctx, "probe", orgID, secondID); err != nil || kept {
		t.Fatalf("deprovision one of two admins = kept %v, %v; want the membership gone", kept, err)
	}
	if got := env.membership(orgID, secondID); got != "" {
		t.Fatalf("the second admin after deprovisioning is %q, want none", got)
	}

	// The last admin keeps the membership, so the organization keeps
	// someone who can act, and loses every credential all the same. An admin
	// who is still pending, and one whose account is suspended, cannot act:
	// neither makes the first admin any less the last.
	pendingH := env.register("md-pending")
	env.seedMembership(orgH, pendingH, "admin", "pending")
	suspendedH := env.register("md-suspended")
	env.seedMembership(orgH, suspendedH, "admin", "active")
	if _, err := env.st.Pool().Exec(ctx, `UPDATE users SET state = 'suspended' WHERE id = $1`, env.userID(suspendedH)); err != nil {
		t.Fatal(err)
	}
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
	// The audit row says the membership was kept, and by whom it was asked.
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'scim.user_deactivate'
		AND org_id = $1 AND target_id = $2 AND detail->>'lastAdminKept' = 'true' AND detail->>'extension' = 'probe'`, orgID, adminID).Scan(&n); err != nil || n == 0 {
		t.Fatalf("audit rows for the kept last admin naming the extension = %d (%v), want at least one", n, err)
	}
}

// A deprovisioned member of the staff organization is no longer platform
// staff: the standing follows the membership, and the change is recorded.
func TestTheMembersSeamDeprovisionEndsStaffStanding(t *testing.T) {
	f := newStaffFixture(t)
	ctx := context.Background()
	var orgID uuid.UUID
	if err := f.env.st.Pool().QueryRow(ctx, `SELECT id FROM handles WHERE handle = $1`, f.org).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	erin := f.person("erin")
	f.join(erin, "erin-"+f.env.sfx+"@"+f.domain)
	if !f.staff(erin) {
		t.Fatal("setup: a member of the staff organization at its domain must be staff")
	}
	erinID := uuid.MustParse(f.env.userID(erin))
	if kept, err := f.env.srvObj.DeprovisionMember(ctx, "probe", orgID, erinID); err != nil || kept {
		t.Fatalf("deprovision a staff member = kept %v, %v; want the membership gone", kept, err)
	}
	if f.staff(erin) {
		t.Fatal("a deprovisioned member of the staff organization is still platform staff")
	}
	if got := f.staffSyncs(erin, "false"); got != 1 {
		t.Fatalf("staff-standing audit rows for the deprovisioned member = %d, want 1", got)
	}
}
