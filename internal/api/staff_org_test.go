package api_test

// Platform staff is membership of the staff organization: an
// account is staff exactly while it is active, holds a verified address at
// the staff domain, and is an active member of the staff organization; the
// organization admits nobody else, at every door. These tests drive the
// doors the way a person does and read the flag the way authorisation does.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/testidp"
)

// staffFixture is a test env whose configuration names a staff organization
// unique to the test, and that organization, founded by an account at the
// staff domain.
type staffFixture struct {
	env     *testEnv
	idp     *testidp.IdP
	srv     *api.Server
	org     string // the staff organization's handle
	domain  string // the staff domain
	founder caller
	founded string // the founder's handle
}

func newStaffFixture(t *testing.T) *staffFixture {
	t.Helper()
	return newStaffFixtureWith(t, nil)
}

// newStaffFixtureWith is newStaffFixture with more configuration, given the
// staff organization's handle.
func newStaffFixtureWith(t *testing.T, more func(cfg *config.Config, org string)) *staffFixture {
	t.Helper()
	tag := fmt.Sprintf("%06x", rand.Int63n(1<<24)) //nolint:gosec // test fixture names
	f := &staffFixture{org: "staff" + tag, domain: "staffkit" + tag + ".test"}
	f.env, f.idp = newOIDCTestEnv(t, func(cfg *config.Config) {
		cfg.Auth.StaffOrg, cfg.Auth.StaffDomain = f.org, f.domain
		if more != nil {
			more(cfg, f.org)
		}
	}, func(s *api.Server) { f.srv = s })
	// Founding the staff organization is reserved to platform staff: the
	// founder is seeded staff, the way an operator seeds the first.
	f.founded = f.person("founder")
	f.founder = f.env.login(f.founded)
	f.env.makePlatformStaff(t, f.founded)
	f.env.createOrg(f.founder, f.org)
	return f
}

// person registers an account at the staff domain with a verified address.
func (f *staffFixture) person(prefix string) string {
	f.env.t.Helper()
	h := f.env.registerEmail(prefix, prefix+"-"+f.env.sfx+"@"+f.domain)
	f.env.verifyEmail(h)
	return h
}

// signIn signs a person in through the stand-in provider, at the address
// they were registered with, as a real sign-in does (which recomputes the
// staff flag).
func (f *staffFixture) signIn(handle string) {
	f.env.t.Helper()
	var addr string
	if err := f.env.st.Pool().QueryRow(context.Background(),
		`SELECT email::text FROM users WHERE id = (SELECT id FROM handles WHERE handle = $1)`, handle).Scan(&addr); err != nil {
		f.env.t.Fatal(err)
	}
	in := f.env.signInOIDC(f.env.t, f.idp, config.OIDCProviderID, testidp.Person{
		Subject: "sub-" + handle, Email: addr, EmailVerified: true, Username: handle,
	})
	if in.status != http.StatusOK || in.handle != handle {
		f.env.t.Fatalf("sign-in as %s: %d %s", handle, in.status, in.body)
	}
}

// invite has the founder invite an address to the staff organization and
// returns the response.
func (f *staffFixture) invite(email string) *http.Response {
	f.env.t.Helper()
	return f.env.do(f.founder, http.MethodPost, "/api/v1/orgs/"+f.org+"/invitations",
		map[string]any{"email": email, "role": "member"})
}

// join invites a person by their address and has them accept.
func (f *staffFixture) join(handle, email string) {
	f.env.t.Helper()
	var inv struct {
		Token string `json:"token"`
	}
	f.env.doJSON(f.founder, http.MethodPost, "/api/v1/orgs/"+f.org+"/invitations",
		map[string]any{"email": email, "role": "member"}, &inv, http.StatusCreated)
	f.env.doJSON(f.env.login(handle), http.MethodPost, "/api/v1/invitations/"+inv.Token, nil, nil, http.StatusOK)
}

func (f *staffFixture) staff(handle string) bool {
	f.env.t.Helper()
	var staff bool
	if err := f.env.st.Pool().QueryRow(context.Background(),
		`SELECT platform_staff FROM users WHERE id = (SELECT id FROM handles WHERE handle = $1)`, handle).Scan(&staff); err != nil {
		f.env.t.Fatal(err)
	}
	return staff
}

func (f *staffFixture) staffSyncs(handle, want string) int {
	f.env.t.Helper()
	var n int
	if err := f.env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.staff_sync'
		   AND target_id = (SELECT id FROM handles WHERE handle = $1)
		   AND detail->>'rule' = 'staff-org' AND detail->>'platformStaff' = $2`, handle, want).Scan(&n); err != nil {
		f.env.t.Fatal(err)
	}
	return n
}

func wantProblem(t *testing.T, res *http.Response, status int, typ string) {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	var body strings.Builder
	buf := make([]byte, 4096)
	n, _ := res.Body.Read(buf)
	body.Write(buf[:n])
	if res.StatusCode != status || !strings.Contains(body.String(), typ) {
		t.Fatalf("got %d %s, want %d %s", res.StatusCode, body.String(), status, typ)
	}
}

// staffSyncReasons lists, oldest first, the reasons the audit rows of an
// account's staff changes give.
func (f *staffFixture) staffSyncReasons(userID string) string {
	f.env.t.Helper()
	rows, err := f.env.st.Pool().Query(context.Background(),
		`SELECT detail->>'reason' FROM audit_events WHERE action = 'user.staff_sync' AND target_id = $1::uuid
		   AND detail->>'rule' = 'staff-org' ORDER BY occurred_at, id`, userID)
	if err != nil {
		f.env.t.Fatal(err)
	}
	defer rows.Close()
	var reasons []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			f.env.t.Fatal(err)
		}
		reasons = append(reasons, r)
	}
	if err := rows.Err(); err != nil {
		f.env.t.Fatal(err)
	}
	return strings.Join(reasons, ",")
}

// TestStaffIsMembershipOfTheStaffOrg: founding the staff organization,
// joining it and leaving it grant and revoke staff in the same act, each
// change audited with the rule.
func TestStaffIsMembershipOfTheStaffOrg(t *testing.T) {
	f := newStaffFixture(t)
	if !f.staff(f.founded) {
		t.Fatal("the staff organization's founder is its first member and must be staff")
	}

	alice := f.person("alice")
	if f.staff(alice) {
		t.Fatal("an address at the domain alone must not make staff")
	}
	f.join(alice, "alice-"+f.env.sfx+"@"+f.domain)
	if !f.staff(alice) {
		t.Fatal("joining the staff organization must make staff at once")
	}
	if n := f.staffSyncs(alice, "true"); n != 1 {
		t.Fatalf("the grant must be audited once with the rule, got %d", n)
	}
	if got := f.staffSyncReasons(f.env.userID(alice)); got != "membership" {
		t.Fatalf("the grant's audit reasons = %q, want membership", got)
	}

	f.env.doJSON(f.founder, http.MethodDelete, "/api/v1/orgs/"+f.org+"/members/"+alice, nil, nil, http.StatusNoContent)
	if f.staff(alice) {
		t.Fatal("removal from the staff organization must revoke staff at once")
	}
	if n := f.staffSyncs(alice, "false"); n != 1 {
		t.Fatalf("the revocation must be audited once with the rule, got %d", n)
	}
	if got := f.staffSyncReasons(f.env.userID(alice)); got != "membership,membership" {
		t.Fatalf("the audit reasons after the revocation = %q, want membership,membership", got)
	}
}

// TestStaffOrgAdmitsOnlyItsDomain: every door into the staff organization
// refuses an address outside its domain — a stranger, a subdomain, a
// look-alike — while any other organization invites whom it likes.
func TestStaffOrgAdmitsOnlyItsDomain(t *testing.T) {
	f := newStaffFixture(t)
	for _, email := range []string{
		"bob-" + f.env.sfx + "@elsewhere.test",
		"bob-" + f.env.sfx + "@ops." + f.domain,
		"bob-" + f.env.sfx + "@" + f.domain + ".evil.test",
		"bob-" + f.env.sfx + "@" + strings.Replace(f.domain, "s", "\u0455", 1), // Cyrillic dze
		// Characters that fold to the domain's own letters under case folding.
		"bob-" + f.env.sfx + "@" + strings.Replace(f.domain, "k", "\u212a", 1), // Kelvin sign
		"bob-" + f.env.sfx + "@" + strings.Replace(f.domain, "i", "\u0130", 1), // dotted capital I
	} {
		wantProblem(t, f.invite(email), http.StatusConflict, "staff-org-domain")
	}

	// An account whose address is outside the domain cannot be approved in
	// either: seeded pending (the fold-in's or provisioning's row), the approval is
	// the chokepoint and refuses it.
	carol := f.env.registerEmail("carol", "carol-"+f.env.sfx+"@elsewhere.test")
	f.env.verifyEmail(carol)
	f.env.seedMembership(f.org, carol, "member", "pending")
	wantProblem(t, f.env.do(f.founder, http.MethodPost, "/api/v1/orgs/"+f.org+"/members/"+carol+"/approve",
		map[string]any{"role": "member"}), http.StatusConflict, "staff-org-domain")
	if f.staff(carol) {
		t.Fatal("a refused approval must leave the flag false")
	}
	// An address at the domain that nobody has verified is not at the domain
	// either: seeded pending, the approval refuses it as well.
	dora := f.env.registerEmailUnverified("dora", "dora-"+f.env.sfx+"@"+f.domain)
	f.env.seedMembership(f.org, dora, "member", "pending")
	doraRes := f.env.do(f.founder, http.MethodPost, "/api/v1/orgs/"+f.org+"/members/"+dora+"/approve", map[string]any{"role": "member"})
	if code, slug, _ := problemOf(t, doraRes); code != http.StatusConflict || slug != "staff-org-domain" {
		t.Fatalf("approving an unverified address at the domain: %d %s, want 409 staff-org-domain", code, slug)
	}
	if f.staff(dora) {
		t.Fatal("a refused approval of an unverified address must leave the flag false")
	}

	// Another organization is untouched by the rule.
	other := f.env.register("otherowner")
	f.env.verifyEmail(other)
	otherOwner := f.env.login(other)
	otherOrg := "other" + f.env.sfx
	f.env.createOrg(otherOwner, otherOrg)
	res := f.env.do(otherOwner, http.MethodPost, "/api/v1/orgs/"+otherOrg+"/invitations",
		map[string]any{"email": "bob-" + f.env.sfx + "@elsewhere.test", "role": "member"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("another organization's invitation: got %d want 201", res.StatusCode)
	}
}

// TestStaffOrgFoundingIsReservedToStaffAtItsDomain: nobody makes themselves
// staff by founding the staff organization — a person at its domain who is
// not staff is refused the handle — and a staff founder must be at its
// domain too, since they become its first member.
func TestStaffOrgFoundingIsReservedToStaffAtItsDomain(t *testing.T) {
	tag := fmt.Sprintf("%06x", rand.Int63n(1<<24)) //nolint:gosec // test fixture names
	org, domain := "staff"+tag, "staff"+tag+".test"
	env := newTestEnvCfg(t, func(cfg *config.Config) { cfg.Auth.StaffOrg, cfg.Auth.StaffDomain = org, domain })
	body := map[string]any{"handle": org, "displayName": "Staff"}

	insider := env.registerEmail("insider", "insider-"+env.sfx+"@"+domain)
	env.verifyEmail(insider)
	res := env.do(env.login(insider), http.MethodPost, "/api/v1/orgs", body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity && res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a non-staff person at the domain founding the staff organization: got %d, want a refusal", res.StatusCode)
	}
	var staff bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT platform_staff FROM users WHERE id = (SELECT id FROM handles WHERE handle = $1)`, insider).Scan(&staff); err != nil {
		t.Fatal(err)
	}
	if staff {
		t.Fatal("a refused founding must not make staff")
	}

	outsider := env.registerEmail("outsider", "outsider-"+env.sfx+"@elsewhere.test")
	env.verifyEmail(outsider)
	sess := env.login(outsider)
	env.makePlatformStaff(t, outsider)
	wantProblem(t, env.do(sess, http.MethodPost, "/api/v1/orgs", body), http.StatusConflict, "staff-org-domain")
}

// TestStaffOrgProvisionsOnlyItsDomain: the members seam refuses to
// provision an address outside the staff organization's domain before any
// account is made for it.
func TestStaffOrgProvisionsOnlyItsDomain(t *testing.T) {
	f := newStaffFixture(t)
	ctx := context.Background()
	var orgID uuid.UUID
	if err := f.env.st.Pool().QueryRow(ctx, `SELECT id FROM handles WHERE handle = $1`, f.org).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	outside := "dave-" + f.env.sfx + "@elsewhere.test"
	if _, err := f.env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: outside}); !errors.Is(err, registry.ErrStaffOrgDomain) {
		t.Fatalf("provisioning outside the domain: %v, want ErrStaffOrgDomain", err)
	}
	var made int
	if err := f.env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, outside).Scan(&made); err != nil {
		t.Fatal(err)
	}
	if made != 0 {
		t.Fatal("a refused provisioning must make no account")
	}
	if _, err := f.env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: "erin-" + f.env.sfx + "@" + f.domain}); err != nil {
		t.Fatalf("provisioning at the domain: %v", err)
	}
}

// TestStaffEndsWithErasure: an erased account is not staff.
func TestStaffEndsWithErasure(t *testing.T) {
	// The hold is zero so the staff organization's own erasure, at the end,
	// is due as soon as it begins.
	f := newStaffFixtureWith(t, func(cfg *config.Config, _ string) { cfg.Orgs.DecommissionHold = 0 })
	gina := f.person("gina")
	f.join(gina, "gina-"+f.env.sfx+"@"+f.domain)
	if !f.staff(gina) {
		t.Fatal("setup: gina must be staff")
	}
	// Erasure releases the handle, so the account is read by its id after.
	id := f.env.userID(gina)
	f.env.doJSON(f.env.login(gina), http.MethodPost, "/api/v1/user/delete?publishedContent=yank", nil, nil, http.StatusNoContent)
	var staff bool
	if err := f.env.st.Pool().QueryRow(context.Background(),
		`SELECT platform_staff FROM users WHERE id = $1::uuid`, id).Scan(&staff); err != nil {
		t.Fatal(err)
	}
	if staff {
		t.Fatal("an erased account must not be staff")
	}
	if n := f.env.countStaffSyncs(id, "false"); n != 1 {
		t.Fatalf("the erasure's revocation must be audited once, got %d", n)
	}
	if got := f.staffSyncReasons(id); got != "membership,erasure" {
		t.Fatalf("the audit reasons of the grant and the erasure = %q, want membership,erasure", got)
	}

	// Erasing the staff organization itself ends its members' staff with it.
	ctx := context.Background()
	if !f.staff(f.founded) {
		t.Fatal("setup: the founder must be staff")
	}
	var orgID string
	if err := f.env.st.Pool().QueryRow(ctx, `SELECT id::text FROM handles WHERE handle = $1`, f.org).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	f.env.doJSON(f.founder, http.MethodPost, "/api/v1/orgs/"+f.org+"/decommission", map[string]any{"confirm": f.org}, nil, http.StatusOK)
	if _, err := f.srv.RunOrgDecommissionSweep(ctx); err != nil {
		t.Fatal(err)
	}
	var orgState string
	if err := f.env.st.Pool().QueryRow(ctx, `SELECT state FROM orgs WHERE id = $1::uuid`, orgID).Scan(&orgState); err != nil || orgState != "decommissioned" {
		t.Fatalf("the staff organization after its sweep: %q %v, want decommissioned", orgState, err)
	}
	if f.staff(f.founded) {
		t.Fatal("a member of the erased staff organization must not stay staff")
	}
}

// TestStaffFollowsSignInAndStartup: a flag set by any other means — the SQL
// a seed script writes, a directory group — is corrected at the
// person's next sign-in and by the resync the server runs when it starts.
func TestStaffFollowsSignInAndStartup(t *testing.T) {
	f := newStaffFixture(t)
	hank := f.person("hank")
	f.env.makePlatformStaff(t, hank)
	f.signIn(hank)
	if f.staff(hank) {
		t.Fatal("a sign-in must revoke a flag the rule does not grant")
	}

	ivy := f.person("ivy")
	f.env.makePlatformStaff(t, ivy)
	if _, err := f.srv.Reg().ResyncStaff(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.staff(ivy) {
		t.Fatal("the start-up resync must revoke a flag the rule does not grant")
	}
	if !f.staff(f.founded) {
		t.Fatal("the start-up resync must keep a member of the staff organization staff")
	}
	if got := f.staffSyncReasons(f.env.userID(hank)); got != "sign-in" {
		t.Fatalf("the sign-in's audit reasons = %q, want sign-in", got)
	}
	if got := f.staffSyncReasons(f.env.userID(ivy)); got != "startup" {
		t.Fatalf("the resync's audit reasons = %q, want startup", got)
	}

	// A person waiting for approval is not a member yet: signing in grants
	// nothing.
	jess := f.person("jess")
	f.env.seedMembership(f.org, jess, "member", "pending")
	f.signIn(jess)
	if f.staff(jess) {
		t.Fatal("a pending member of the staff organization must not be staff")
	}

	// Founding an organization is a membership change too: a flag the rule
	// does not grant does not survive it.
	kim := f.person("kim")
	f.env.makePlatformStaff(t, kim)
	f.env.createOrg(f.env.login(kim), "kimorg"+f.env.sfx)
	if f.staff(kim) {
		t.Fatal("founding an organization must revoke a flag the rule does not grant")
	}

	// The resync also grants: an active member of the staff organization at
	// its domain whose flag was never set becomes staff.
	pia := f.person("pia")
	f.env.seedMembership(f.org, pia, "member", "active")
	if f.staff(pia) {
		t.Fatal("setup: pia must not be staff before the resync")
	}
	if _, err := f.srv.Reg().ResyncStaff(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !f.staff(pia) {
		t.Fatal("the start-up resync must grant a member of the staff organization at its domain")
	}

	// An address nobody has verified is not at the domain, so an active
	// member of the staff organization holding one is not staff.
	eve := f.env.registerEmailUnverified("eve", "eve-"+f.env.sfx+"@"+f.domain)
	f.env.seedMembership(f.org, eve, "member", "active")
	if _, err := f.srv.Reg().ResyncStaff(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.staff(eve) {
		t.Fatal("a member of the staff organization with an unverified address must not be staff")
	}

	// Changing a member's role recomputes the flag as well: one the rule does
	// not grant does not survive it.
	kimOrg := f.env.login(kim)
	omar := f.env.register("omar")
	f.env.joinOrg(kimOrg, "kimorg"+f.env.sfx, omar)
	f.env.makePlatformStaff(t, omar)
	f.env.doJSON(kimOrg, http.MethodPut, "/api/v1/orgs/kimorg"+f.env.sfx+"/members/"+omar, map[string]any{"role": "admin"}, nil, http.StatusOK)
	if f.staff(omar) {
		t.Fatal("a role change must revoke a flag the rule does not grant")
	}

	// An account that is not active is not staff, whatever else is true of it.
	lena := f.person("lena")
	f.join(lena, "lena-"+f.env.sfx+"@"+f.domain)
	if !f.staff(lena) {
		t.Fatal("setup: lena must be staff")
	}
	if _, err := f.env.st.Pool().Exec(context.Background(),
		`UPDATE users SET state = 'suspended' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, lena); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.Reg().SyncStaff(context.Background(), uuid.MustParse(f.env.userID(lena)), registry.StaffSyncState, audit.Event{}); err != nil {
		t.Fatal(err)
	}
	if f.staff(lena) {
		t.Fatal("a suspended account must not be staff")
	}
}

// TestStaffUnconfiguredLeavesTheFlag: with no staff organization named,
// nothing syncs and a seeded flag stands (the default for a
// deployment with no staff organization, and for every other test here).
func TestStaffUnconfiguredLeavesTheFlag(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("unconfigured")
	env.makePlatformStaff(t, h)
	env.login(h)
	var staff bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT platform_staff FROM users WHERE id = (SELECT id FROM handles WHERE handle = $1)`, h).Scan(&staff); err != nil {
		t.Fatal(err)
	}
	if !staff {
		t.Fatal("with no staff organization configured the flag must be left alone")
	}

	// Nothing the rule runs at touches it either: a sign-in's recomputation,
	// the start-up resync, and a membership change (founding an organization).
	// A staff organization named without its domain is no configuration
	// either: the rule needs both.
	half := newTestEnvCfg(t, func(cfg *config.Config) { cfg.Auth.StaffOrg = "half" + fmt.Sprintf("%06x", rand.Int63n(1<<24)) }) //nolint:gosec // test fixture names
	hh := half.register("half-configured")
	for _, e := range []struct {
		env    *testEnv
		handle string
	}{{env, h}, {half, hh}} {
		e.env.makePlatformStaff(t, e.handle)
		e.env.verifyEmail(e.handle)
		if err := e.env.srvObj.Reg().SyncStaff(context.Background(), uuid.MustParse(e.env.userID(e.handle)), registry.StaffSyncSignIn, audit.Event{}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.env.srvObj.Reg().ResyncStaff(context.Background()); err != nil {
			t.Fatal(err)
		}
		e.env.createOrg(e.env.login(e.handle), "unconfigured"+e.handle)
		if err := e.env.st.Pool().QueryRow(context.Background(),
			`SELECT platform_staff FROM users WHERE id = (SELECT id FROM handles WHERE handle = $1)`, e.handle).Scan(&staff); err != nil {
			t.Fatal(err)
		}
		if !staff {
			t.Fatalf("%s: a sync with no complete staff configuration must leave the flag alone", e.handle)
		}
	}
}

func (env *testEnv) countStaffSyncs(userID, want string) int {
	env.t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.staff_sync' AND target_id = $1::uuid
		   AND detail->>'rule' = 'staff-org' AND detail->>'platformStaff' = $2`, userID, want).Scan(&n); err != nil {
		env.t.Fatal(err)
	}
	return n
}

// TestStaffOrgInvitationAtItsVerifiedDomainVerifiesInTheSameAct: accepting
// an invitation at the organization's verified domain confirms the address,
// and it does so inside the activation, so an invitee whose
// address was not yet verified is admitted to the staff organization rather
// than refused as unverified.
func TestStaffOrgInvitationAtItsVerifiedDomainVerifiesInTheSameAct(t *testing.T) {
	f := newStaffFixture(t)
	f.env.verifyOrgDomain(f.org, f.domain)
	jo := f.env.registerEmailUnverified("jo", "jo-"+f.env.sfx+"@"+f.domain)
	var inv struct {
		Token string `json:"token"`
	}
	f.env.doJSON(f.founder, http.MethodPost, "/api/v1/orgs/"+f.org+"/invitations",
		map[string]any{"email": "jo-" + f.env.sfx + "@" + f.domain, "role": "member"}, &inv, http.StatusCreated)
	f.env.doJSON(f.env.login(jo), http.MethodPost, "/api/v1/invitations/"+inv.Token, nil, nil, http.StatusOK)
	if !f.staff(jo) {
		t.Fatal("an invitee at the staff organization's verified domain must be admitted and made staff")
	}
}

// TestStaffOrgMembersWhoAreNotStaffAreReported: a member of the staff
// organization outside its domain is reported by the start-up check, and
// stays a member.
func TestStaffOrgMembersWhoAreNotStaffAreReported(t *testing.T) {
	f := newStaffFixture(t)
	old := f.env.registerEmail("oldtimer", "oldtimer-"+f.env.sfx+"@elsewhere.test")
	f.env.verifyEmail(old)
	f.env.seedMembership(f.org, old, "member", "active") // seeded past the domain check
	if _, err := f.srv.Reg().ResyncStaff(context.Background()); err != nil {
		t.Fatal(err)
	}
	handles, err := f.srv.Reg().StaffOrgMembersNotStaff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(handles) != 1 || handles[0] != old {
		t.Fatalf("reported %v, want only %s", handles, old)
	}
	if f.staff(old) {
		t.Fatal("a member outside the domain is staff")
	}
	var state string
	if err := f.env.st.Pool().QueryRow(context.Background(),
		`SELECT state FROM memberships WHERE org_id = (SELECT id FROM handles WHERE handle = $1)
		   AND user_id = (SELECT id FROM handles WHERE handle = $2)`, f.org, old).Scan(&state); err != nil || state != "active" {
		t.Fatalf("the member was touched: %q %v", state, err)
	}
}
