package api_test

// The roles: there is no owner; the creator is the first admin; the last admin
// cannot be demoted or removed, only joined by another; the security
// reviewer exists only inside a first-party organization; and creating an
// organization needs a verified address and, where an admission extension
// runs, no other organization of the caller's still awaiting activation.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
)

// problemOf reads a problem response's status, slug and detail.
func problemOf(t *testing.T, res *http.Response) (int, string, string) {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	var body struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(b, &body)
	return res.StatusCode, strings.TrimPrefix(body.Type, api.ProblemTypeBase), body.Detail
}

// TestLastAdminCannotBeRemoved: demoting, removing and self-demoting the
// only admin are each 409 last-admin; promoting another member first makes
// every one of them succeed. An erased admin does not count.
func TestLastAdminCannotBeRemoved(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("la-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "laorg" + env.sfx
	env.createOrg(admin, orgH)

	otherH := env.register("la-other")
	env.joinOrg(admin, orgH, otherH)

	var members []struct {
		User struct {
			Handle string `json:"handle"`
		} `json:"user"`
		Role string `json:"role"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH+"/members", nil, &members, http.StatusOK)
	for _, m := range members {
		if m.User.Handle == adminH && m.Role != "admin" {
			t.Fatalf("the creator is %q, want admin", m.Role)
		}
	}

	// Self-demote and remove: refused while nobody else is an admin.
	for _, tc := range []struct {
		name   string
		method string
		body   any
	}{
		{"self-demote", http.MethodPut, map[string]any{"role": "member"}},
		{"self-remove", http.MethodDelete, nil},
	} {
		res := env.do(admin, tc.method, "/api/v1/orgs/"+orgH+"/members/"+adminH, tc.body)
		if code, slug, detail := problemOf(t, res); code != http.StatusConflict || slug != "last-admin" || !strings.Contains(detail, orgH) {
			t.Fatalf("%s of the last admin: %d %s %q, want 409 last-admin naming the org", tc.name, code, slug, detail)
		}
	}

	// Promote the other member; now the first admin may step down and leave.
	env.doJSON(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+otherH,
		map[string]any{"role": "admin"}, nil, http.StatusOK)
	env.doJSON(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+adminH,
		map[string]any{"role": "member"}, nil, http.StatusOK)
	other := env.login(otherH)
	// A demoted admin is a member: no longer able to manage members.
	env.doJSON(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+adminH,
		map[string]any{"role": "admin"}, nil, http.StatusForbidden)
	// The remaining admin is now the last one and is guarded in turn.
	res := env.do(other, http.MethodDelete, "/api/v1/orgs/"+orgH+"/members/"+otherH, nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "last-admin" {
		t.Fatalf("remove the new last admin: %d %s, want 409 last-admin", code, slug)
	}
	// Re-promote the first and remove the second: fine, one admin remains.
	env.doJSON(other, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+adminH,
		map[string]any{"role": "admin"}, nil, http.StatusOK)
	env.doJSON(other, http.MethodDelete, "/api/v1/orgs/"+orgH+"/members/"+otherH, nil, nil, http.StatusNoContent)

	// An erased admin keeps a membership row but cannot act: with the
	// second admin erased, the first is again the last. The second
	// membership is seeded rather than re-invited — the subject here is
	// what the count does with an erased account, not the door.
	admin = env.login(adminH)
	env.seedMembership(orgH, otherH, "admin", "active")
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE users SET state = 'deleted' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, otherH); err != nil {
		t.Fatal(err)
	}
	res = env.do(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+adminH, map[string]any{"role": "member"})
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "last-admin" {
		t.Fatalf("self-demote beside an erased admin: %d %s, want 409 last-admin", code, slug)
	}

	// The erasure case: the last admin cannot erase their
	// account either, and the refusal names the organization; with another
	// admin in place the erasure goes through and takes the membership
	// with it, so no seat is held by an account that is gone.
	res = env.do(admin, http.MethodPost, "/api/v1/user/delete", nil)
	if code, slug, detail := problemOf(t, res); code != http.StatusConflict || slug != "last-admin" || !strings.Contains(detail, orgH) {
		t.Fatalf("erasing the last admin: %d %s %q, want 409 last-admin naming the org", code, slug, detail)
	}
	thirdH := env.register("la-third")
	env.joinOrg(admin, orgH, thirdH)
	env.doJSON(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+thirdH,
		map[string]any{"role": "admin"}, nil, http.StatusOK)
	env.doJSON(admin, http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)
	var held int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM memberships m JOIN users u ON u.id = m.user_id WHERE u.state = 'deleted' AND u.deleted_tombstone IS NOT NULL
		   AND m.org_id = (SELECT id FROM handles WHERE handle = $1)`, orgH).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if held != 0 {
		t.Fatalf("an erased account still holds %d membership(s)", held)
	}
}

// TestSecurityReviewerIsFirstPartyOnly: the role is refused in an ordinary
// organization, with the refusal naming who holds its powers there, and
// assignable inside a first-party one. The owner spelling still
// parses and is refused by naming the roles that exist.
func TestSecurityReviewerIsFirstPartyOnly(t *testing.T) {
	env := newTestEnv(t)
	staffH := env.register("sr-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)
	memberH := env.register("sr-member")
	env.verifyEmail(memberH)

	orgH := "srorg" + env.sfx
	env.createOrg(staff, orgH)
	res := env.do(staff, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+memberH, map[string]any{"role": "security_reviewer"})
	if code, slug, detail := problemOf(t, res); code != http.StatusUnprocessableEntity || slug != "validation" || !strings.Contains(detail, "admins") {
		t.Fatalf("security_reviewer in an ordinary org: %d %s %q, want 422 saying the admins hold it", code, slug, detail)
	}
	res = env.do(staff, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+memberH, map[string]any{"role": "owner"})
	if code, slug, detail := problemOf(t, res); code != http.StatusUnprocessableEntity || slug != "validation" || !strings.Contains(detail, "admin or member") {
		t.Fatalf("the retired owner role: %d %s %q, want 422 naming admin or member", code, slug, detail)
	}

	// The first-party org: created here by a second staff account — the
	// first now belongs to the ordinary organization, and a person belongs
	// to one at a time — or already present from an
	// earlier run over the same database (the handle is fixed by design),
	// in which case this run's account is seeded as one of its admins.
	// (The refusals above needed no membership: an unassignable role is
	// refused before the handler asks who the target is.)
	staffH = env.register("sr-staff2")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff = env.login(staffH)
	res = env.do(staff, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "secureagentry", "displayName": "SecureAgentry"})
	code, slug, _ := problemOf(t, res)
	switch {
	case code == http.StatusCreated:
	case code == http.StatusConflict && slug == "conflict":
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO memberships (org_id, user_id, role)
			 SELECT o.id, u.id, 'admin' FROM handles o, handles u WHERE o.handle = 'secureagentry' AND u.handle = $1
			 ON CONFLICT (org_id, user_id) DO UPDATE SET role = 'admin'`, staffH); err != nil {
			t.Fatal(err)
		}
		staff = env.login(staffH)
	default:
		t.Fatalf("createOrg secureagentry as staff: %d %s", code, slug)
	}
	var m struct {
		Role string `json:"role"`
	}
	env.joinOrg(staff, "secureagentry", memberH)
	env.doJSON(staff, http.MethodPut, "/api/v1/orgs/secureagentry/members/"+memberH,
		map[string]any{"role": "security_reviewer"}, &m, http.StatusOK)
	if m.Role != "security_reviewer" {
		t.Fatalf("first-party reviewer: role %q", m.Role)
	}
	env.doJSON(staff, http.MethodDelete, "/api/v1/orgs/secureagentry/members/"+memberH, nil, nil, http.StatusNoContent)
}

// TestCreateOrgRequiresVerifiedEmail: an account with no verified address
// is refused before the body is read. One with an unconfirmed real address
// is unactivated and refused as such; one the provider gave no address at
// all (a placeholder, which no link can confirm) is refused with its own
// slug. Verifying is all it takes.
func TestCreateOrgRequiresVerifiedEmail(t *testing.T) {
	env := newTestEnv(t)
	h := env.registerUnverified("co-unverified")
	sess := env.login(h)
	res := env.do(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "coorg" + env.sfx, "displayName": "Co"})
	if code, slug, _ := problemOf(t, res); code != http.StatusForbidden || slug != "account-unactivated" {
		t.Fatalf("unactivated createOrg: %d %s, want 403 account-unactivated", code, slug)
	}
	placeholder := env.registerEmailUnverified("co-noaddr", "co-noaddr"+env.sfx+"@oidc"+auth.SyntheticAddressSuffix)
	res = env.do(env.login(placeholder), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "coorg2" + env.sfx, "displayName": "Co"})
	if code, slug, _ := problemOf(t, res); code != http.StatusForbidden || slug != "email-unverified" {
		t.Fatalf("createOrg with no address: %d %s, want 403 email-unverified", code, slug)
	}
	env.verifyEmail(h)
	env.createOrg(sess, "coorg"+env.sfx)
}

// TestOnePendingOrgPerAccount: where an admission extension runs an
// organization is created awaiting activation, and its creator may not
// create another until it is activated through Deps.Orgs; with no
// extension every organization is activated as it is created and the
// pending rule never bites (the core with no extension is unchanged).
// A person belongs to one organization at a time whatever the deployment,
// so between the two creations the creator hands the first organization
// to another admin and leaves it.
func TestOnePendingOrgPerAccount(t *testing.T) {
	t.Run("without an extension", func(t *testing.T) {
		env := newTestEnv(t)
		h := env.register("po-free")
		env.verifyEmail(h)
		sess := env.login(h)
		first := "pofree1" + env.sfx
		env.createOrg(sess, first)
		otherH := env.register("po-free2")
		env.joinOrg(sess, first, otherH)
		env.handOverAndLeave(sess, first, otherH)
		env.createOrg(sess, "pofree2"+env.sfx)
	})
	t.Run("with an admission extension", func(t *testing.T) {
		var srv *api.Server
		env := newTestEnvWith(t, func(s *api.Server) {
			srv = s
			s.Reg().SetAdmitter(&recordingAdmitter{})
		})
		h := env.register("po-paid")
		env.verifyEmail(h)
		sess := env.login(h)
		first := "popaid1" + env.sfx
		firstID := env.createOrg(sess, first)
		res := env.do(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "popaid2" + env.sfx, "displayName": "Second"})
		if code, slug, detail := problemOf(t, res); code != http.StatusConflict || slug != "org-pending" || !strings.Contains(detail, first) {
			t.Fatalf("second org while the first awaits activation: %d %s %q, want 409 org-pending naming it", code, slug, detail)
		}
		// Another account is not held back by this one's pending org.
		otherH := env.register("po-other")
		env.verifyEmail(otherH)
		env.createOrg(env.login(otherH), "poother"+env.sfx)

		did, err := srv.ActivateOrg(context.Background(), uuid.MustParse(firstID))
		if err != nil || !did {
			t.Fatalf("ActivateOrg: %v %v, want true", did, err)
		}
		if did, err := srv.ActivateOrg(context.Background(), uuid.MustParse(firstID)); err != nil || did {
			t.Fatalf("ActivateOrg twice: %v %v, want false and no error", did, err)
		}
		if did, err := srv.ActivateOrg(context.Background(), uuid.New()); err != nil || did {
			t.Fatalf("ActivateOrg of nobody: %v %v, want false and no error", did, err)
		}
		// Activated, the first organization no longer stands in the way of
		// the pending rule — and the creator's membership of it does, until
		// they hand it over and leave.
		res = env.do(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "popaid2" + env.sfx, "displayName": "Second"})
		if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "already-a-member" {
			t.Fatalf("second org while a member of the first: %d %s, want 409 already-a-member", code, slug)
		}
		successorH := env.register("po-succ")
		env.joinOrg(sess, first, successorH)
		env.handOverAndLeave(sess, first, successorH)
		env.createOrg(sess, "popaid2"+env.sfx)
	})
}

// TestLastAdminGuardHoldsUnderConcurrentDemotions: two admins demoting each
// other at the same moment end with exactly one admin, whatever the
// interleaving — the guard counts under the organization's row lock, so the
// second demotion sees the first one committed and is refused (409), or,
// when the first commits before the second is even authorized, the loser
// is no longer an admin at all (403). Never two members.
func TestLastAdminGuardHoldsUnderConcurrentDemotions(t *testing.T) {
	env := newTestEnv(t)
	aH := env.register("cc-a")
	env.verifyEmail(aH)
	a := env.login(aH)
	bH := env.register("cc-b")
	orgH := "ccorg" + env.sfx
	env.createOrg(a, orgH)
	env.joinOrg(a, orgH, bH)
	env.doJSON(a, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+bH, map[string]any{"role": "admin"}, nil, http.StatusOK)
	b := env.login(bH)

	codes := make(chan int, 2)
	start := make(chan struct{})
	for _, pair := range []struct {
		who    caller
		target string
	}{{a, bH}, {b, aH}} {
		go func() {
			<-start
			res := env.do(pair.who, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+pair.target, map[string]any{"role": "member"})
			_ = res.Body.Close()
			codes <- res.StatusCode
		}()
	}
	close(start)
	got := map[int]int{}
	for range 2 {
		got[<-codes]++
	}
	if got[http.StatusOK] != 1 || got[http.StatusConflict]+got[http.StatusForbidden] != 1 {
		t.Fatalf("concurrent demotions: %v, want one 200 and one refusal", got)
	}
	var admins int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM memberships m JOIN handles h ON h.id = m.org_id WHERE h.handle = $1 AND m.role = 'admin'`, orgH).Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if admins != 1 {
		t.Fatalf("admins left: %d, want 1", admins)
	}
}
