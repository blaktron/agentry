package api_test

// Seats, invitations and approvals (agentry#361; plan
// organization-subscriptions §4 "Seats" and "The doors", §5.2; D3, D7,
// D12, D26). The chokepoint is one function, so these tests drive each
// door at it: the wall, the fail-closed rule, the token's semantics, and
// the two facts that must survive a cap — nothing already active is
// touched, and a registry with no extension caps nothing.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	samlsp "github.com/blaktron/agentry/internal/auth/saml"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/notify"
)

// seatedResolver is the core resolver with a seat cap, as a tier's
// resolver would answer. broken fails instead, for the fail-closed case.
type seatedResolver struct {
	entitlements.Resolver
	max    int64
	broken bool
}

func (c seatedResolver) Features(ctx context.Context, s entitlements.Subject) (entitlements.Features, error) {
	if c.broken {
		return entitlements.Features{}, context.DeadlineExceeded
	}
	f, err := c.Resolver.Features(ctx, s)
	if err != nil {
		return f, err
	}
	if s.Kind == entitlements.NamespaceOrg {
		f.Seats = entitlements.Cap{Enabled: true, Max: c.max}
	}
	return f, nil
}

func cappedSeats(max int64) func(*api.Server) {
	return func(s *api.Server) {
		s.SetEntitlements(seatedResolver{Resolver: entitlements.NewConfigResolver(config.Default().Limits), max: max})
	}
}

// inviteTo sends an invitation and returns its token, failing the test
// unless it was created. A refusal is asserted by the caller with env.do,
// where the problem body is what matters.
func inviteTo(t *testing.T, env *testEnv, admin caller, org, email string) string {
	t.Helper()
	res := env.do(admin, http.MethodPost, "/api/v1/orgs/"+org+"/invitations",
		map[string]any{"email": email, "role": "member"})
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("invite %s: got %d %s, want 201", email, res.StatusCode, body)
	}
	var out struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(body, &out)
	return out.Token
}

// TestEveryMembershipDoorCountsSeats: with a capped resolver the
// invitation, the approval and the accept each meet the same wall, and the
// refusal names the counts. The doors share one function, so this is one
// rule asserted three ways rather than three rules.
func TestEveryMembershipDoorCountsSeats(t *testing.T) {
	env := newTestEnvWith(t, cappedSeats(2))
	adminH := env.register("st-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "storg" + env.sfx
	env.createOrg(admin, orgH)
	// The creator holds the first of two seats.

	// The second seat goes to an invitation, which reserves it when sent.
	oneH := env.register("st-one")
	env.verifyEmail(oneH)
	token := inviteTo(t, env, admin, orgH, oneH+"@example.test")

	// The third is refused at the invitation, before anybody is told:
	// used 1, invited 1, max 2.
	res := env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/invitations",
		map[string]any{"email": "nobody-" + env.sfx + "@example.test"})
	code, slug, _ := problemOf(t, res)
	if code != http.StatusForbidden || slug != "seat-allowance" {
		t.Fatalf("invitation past the cap: %d %s, want 403 seat-allowance", code, slug)
	}

	// The invitation already holds its seat, so accepting it is not
	// refused for the seat it reserved.
	env.doJSON(env.login(oneH), http.MethodPost, "/api/v1/invitations/"+token, nil, nil, http.StatusOK)

	// An approval past the cap is refused too: a SCIM-provisioned person is
	// pending, which costs nothing, and the wall is at the approval.
	pendingH := env.register("st-pending")
	env.verifyEmail(pendingH)
	env.seedMembership(orgH, pendingH, "member", "pending")
	res = env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+pendingH+"/approve", nil)
	code, slug, detail := problemOf(t, res)
	if code != http.StatusForbidden || slug != "seat-allowance" || !strings.Contains(detail, orgH) {
		t.Fatalf("approval past the cap: %d %s %q, want 403 seat-allowance naming the org", code, slug, detail)
	}

	// The refusal carries the counts so a console can show them.
	var fields struct {
		Used, Invited, Pending, Max int64
	}
	res = env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+pendingH+"/approve", nil)
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	_ = json.Unmarshal(raw, &fields)
	if fields.Used != 2 || fields.Invited != 0 || fields.Pending != 1 || fields.Max != 2 {
		t.Fatalf("seat-allowance fields = %+v, want used 2, invited 0, pending 1, max 2: %s", fields, raw)
	}

	// Nothing already active was touched by any of it.
	var members []struct {
		Role  string `json:"role"`
		State string `json:"state"`
		User  struct {
			Handle string `json:"handle"`
		} `json:"user"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH+"/members", nil, &members, http.StatusOK)
	active := 0
	for _, m := range members {
		if m.State == "active" {
			active++
		}
	}
	if active != 2 {
		t.Fatalf("active members after the refusals = %d, want 2: %+v", active, members)
	}
}

// TestSeatCapNeverRemovesAMember: a cap already exceeded — a subscription
// whose seats were reduced — adds nobody and removes nobody.
func TestSeatCapNeverRemovesAMember(t *testing.T) {
	env := newTestEnvWith(t, cappedSeats(1))
	adminH := env.register("sc-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "scorg" + env.sfx
	env.createOrg(admin, orgH)
	// Two more actives than the allowance of one, as a Portal reduction
	// would leave them.
	for _, h := range []string{"sc-a", "sc-b"} {
		env.seedMembership(orgH, env.register(h), "member", "active")
	}

	res := env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/invitations",
		map[string]any{"email": "sc-more-" + env.sfx + "@example.test"})
	if code, slug, _ := problemOf(t, res); code != http.StatusForbidden || slug != "seat-allowance" {
		t.Fatalf("invitation over an exceeded cap: %d %s, want 403 seat-allowance", code, slug)
	}
	var members []struct {
		State string `json:"state"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH+"/members", nil, &members, http.StatusOK)
	if len(members) != 3 {
		t.Fatalf("members over an exceeded cap = %d, want the 3 that were there", len(members))
	}
}

// TestSeatDoorsFailClosed: an entitlement that cannot be resolved is not
// permission. Nothing is written and nobody becomes a member.
func TestSeatDoorsFailClosed(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("fc-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "fcorg" + env.sfx
	env.createOrg(admin, orgH)
	pendingH := env.register("fc-pending")
	env.verifyEmail(pendingH)
	env.seedMembership(orgH, pendingH, "member", "pending")

	// Break the resolver only now, so the fixture above could be built.
	env.srvObj.SetEntitlements(seatedResolver{
		Resolver: entitlements.NewConfigResolver(config.Default().Limits), broken: true,
	})
	t.Cleanup(func() {
		env.srvObj.SetEntitlements(entitlements.NewConfigResolver(config.Default().Limits))
	})

	res := env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/invitations",
		map[string]any{"email": "fc-someone-" + env.sfx + "@example.test"})
	_ = res.Body.Close()
	if res.StatusCode < 500 {
		t.Fatalf("invitation with an unresolvable entitlement: %d, want a refusal (5xx), never a grant", res.StatusCode)
	}
	res = env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+pendingH+"/approve", nil)
	_ = res.Body.Close()
	if res.StatusCode < 500 {
		t.Fatalf("approval with an unresolvable entitlement: %d, want a refusal", res.StatusCode)
	}
	// Nothing was written: the pending member is still pending, and no
	// invitation exists.
	var state string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT m.state FROM memberships m JOIN handles h ON h.id = m.user_id
		 JOIN handles o ON o.id = m.org_id WHERE h.handle = $1 AND o.handle = $2`, pendingH, orgH).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "pending" {
		t.Fatalf("membership state after a failed-closed approval = %q, want pending", state)
	}
	var invitations int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM org_invitations i JOIN handles o ON o.id = i.org_id WHERE o.handle = $1`, orgH).Scan(&invitations); err != nil {
		t.Fatal(err)
	}
	if invitations != 0 {
		t.Fatalf("invitations written despite the refusal: %d", invitations)
	}
}

// TestSeatCapIsAbsentWithoutAnExtension: the core caps nothing. A registry
// with no billing extension lets an organization hold as many people as it
// likes, which is what §3's "the core with no extension is unchanged" means
// for seats.
func TestSeatCapIsAbsentWithoutAnExtension(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("nc-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "ncorg" + env.sfx
	env.createOrg(admin, orgH)
	for i := range 4 {
		h := env.register("nc-m" + string(rune('a'+i)))
		env.joinOrg(admin, orgH, h)
	}
	var org struct {
		Seats struct {
			Used, Invited, Pending, Max int64
		} `json:"seats"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &org, http.StatusOK)
	if org.Seats.Used != 5 || org.Seats.Max != 0 {
		t.Fatalf("seats with no extension = %+v, want 5 used and an unbounded max", org.Seats)
	}
}

// TestInvitationIsACredential: the token round trip. Hashed at rest, single
// use, expiring, bound to the invited address, and answerable only from a
// session.
func TestInvitationIsACredential(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("iv-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "ivorg" + env.sfx
	env.createOrg(admin, orgH)

	inviteeH := env.register("iv-invitee")
	env.verifyEmail(inviteeH)
	token := inviteTo(t, env, admin, orgH, inviteeH+"@example.test")
	if !strings.HasPrefix(token, "agyi_") {
		t.Fatalf("token %q does not identify itself", token)
	}

	// Stored only as a hash: the plaintext appears nowhere in the table.
	var stored int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM org_invitations WHERE encode(token_sha256,'hex') = $1 OR token_sha256::text LIKE '%' || $2 || '%'`,
		"", token).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("the token itself is in the table (%d rows)", stored)
	}

	// A PAT cannot answer it, however scoped: this is a person's act.
	_, pat := env.mintPAT(admin, "iv-pat", "org:admin", "user:profile")
	res := env.do(caller{name: "pat", pat: pat}, http.MethodPost, "/api/v1/invitations/"+token, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("accept with a PAT: %d, want 403", res.StatusCode)
	}

	// The wrong account may read the offer and may not take it.
	strangerH := env.register("iv-stranger")
	env.verifyEmail(strangerH)
	stranger := env.login(strangerH)
	var offer struct {
		Org        string `json:"org"`
		Email      string `json:"email"`
		Acceptable bool   `json:"acceptable"`
		Reason     string `json:"reason"`
	}
	env.doJSON(stranger, http.MethodGet, "/api/v1/invitations/"+token, nil, &offer, http.StatusOK)
	if offer.Org != orgH || offer.Acceptable || !strings.Contains(offer.Reason, inviteeH) {
		t.Fatalf("offer to the wrong account = %+v, want unacceptable and named", offer)
	}
	res = env.do(stranger, http.MethodPost, "/api/v1/invitations/"+token, nil)
	if code, _, _ := problemOf(t, res); code != http.StatusForbidden {
		t.Fatalf("accept by the wrong account: %d, want 403", code)
	}

	// An account whose address is not verified cannot accept, even when it
	// is the invited one.
	unverifiedH := env.register("iv-unverified")
	unverifiedToken := inviteTo(t, env, admin, orgH, unverifiedH+"@example.test")
	res = env.do(env.login(unverifiedH), http.MethodPost, "/api/v1/invitations/"+unverifiedToken, nil)
	if code, _, detail := problemOf(t, res); code != http.StatusForbidden || !strings.Contains(detail, "Verify") {
		t.Fatalf("accept from an unverified address: %d %q, want 403 asking for verification", code, detail)
	}

	// The invited account accepts, once.
	invitee := env.login(inviteeH)
	env.doJSON(invitee, http.MethodPost, "/api/v1/invitations/"+token, nil, nil, http.StatusOK)
	res = env.do(invitee, http.MethodPost, "/api/v1/invitations/"+token, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("second accept with the same token: %d, want 404", res.StatusCode)
	}

	// An expired invitation is not acceptable either.
	expiredH := env.register("iv-expired")
	env.verifyEmail(expiredH)
	expiredToken := inviteTo(t, env, admin, orgH, expiredH+"@example.test")
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE org_invitations SET expires_at = now() - interval '1 hour' WHERE email = $1`, expiredH+"@example.test"); err != nil {
		t.Fatal(err)
	}
	res = env.do(env.login(expiredH), http.MethodPost, "/api/v1/invitations/"+expiredToken, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("accept of an expired invitation: %d, want 404", res.StatusCode)
	}

	// Revoking releases the seat and stops the token.
	revokedH := env.register("iv-revoked")
	env.verifyEmail(revokedH)
	revokedToken := inviteTo(t, env, admin, orgH, revokedH+"@example.test")
	var open []struct {
		Id    string `json:"id"`
		Email string `json:"email"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH+"/invitations", nil, &open, http.StatusOK)
	id := ""
	for _, o := range open {
		if o.Email == revokedH+"@example.test" {
			id = o.Id
		}
	}
	if id == "" {
		t.Fatalf("the open invitation is not listed: %+v", open)
	}
	env.doJSON(admin, http.MethodDelete, "/api/v1/orgs/"+orgH+"/invitations/"+id, nil, nil, http.StatusNoContent)
	res = env.do(env.login(revokedH), http.MethodPost, "/api/v1/invitations/"+revokedToken, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("accept of a revoked invitation: %d, want 404", res.StatusCode)
	}
}

// TestOneOrgPerPerson: an active member of one organization cannot be
// invited into, or approved into, another (D26).
func TestOneOrgPerPerson(t *testing.T) {
	env := newTestEnv(t)
	firstAdminH := env.register("op-a1")
	env.verifyEmail(firstAdminH)
	firstAdmin := env.login(firstAdminH)
	firstOrg := "oporg1" + env.sfx
	env.createOrg(firstAdmin, firstOrg)

	personH := env.register("op-person")
	env.joinOrg(firstAdmin, firstOrg, personH)

	secondAdminH := env.register("op-a2")
	env.verifyEmail(secondAdminH)
	secondAdmin := env.login(secondAdminH)
	secondOrg := "oporg2" + env.sfx
	env.createOrg(secondAdmin, secondOrg)

	res := env.do(secondAdmin, http.MethodPost, "/api/v1/orgs/"+secondOrg+"/invitations",
		map[string]any{"email": personH + "@example.test"})
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "already-a-member" {
		t.Fatalf("inviting someone else's member: %d %s, want 409 already-a-member", code, slug)
	}

	// The approval door refuses the same person, so a pending row that
	// predates their other membership cannot be waved through either.
	env.seedMembership(secondOrg, personH, "member", "pending")
	res = env.do(secondAdmin, http.MethodPost, "/api/v1/orgs/"+secondOrg+"/members/"+personH+"/approve", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "already-a-member" {
		t.Fatalf("approving someone else's member: %d %s, want 409 already-a-member", code, slug)
	}
}

// TestSCIMProvisionsPending: the IdP says who exists, an admin says who is
// a member. A SCIM create answers 201 whatever the seats, because a pending
// person holds none; approving is where the seat is taken, and declining
// removes them.
func TestSCIMProvisionsPending(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("sp-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "sporg" + env.sfx
	env.createOrg(admin, orgH)
	var tok struct {
		Token string `json:"token"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/scim/tokens", map[string]any{}, &tok, http.StatusCreated)
	scim := caller{name: "scim", pat: tok.Token}

	email := "dana-" + env.sfx + "@acme.example"
	var created struct {
		ID string `json:"id"`
	}
	env.doJSON(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
		"userName": email, "emails": []map[string]any{{"value": email, "primary": true}}, "active": true,
	}, &created, http.StatusCreated)

	var members []struct {
		State string `json:"state"`
		User  struct {
			Handle string `json:"handle"`
		} `json:"user"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH+"/members", nil, &members, http.StatusOK)
	provisioned := ""
	for _, m := range members {
		if m.User.Handle != adminH {
			if m.State != "pending" {
				t.Fatalf("a SCIM-provisioned member is %q, want pending", m.State)
			}
			provisioned = m.User.Handle
		}
	}
	if provisioned == "" {
		t.Fatal("SCIM provisioned nobody")
	}

	// A pending member holds no seat.
	var org struct {
		Seats struct {
			Used, Pending int64
		} `json:"seats"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &org, http.StatusOK)
	if org.Seats.Used != 1 || org.Seats.Pending != 1 {
		t.Fatalf("seats with one pending member = %+v, want 1 used and 1 pending", org.Seats)
	}

	// Approving makes them a member; the seat is taken then.
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+provisioned+"/approve", nil, nil, http.StatusOK)
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &org, http.StatusOK)
	if org.Seats.Used != 2 || org.Seats.Pending != 0 {
		t.Fatalf("seats after the approval = %+v, want 2 used and none pending", org.Seats)
	}

	// Declining removes a pending person and takes no seat.
	email2 := "eli-" + env.sfx + "@acme.example"
	env.doJSON(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
		"userName": email2, "emails": []map[string]any{{"value": email2, "primary": true}}, "active": true,
	}, nil, http.StatusCreated)
	var handle2 string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT h.handle FROM users u JOIN handles h ON h.id = u.id WHERE u.email = $1`, email2).Scan(&handle2); err != nil {
		t.Fatal(err)
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+handle2+"/decline", nil, nil, http.StatusNoContent)
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &org, http.StatusOK)
	if org.Seats.Used != 2 || org.Seats.Pending != 0 {
		t.Fatalf("seats after the decline = %+v, want 2 used and none pending", org.Seats)
	}
}

// TestAddingByHandleIsRetired: an organization is not joined by being
// added. The route keeps role changes and refuses to create a membership,
// naming the door that does.
func TestAddingByHandleIsRetired(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("ar-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "arorg2" + env.sfx
	env.createOrg(admin, orgH)
	strangerH := env.register("ar-stranger")

	res := env.do(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+strangerH, map[string]any{"role": "member"})
	code, slug, detail := problemOf(t, res)
	if code != http.StatusUnprocessableEntity || slug != "validation" || !strings.Contains(detail, "invitations") {
		t.Fatalf("add by handle: %d %s %q, want 422 naming the invitation route", code, slug, detail)
	}

	// A role change for someone who is already here still works.
	env.joinOrg(admin, orgH, strangerH)
	env.doJSON(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+strangerH,
		map[string]any{"role": "admin"}, nil, http.StatusOK)

	// A pending member's role is changed by approving them, not here.
	pendingH := env.register("ar-pending")
	env.seedMembership(orgH, pendingH, "member", "pending")
	res = env.do(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+pendingH, map[string]any{"role": "admin"})
	if code, _, detail := problemOf(t, res); code != http.StatusUnprocessableEntity || !strings.Contains(detail, "approve") {
		t.Fatalf("role change for a pending member: %d %q, want 422 naming approve", code, detail)
	}
}

// invitationNotifier records the offers a test's server sent.
type invitationNotifier struct {
	notify.Notifier
	mu     sync.Mutex
	offers []notify.InviteOffer
}

func (n *invitationNotifier) OrgInvite(_ context.Context, o notify.InviteOffer) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.offers = append(n.offers, o)
	return nil
}

func (n *invitationNotifier) sentTo(email string) *notify.InviteOffer {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := range n.offers {
		if n.offers[i].ToEmail == email {
			return &n.offers[i]
		}
	}
	return nil
}

// TestInvitationToTheOrgsOwnDomainIsMailedAndConfirmsTheAddress: the
// operator's rule of 2026-09-18. An organization that proved it controls a
// domain (DNS TXT) vouches for the addresses there, so an invitation to one
// is mailed even though no verified account holds it — which is the whole
// point, since those are the colleagues an organization most needs to
// invite — and accepting it confirms the accepting account's address.
// Every other address keeps DEV-099's rule.
func TestInvitationToTheOrgsOwnDomainIsMailedAndConfirmsTheAddress(t *testing.T) {
	mails := &invitationNotifier{Notifier: notify.LogNotifier{}}
	env := newTestEnvCfg(t, func(c *config.Config) {
		// An absolute origin, so the offer carries a link a person can open
		// (webPaths.invitationURL answers "" without one, as every other
		// emailed link does).
		c.BaseURL = "https://registry.example"
	}, func(s *api.Server) { s.SetNotifier(mails) })
	adminH := env.register("od-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "odorg" + env.sfx
	env.createOrg(admin, orgH)
	domain := orgH + ".example"
	env.verifyOrgDomain(orgH, domain)

	// An address at the organization's own domain, held by nobody here.
	stranger := "newcomer@" + domain
	var created struct {
		Mailed    bool   `json:"mailed"`
		AcceptUrl string `json:"acceptUrl"`
		Token     string `json:"token"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/invitations",
		map[string]any{"email": stranger}, &created, http.StatusCreated)
	if !created.Mailed {
		t.Fatal("an invitation to the organization's own domain was not mailed")
	}
	if offer := mails.sentTo(stranger); offer == nil || offer.AcceptURL == "" || offer.Org != orgH {
		t.Fatalf("the offer that went to %s: %+v", stranger, offer)
	}

	// An address somewhere else, held by nobody: not mailed, and the admin
	// is handed the link instead (DEV-099 unchanged).
	outsider := "someone@elsewhere.example"
	var elsewhere struct {
		Mailed    bool   `json:"mailed"`
		AcceptUrl string `json:"acceptUrl"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/invitations",
		map[string]any{"email": outsider}, &elsewhere, http.StatusCreated)
	if elsewhere.Mailed || mails.sentTo(outsider) != nil {
		t.Fatal("an invitation to an unverified address elsewhere was mailed")
	}
	if elsewhere.AcceptUrl == "" {
		t.Fatal("the admin was given no link for an invitation that was not mailed")
	}

	// Accepting an invitation at the organization's domain confirms the
	// accepting account's address: the organization holds the mail domain,
	// so it holds the mailbox.
	joinerH := env.registerEmail("od-joiner", "joiner@"+domain)
	joinerToken := inviteTo(t, env, admin, orgH, "joiner@"+domain)
	joiner := env.login(joinerH)
	// Unverified, and accepted anyway.
	env.doJSON(joiner, http.MethodPost, "/api/v1/invitations/"+joinerToken, nil, nil, http.StatusOK)
	var verified bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT email_verified_at IS NOT NULL FROM users u JOIN handles h ON h.id = u.id WHERE h.handle = $1`, joinerH).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("accepting an invitation at the organization's own domain did not confirm the address")
	}

	// An invitation to an address NOT at the organization's domain still
	// needs the account's own verified address.
	elseH := env.registerEmail("od-else", "else@elsewhere.example")
	elseToken := inviteTo(t, env, admin, orgH, "else@elsewhere.example")
	res := env.do(env.login(elseH), http.MethodPost, "/api/v1/invitations/"+elseToken, nil)
	if code, _, detail := problemOf(t, res); code != http.StatusForbidden || !strings.Contains(detail, "Verify") {
		t.Fatalf("accept from an unverified address elsewhere: %d %q, want 403 asking for verification", code, detail)
	}
}

// TestPendingMemberHoldsNothing: a pending membership is not a role. The
// principal every request is authorized against carries active memberships
// only, so someone the IdP provisioned and no admin has approved cannot
// read the organization's members or its teams.
func TestPendingMemberHoldsNothing(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("ph-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "phorg" + env.sfx
	env.createOrg(admin, orgH)

	pendingH := env.register("ph-pending")
	env.verifyEmail(pendingH)
	env.seedMembership(orgH, pendingH, "member", "pending")
	pending := env.login(pendingH)

	for _, path := range []string{"/members", "/teams"} {
		res := env.do(pending, http.MethodGet, "/api/v1/orgs/"+orgH+path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("a pending member reading %s: %d, want 403", path, res.StatusCode)
		}
	}
	// And the organization does not appear as one of theirs with a role
	// that would let a client offer its pages.
	var me struct {
		Orgs []struct {
			Handle string `json:"handle"`
			State  string `json:"state"`
		} `json:"orgs"`
	}
	env.doJSON(pending, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	for _, o := range me.Orgs {
		if o.Handle == orgH && o.State != "pending" {
			t.Fatalf("GET /user shows the pending membership as %q", o.State)
		}
	}
	// Approving them is what confers it.
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+pendingH+"/approve", nil, nil, http.StatusOK)
	env.doJSON(env.login(pendingH), http.MethodGet, "/api/v1/orgs/"+orgH+"/members", nil, nil, http.StatusOK)
}

// TestOrgSSODoesNotLinkAnAccountOutsideTheVerifiedDomain: an organization's
// admin configures its SSO connection, so an assertion alone must not be
// able to speak for an account. Linking an identity to an existing member
// needs the organization's verified domain as well as the membership
// (T-12); a member who joined with a personal address is never linked
// automatically.
func TestOrgSSODoesNotLinkAnAccountOutsideTheVerifiedDomain(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("lk-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "lkorg" + env.sfx
	env.createOrg(admin, orgH)
	env.verifyOrgDomain(orgH, orgH+".example")

	idp := newSAMLTestIdP(t)
	metadataXML, err := samlsp.BuildIDPMetadataXML(idp.entityID, "https://lk-idp.test/sso", idp.certPEM)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/saml", map[string]any{
		"enabled": true,
		"config":  map[string]any{"idpMetadataXml": metadataXML, "emailAttribute": "email"},
	}, nil, http.StatusOK)
	metadataURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/metadata"
	acsURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/acs"

	// A member who joined with a personal address. The IdP asserts it —
	// which an org admin who controls the connection could always do — and
	// the registry refuses to hand over the account.
	personal := "lk-person-" + env.sfx + "@personal.example"
	memberH := env.registerEmail("lk-member", personal)
	env.seedMembership(orgH, memberH, "member", "active")
	res := env.postForm(t, acsURL, url.Values{"SAMLResponse": {idp.signedResponse(t, metadataURL, acsURL, personal, false)}})
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusConflict || !strings.Contains(string(body), "sso-link-required") {
		t.Fatalf("assertion for a member's personal address: %d %s, want 409 sso-link-required", res.StatusCode, body)
	}
	var identities int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM identities i JOIN handles h ON h.id = i.user_id WHERE h.handle = $1`, memberH).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if identities != 0 {
		t.Fatalf("the refused assertion linked %d identity/identities", identities)
	}

	// The same member at the organization's own verified domain: linked,
	// because the organization proved it controls that domain.
	atDomain := "lk-at-" + env.sfx + "@" + orgH + ".example"
	domainMemberH := env.registerEmail("lk-domain", atDomain)
	env.seedMembership(orgH, domainMemberH, "member", "active")
	ok := env.postForm(t, acsURL, url.Values{"SAMLResponse": {idp.signedResponse(t, metadataURL, acsURL, atDomain, false)}})
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("assertion for a member at the verified domain: %d, want 200", ok.StatusCode)
	}
}
