package api_test

// Seats, invitations and approvals. The chokepoint is one function, so these tests drive each
// door at it: the wall, the fail-closed rule, the token's semantics, and
// the two facts that must survive a cap — nothing already active is
// touched, and a registry with no extension caps nothing.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/notify"
)

// seatedResolver is the core resolver with a seat cap, as a tier's
// resolver would answer. broken fails instead, for the fail-closed case;
// none answers for a subscription that includes no seats at all.
type seatedResolver struct {
	entitlements.Resolver
	max    int64
	broken bool
	none   bool
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
		f.Seats = entitlements.Cap{Enabled: !c.none, Max: c.max}
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

	// A person waiting for approval holds none, so the invitations below are
	// not turned away on their account.
	pendingH := env.register("st-pending")
	env.verifyEmail(pendingH)
	env.seedMembership(orgH, pendingH, "member", "pending")

	// An invitation that has expired reserves nothing: it is an offer nobody
	// can take any more, so it does not stand in the way of the next one.
	lapsedH := env.register("st-lapsed")
	env.verifyEmail(lapsedH)
	inviteTo(t, env, admin, orgH, lapsedH+"@example.test")
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE org_invitations SET expires_at = now() - interval '1 hour' WHERE email = $1`, lapsedH+"@example.test"); err != nil {
		t.Fatal(err)
	}

	// The second seat goes to an invitation, which reserves it when sent.
	oneH := env.register("st-one")
	env.verifyEmail(oneH)
	token := inviteTo(t, env, admin, orgH, oneH+"@example.test")

	// Sending the same address another invitation replaces the first: the old
	// token stops working and its seat is given back, so the new one is not
	// refused for the seat that the first one held.
	superseded := token
	token = inviteTo(t, env, admin, orgH, oneH+"@example.test")
	if token == superseded {
		t.Fatal("a second invitation to the same address reused the first token")
	}
	stale := env.do(env.login(oneH), http.MethodPost, "/api/v1/invitations/"+superseded, nil)
	if code, _, _ := problemOf(t, stale); code != http.StatusNotFound {
		t.Fatalf("accept with a superseded token: %d, want 404", code)
	}

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

	// An approval past the cap is refused too: a provisioned person is
	// pending, which costs nothing, and the wall is at the approval.
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
	// Two more actives than the allowance of one, as a seat reduction
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
	// A subscription that includes no seats is no permission either, and the
	// refusal says so instead of quoting an allowance.
	env.srvObj.SetEntitlements(seatedResolver{
		Resolver: entitlements.NewConfigResolver(config.Default().Limits), none: true,
	})
	res = env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/invitations",
		map[string]any{"email": "fc-nobody-" + env.sfx + "@example.test"})
	if code, slug, detail := problemOf(t, res); code != http.StatusForbidden || slug != "feature-not-included" || !strings.Contains(detail, orgH) {
		t.Fatalf("invitation with no seats in the subscription: %d %s %q, want 403 feature-not-included naming the org", code, slug, detail)
	}
	res = env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+pendingH+"/approve", nil)
	if code, slug, detail := problemOf(t, res); code != http.StatusForbidden || slug != "feature-not-included" || !strings.Contains(detail, orgH) {
		t.Fatalf("approval with no seats in the subscription: %d %s %q, want 403 feature-not-included naming the org", code, slug, detail)
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
// likes: the core with no extension is unchanged.
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
	// How many people an organization licenses is its own business: neither
	// the public profile nor a signed-in stranger's read carries the seats.
	outsiderH := env.register("nc-outsider")
	env.verifyEmail(outsiderH)
	for _, c := range []caller{anonymous, env.login(outsiderH)} {
		res := env.do(c, http.MethodGet, "/api/v1/orgs/"+orgH, nil)
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK || strings.Contains(string(body), `"seats"`) {
			t.Fatalf("%s reading the organization: %d %s, want 200 without its seats", c.name, res.StatusCode, body)
		}
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
	// What is stored is the SHA-256 of the token and nothing else about it:
	// not the token's bytes, and not the audit row of the act that made it.
	var hashed, inClear, audited int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT
		   (SELECT count(*) FROM org_invitations WHERE token_sha256 = sha256(convert_to($1, 'UTF8'))),
		   (SELECT count(*) FROM org_invitations WHERE token_sha256 = convert_to($1, 'UTF8')),
		   (SELECT count(*) FROM audit_events WHERE target_kind = 'invitation' AND detail::text LIKE '%' || $1 || '%')`,
		token).Scan(&hashed, &inClear, &audited); err != nil {
		t.Fatal(err)
	}
	if hashed != 1 || inClear != 0 || audited != 0 {
		t.Fatalf("token at rest: %d rows hold its SHA-256, %d hold its bytes, %d audit rows carry it; want 1, 0, 0", hashed, inClear, audited)
	}
	// It stands for seven days.
	var expires time.Time
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT expires_at FROM org_invitations WHERE email = $1`, inviteeH+"@example.test").Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if left := time.Until(expires); left > 7*24*time.Hour || left < 7*24*time.Hour-time.Minute {
		t.Fatalf("invitation expires in %s, want seven days", left)
	}

	// Only an address is invited, and the address is taken as typed minus the
	// space around it.
	for _, bad := range []string{"", "nobody", "nobody@", "@example.test", "no body@example.test", "a@@example.test", "a@example"} {
		res := env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/invitations", map[string]any{"email": bad})
		if code, slug, _ := problemOf(t, res); code != http.StatusUnprocessableEntity || slug != "validation" {
			t.Fatalf("invitation to %q: %d %s, want 422 validation", bad, code, slug)
		}
	}
	paddedH := env.register("iv-padded")
	var padded struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/invitations",
		map[string]any{"email": "  " + paddedH + "@example.test  "}, &padded, http.StatusCreated)
	if padded.Email != paddedH+"@example.test" || padded.Role != "member" {
		t.Fatalf("invitation to a padded address with no role: %+v, want the trimmed address as a member", padded)
	}

	// The offer is answered from a session only: an anonymous caller is not
	// signed in, whatever token they hold.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		res := env.do(anonymous, method, "/api/v1/invitations/"+token, nil)
		if code, _, _ := problemOf(t, res); code != http.StatusUnauthorized {
			t.Fatalf("%s the invitation anonymously: %d, want 401", method, code)
		}
	}

	// A PAT cannot answer it, however scoped: this is a person's act.
	_, pat := env.mintPAT(admin, "iv-pat", "org:admin", "user:profile")
	res := env.do(caller{name: "pat", pat: pat}, http.MethodPost, "/api/v1/invitations/"+token, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("accept with a PAT: %d, want 403", res.StatusCode)
	}
	// The invitee's own token is no better: the answer is a person's, and the
	// offer stays open.
	_, inviteePAT := env.mintPAT(env.login(inviteeH), "iv-invitee-pat", "user:profile", "org:admin")
	res = env.do(caller{name: "pat", pat: inviteePAT}, http.MethodPost, "/api/v1/invitations/"+token, nil)
	if code, _, detail := problemOf(t, res); code != http.StatusForbidden || !strings.Contains(detail, "session") {
		t.Fatalf("accept with the invitee's own PAT: %d %q, want 403 asking for a session", code, detail)
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
	unverifiedH := env.registerUnverified("iv-unverified")
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

	// An accepted invitation is a record, not an open offer: it cannot be
	// revoked away.
	var spentID string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT id::text FROM org_invitations WHERE email = $1 AND accepted_at IS NOT NULL`, inviteeH+"@example.test").Scan(&spentID); err != nil {
		t.Fatal(err)
	}
	res = env.do(admin, http.MethodDelete, "/api/v1/orgs/"+orgH+"/invitations/"+spentID, nil)
	if code, _, _ := problemOf(t, res); code != http.StatusNotFound {
		t.Fatalf("revoking an accepted invitation: %d, want 404", code)
	}

	// An invitation sent to someone who then became a member by another door
	// is not a second way in: accepting it says they are here already, and the
	// offer stays open.
	staleH := env.register("iv-stale")
	env.verifyEmail(staleH)
	env.seedMembership(orgH, staleH, "member", "pending")
	staleToken := inviteTo(t, env, admin, orgH, staleH+"@example.test")
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+staleH+"/approve", nil, nil, http.StatusOK)
	res = env.do(env.login(staleH), http.MethodPost, "/api/v1/invitations/"+staleToken, nil)
	if code, _, detail := problemOf(t, res); code != http.StatusConflict || !strings.Contains(detail, orgH) {
		t.Fatalf("accepting an invitation as a current member: %d %q, want 409 naming the org", code, detail)
	}
	var stillOpen int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM org_invitations WHERE email = $1 AND accepted_at IS NULL`, staleH+"@example.test").Scan(&stillOpen); err != nil {
		t.Fatal(err)
	}
	if stillOpen != 1 {
		t.Fatalf("open invitations for the current member after the refusal: %d, want 1", stillOpen)
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
	// Revoking what is not there is a 404 as well.
	res = env.do(admin, http.MethodDelete, "/api/v1/orgs/"+orgH+"/invitations/"+id, nil)
	if code, _, _ := problemOf(t, res); code != http.StatusNotFound {
		t.Fatalf("revoking an invitation twice: %d, want 404", code)
	}

	// A person who accepted and later left can be invited again, and the
	// earlier acceptance stays on record beside the new offer.
	env.doJSON(invitee, http.MethodDelete, "/api/v1/orgs/"+orgH+"/members/"+inviteeH, nil, nil, http.StatusNoContent)
	inviteTo(t, env, admin, orgH, inviteeH+"@example.test")
	var acceptedRows, openRows int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FILTER (WHERE accepted_at IS NOT NULL), count(*) FILTER (WHERE accepted_at IS NULL)
		   FROM org_invitations WHERE email = $1`, inviteeH+"@example.test").Scan(&acceptedRows, &openRows); err != nil {
		t.Fatal(err)
	}
	if acceptedRows != 1 || openRows != 1 {
		t.Fatalf("invitations to the returning person: %d accepted, %d open; want 1 and 1", acceptedRows, openRows)
	}
}

// TestOneOrgPerPerson: an active member of one organization cannot be
// invited into, or approved into, another.
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
	// Someone already in the organization is not invited into it again, and
	// the refusal is not the other-organization one.
	res = env.do(firstAdmin, http.MethodPost, "/api/v1/orgs/"+firstOrg+"/invitations",
		map[string]any{"email": personH + "@example.test"})
	if code, slug, detail := problemOf(t, res); code != http.StatusConflict || slug != "conflict" || !strings.Contains(detail, firstOrg) {
		t.Fatalf("inviting a current member: %d %s %q, want 409 conflict naming the org", code, slug, detail)
	}
	// Waiting in another organization is not belonging to it: a person who is
	// only pending elsewhere can be invited.
	waitingH := env.register("op-waiting")
	env.verifyEmail(waitingH)
	env.seedMembership(firstOrg, waitingH, "member", "pending")
	env.doJSON(secondAdmin, http.MethodPost, "/api/v1/orgs/"+secondOrg+"/invitations",
		map[string]any{"email": waitingH + "@example.test"}, nil, http.StatusCreated)
	// An organization's invitations are its own: another organization's admin
	// cannot revoke them by id.
	var open []struct {
		Id string `json:"id"`
	}
	env.doJSON(secondAdmin, http.MethodGet, "/api/v1/orgs/"+secondOrg+"/invitations", nil, &open, http.StatusOK)
	if len(open) != 1 {
		t.Fatalf("open invitations of the second organization: %+v, want the one just sent", open)
	}
	res = env.do(firstAdmin, http.MethodDelete, "/api/v1/orgs/"+firstOrg+"/invitations/"+open[0].Id, nil)
	if code, _, _ := problemOf(t, res); code != http.StatusNotFound {
		t.Fatalf("revoking another organization's invitation: %d, want 404", code)
	}
	var kept int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM org_invitations WHERE id = $1::uuid`, open[0].Id).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != 1 {
		t.Fatalf("the other organization's invitation after a foreign revoke: %d rows, want 1", kept)
	}

	// The approval door refuses the same person, so a pending row that
	// predates their other membership cannot be waved through either.
	env.seedMembership(secondOrg, personH, "member", "pending")
	res = env.do(secondAdmin, http.MethodPost, "/api/v1/orgs/"+secondOrg+"/members/"+personH+"/approve", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "already-a-member" {
		t.Fatalf("approving someone else's member: %d %s, want 409 already-a-member", code, slug)
	}
}

// TestOneOrgPerPersonHoldsUnderConcurrentDoors: four organizations
// approve the same pending person at the same moment, and then a second
// person accepts four invitations at once. Each door counts the
// person's memberships under its own organization's row lock, which does
// not serialise against the other organization's, so without more both
// would count zero and both activate — two seats across two tenants for
// one person. The doors lock the person's row after the organization's,
// and the partial unique index on active memberships is the wall behind
// them.
func TestOneOrgPerPersonHoldsUnderConcurrentDoors(t *testing.T) {
	env := newTestEnv(t)
	type door struct {
		admin caller
		org   string
	}
	doors := make([]door, 4)
	for i := range doors {
		adminH := env.register(fmt.Sprintf("race-admin-%d", i))
		env.verifyEmail(adminH)
		admin := env.login(adminH)
		org := fmt.Sprintf("raceorg%d%s", i, env.sfx)
		env.createOrg(admin, org)
		doors[i] = door{admin: admin, org: org}
	}

	// race opens every door at once and sorts the answers: one admission,
	// the rest refused with the one-organization problem, nothing else.
	race := func(what string, open func(i int) *http.Response) {
		t.Helper()
		codes := make([]int, len(doors))
		slugs := make([]string, len(doors))
		var wg sync.WaitGroup
		for i := range doors {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				codes[i], slugs[i], _ = problemOf(t, open(i))
			}(i)
		}
		wg.Wait()
		ok, refused := 0, 0
		for i, c := range codes {
			switch {
			case c == http.StatusOK || c == http.StatusCreated:
				ok++
			case c == http.StatusConflict && slugs[i] == "already-a-member":
				refused++
			default:
				t.Fatalf("%s: unexpected answer %d %s in %v %v", what, c, slugs[i], codes, slugs)
			}
		}
		if ok != 1 || refused != len(doors)-1 {
			t.Fatalf("%s: %d admitted, %d refused (%v); want 1, %d", what, ok, refused, codes, len(doors)-1)
		}
	}
	activeMemberships := func(handle string) int {
		t.Helper()
		var n int
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT count(*) FROM memberships m JOIN handles h ON h.id = m.user_id WHERE h.handle = $1 AND m.state = 'active'`, handle).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// The approval door: four admins wave the same pending person through.
	approvedH := env.register("race-approved")
	for _, d := range doors {
		env.seedMembership(d.org, approvedH, "member", "pending")
	}
	race("concurrent approvals", func(i int) *http.Response {
		return env.do(doors[i].admin, http.MethodPost, "/api/v1/orgs/"+doors[i].org+"/members/"+approvedH+"/approve", nil)
	})
	if n := activeMemberships(approvedH); n != 1 {
		t.Fatalf("approved person is active in %d organizations, want 1", n)
	}

	// The invitation door: one person holds four invitations and accepts
	// them all at once.
	inviteeH := env.register("race-invitee")
	env.verifyEmail(inviteeH)
	invitee := env.login(inviteeH)
	tokens := make([]string, len(doors))
	for i, d := range doors {
		var invited struct {
			Token string `json:"token"`
		}
		env.doJSON(d.admin, http.MethodPost, "/api/v1/orgs/"+d.org+"/invitations",
			map[string]any{"email": inviteeH + "@example.test", "role": "member"}, &invited, http.StatusCreated)
		tokens[i] = invited.Token
	}
	race("concurrent acceptances", func(i int) *http.Response {
		return env.do(invitee, http.MethodPost, "/api/v1/invitations/"+tokens[i], nil)
	})
	if n := activeMemberships(inviteeH); n != 1 {
		t.Fatalf("invitee is active in %d organizations, want 1", n)
	}

	// The wall itself: a second active row for the person is refused by the
	// database whatever the code above did.
	var orgID string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT org_id FROM memberships WHERE state = 'pending' AND user_id = (SELECT id FROM handles WHERE handle = $1) LIMIT 1`, approvedH).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	tag, err := env.st.Pool().Exec(context.Background(), `UPDATE memberships SET state = 'active' WHERE org_id = $1 AND user_id = (SELECT id FROM handles WHERE handle = $2)`, orgID, approvedH)
	if err == nil || !strings.Contains(err.Error(), "memberships_one_active_per_user") {
		t.Fatalf("the index let a second active membership through: %v (%s)", err, tag)
	}
}

// TestProvisioningMakesPendingMembers: the IdP says who exists, an admin
// says who is a member. Provisioning through the members seam succeeds
// whatever the seats, because a pending person holds none; approving is
// where the seat is taken, and declining removes them.
func TestProvisioningMakesPendingMembers(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	adminH := env.register("sp-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "sporg" + env.sfx
	orgID := uuid.MustParse(env.createOrg(admin, orgH))

	email := "dana-" + env.sfx + "@acme.example"
	if _, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: email, UserName: email}); err != nil {
		t.Fatalf("provision: %v", err)
	}

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
				t.Fatalf("a provisioned member is %q, want pending", m.State)
			}
			provisioned = m.User.Handle
		}
	}
	if provisioned == "" {
		t.Fatal("provisioning made nobody a member")
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
	// Approving twice is a conflict, not a second admission; and declining
	// belongs to the waiting only: an active member leaves by removal, which
	// the last-admin guard covers.
	res := env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+provisioned+"/approve", nil)
	if code, _, detail := problemOf(t, res); code != http.StatusConflict || !strings.Contains(detail, provisioned) {
		t.Fatalf("approving an active member: %d %q, want 409 naming them", code, detail)
	}
	res = env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+provisioned+"/decline", nil)
	if code, _, detail := problemOf(t, res); code != http.StatusConflict || !strings.Contains(detail, provisioned) {
		t.Fatalf("declining an active member: %d %q, want 409 naming them", code, detail)
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH+"/members", nil, &members, http.StatusOK)
	stillActive := false
	for _, m := range members {
		if m.User.Handle == provisioned && m.State == "active" {
			stillActive = true
		}
	}
	if !stillActive {
		t.Fatalf("the declined active member is gone or changed: %+v", members)
	}

	// Declining removes a pending person and takes no seat.
	email2 := "eli-" + env.sfx + "@acme.example"
	if _, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: email2, UserName: email2}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	var handle2 string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT h.handle FROM users u JOIN handles h ON h.id = u.id WHERE u.email = $1`, email2).Scan(&handle2); err != nil {
		t.Fatal(err)
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+handle2+"/decline", nil, nil, http.StatusNoContent)
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &org, http.StatusOK)
	if org.Seats.Used != 2 || org.Seats.Pending != 0 {
		t.Fatalf("seats after the decline = %+v, want 2 used and none pending", org.Seats)
	}
	// The decline is remembered, so the domain does not fold the person in
	// again; an admin's invitation supersedes it.
	declines := func() int {
		t.Helper()
		var n int
		if err := env.st.Pool().QueryRow(ctx,
			`SELECT count(*) FROM fold_in_declines WHERE org_id = $1 AND user_id = (SELECT id FROM handles WHERE handle = $2)`,
			orgID, handle2).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := declines(); n != 1 {
		t.Fatalf("remembered declines after declining: %d, want 1", n)
	}
	token := inviteTo(t, env, admin, orgH, email2)
	env.doJSON(env.login(handle2), http.MethodPost, "/api/v1/invitations/"+token, nil, nil, http.StatusOK)
	if n := declines(); n != 0 {
		t.Fatalf("remembered declines after the invitation was accepted: %d, want 0", n)
	}

	// An approval can set the role the person arrives with.
	email3 := "fay-" + env.sfx + "@acme.example"
	if _, err := env.srvObj.ProvisionMember(ctx, "probe", orgID, api.ProvisionedMember{Email: email3, UserName: email3}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	var handle3 string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT h.handle FROM users u JOIN handles h ON h.id = u.id WHERE u.email = $1`, email3).Scan(&handle3); err != nil {
		t.Fatal(err)
	}
	var approved struct {
		Role  string `json:"role"`
		State string `json:"state"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+handle3+"/approve", map[string]any{"role": "admin"}, &approved, http.StatusOK)
	if approved.Role != "admin" || approved.State != "active" {
		t.Fatalf("approval as admin answered %+v, want an active admin", approved)
	}
	var roleNow string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT m.role FROM memberships m JOIN handles h ON h.id = m.user_id WHERE h.handle = $1`, handle3).Scan(&roleNow); err != nil {
		t.Fatal(err)
	}
	if roleNow != "admin" {
		t.Fatalf("role stored after an approval as admin: %q, want admin", roleNow)
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

// TestInvitationToTheOrgsOwnDomainIsMailedAndConfirmsTheAddress: an
// organization that proved it controls a domain (DNS TXT) vouches for the addresses there, so an invitation to one
// is mailed even though no verified account holds it — which is the whole
// point, since those are the colleagues an organization most needs to
// invite — and accepting it confirms the accepting account's address.
// Every other address keeps the verified-address rule.
func TestInvitationToTheOrgsOwnDomainIsMailedAndConfirmsTheAddress(t *testing.T) {
	mails := &invitationNotifier{Notifier: notify.LogNotifier{}}
	events := &recordedEvents{}
	env := newTestEnvCfg(t, func(c *config.Config) {
		// A site in front, so the offer carries a link a person can open
		// (webPaths.invitationURL answers "" without one: the server has no
		// invitation page of its own).
		c.BaseURL = "https://registry.example"
		c.Web.URL = "https://site.example"
	}, func(s *api.Server) { s.SetNotifier(mails) }, events.hook())
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
	// is handed the link instead (the verified-address rule is unchanged).
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
	joinerH := env.registerEmailUnverified("od-joiner", "joiner@"+domain)
	joinerToken := inviteTo(t, env, admin, orgH, "joiner@"+domain)
	joiner := env.login(joinerH)
	// Unverified, and accepted anyway.
	var verified bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT email_verified_at IS NOT NULL FROM users u JOIN handles h ON h.id = u.id WHERE h.handle = $1`, joinerH).Scan(&verified); err != nil || verified {
		t.Fatalf("setup: the joining account's address is verified before it accepts: %v %v", verified, err)
	}
	env.doJSON(joiner, http.MethodPost, "/api/v1/invitations/"+joinerToken, nil, nil, http.StatusOK)
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT email_verified_at IS NOT NULL FROM users u JOIN handles h ON h.id = u.id WHERE h.handle = $1`, joinerH).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("accepting an invitation at the organization's own domain did not confirm the address")
	}
	// The directory reads that confirmation, so it is announced, once.
	if got := events.count("user.email_verified"); got != 1 {
		t.Fatalf("user.email_verified fired %d times, want 1", got)
	}

	// A domain the organization has only claimed, not proved, vouches for
	// nothing: such an address is not mailed and does not accept unverified.
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/domain-claims", map[string]any{"domain": "claimed-" + orgH + ".example"}, nil, http.StatusCreated)
	claimedAddr := "claimed@claimed-" + orgH + ".example"
	claimedH := env.registerEmailUnverified("od-claimed", claimedAddr)
	claimedToken := inviteTo(t, env, admin, orgH, claimedAddr)
	if mails.sentTo(claimedAddr) != nil {
		t.Fatal("an invitation to an address at a domain that was only claimed was mailed")
	}
	res := env.do(env.login(claimedH), http.MethodPost, "/api/v1/invitations/"+claimedToken, nil)
	if code, _, detail := problemOf(t, res); code != http.StatusForbidden || !strings.Contains(detail, "Verify") {
		t.Fatalf("accept from an unverified address at a claimed domain: %d %q, want 403 asking for verification", code, detail)
	}

	// An invitation to an address NOT at the organization's domain still
	// needs the account's own verified address.
	elseH := env.registerEmailUnverified("od-else", "else@elsewhere.example")
	elseToken := inviteTo(t, env, admin, orgH, "else@elsewhere.example")
	res = env.do(env.login(elseH), http.MethodPost, "/api/v1/invitations/"+elseToken, nil)
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
