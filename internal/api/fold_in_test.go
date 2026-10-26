package api_test

// The fold-in: an account whose verified address is at an
// organization's domain becomes a pending member at its next directory
// sign-in, once; the sweep folds in the accounts already known at a domain
// the organization gains; a decline is remembered; GET /user names the
// organization until an admin decides; the admins are mailed one daily
// digest naming each person once, under the verified-address rule. The
// fold-in writes pending and nothing else — the seat is still taken in
// ActivateMember (TestPendingMemberHoldsNothing covers what a pending
// member holds, which is nothing).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/queue"
)

// signInThroughFakeOIDC signs in through the fake directory and returns
// the account and a caller holding its session.
func signInThroughFakeOIDC(t *testing.T, env *testEnv, idp *fakeOIDC) (string, caller) {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, "authentik")
	visit, err := idp.srv.Client().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	res := env.socialCallback(t, "authentik", state, cookie)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Id     string `json:"id"`
			Handle string `json:"handle"`
		} `json:"user"`
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	c := caller{name: out.User.Handle, csrf: out.CsrfToken}
	for _, ck := range res.Cookies() {
		if ck.Name == "agentry_session" {
			c.session = ck.Value
		}
	}
	return out.User.Id, c
}

// membershipOf reads the person's membership row in the organization, or
// "" for none.
func membershipOf(t *testing.T, env *testEnv, org, userID string) (state string, viaDomain bool) {
	t.Helper()
	err := env.st.Pool().QueryRow(context.Background(),
		`SELECT m.state, m.via_domain FROM memberships m JOIN handles h ON h.id = m.org_id WHERE h.handle = $1 AND m.user_id = $2::uuid`,
		org, userID).Scan(&state, &viaDomain)
	if err != nil {
		return "", false
	}
	return state, viaDomain
}

func pendingAudits(t *testing.T, env *testEnv, org, userID string) int {
	t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events a JOIN handles h ON h.id = a.org_id WHERE a.action = 'org.member_pending' AND h.handle = $1 AND a.target_id = $2::uuid`,
		org, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type userOut struct {
	Handle     string `json:"handle"`
	PendingOrg *struct {
		Handle      string `json:"handle"`
		DisplayName string `json:"displayName"`
		Via         string `json:"via"`
	} `json:"pendingOrg"`
	Orgs []struct {
		Handle string `json:"handle"`
		State  string `json:"state"`
	} `json:"orgs"`
}

func (env *testEnv) userOf(c caller) userOut {
	env.t.Helper()
	var out userOut
	env.doJSON(c, http.MethodGet, "/api/v1/user", nil, &out, http.StatusOK)
	return out
}

// newDirectoryEnv is a test env whose directory is a fake IdP asserting
// the given address.
func newDirectoryEnv(t *testing.T, idp *fakeOIDC) *testEnv {
	t.Helper()
	return newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Auth.OIDC = config.OIDCProvider{ID: config.AuthentikProviderID, ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
}

// TestFoldInAtSignIn: the step fires once for a verified address at the
// organization's domain, never for an unverified one, never for a public
// mail domain even when an organization row claims it, and never for a
// member of another organization; and it writes pending, which confers
// nothing.
func TestFoldInAtSignIn(t *testing.T) {
	idp := newFakeOIDC(t)
	env := newDirectoryEnv(t, idp)
	domain := "fold" + env.sfx + ".io"
	adminH := env.registerEmail("fold-admin", "admin@"+domain)
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	org := "foldorg" + env.sfx
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "Fold Corp"}, nil, http.StatusCreated)

	// A newcomer at the domain signs in through the directory: pending,
	// via the domain, audited once — and GET /user names the organization.
	idp.email = "newcomer-" + env.sfx + "@" + domain
	userID, person := signInThroughFakeOIDC(t, env, idp)
	if state, via := membershipOf(t, env, org, userID); state != "pending" || !via {
		t.Fatalf("after the first sign-in: state=%q viaDomain=%v, want pending via the domain", state, via)
	}
	u := env.userOf(person)
	if u.PendingOrg == nil || u.PendingOrg.Handle != org || u.PendingOrg.DisplayName != "Fold Corp" || u.PendingOrg.Via != "domain" {
		t.Fatalf("GET /user pendingOrg = %+v, want %s via domain", u.PendingOrg, org)
	}
	// The row is a plain member's, through the domain door and not the
	// provisioning one, and its audit event says who, where and why.
	var role string
	var viaScim bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT m.role, m.via_scim FROM memberships m JOIN handles h ON h.id = m.org_id WHERE h.handle = $1 AND m.user_id = $2::uuid`,
		org, userID).Scan(&role, &viaScim); err != nil {
		t.Fatal(err)
	}
	if role != "member" || viaScim {
		t.Fatalf("the folded-in membership: role %q, via scim %v, want a member through the domain door", role, viaScim)
	}
	var auditActor string
	var auditRaw []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT a.actor_kind || ':' || coalesce(a.actor_id::text, ''), a.detail FROM audit_events a JOIN handles h ON h.id = a.org_id
		  WHERE a.action = 'org.member_pending' AND h.handle = $1 AND a.target_id = $2::uuid`, org, userID).Scan(&auditActor, &auditRaw); err != nil {
		t.Fatal(err)
	}
	var auditBody map[string]any
	_ = json.Unmarshal(auditRaw, &auditBody)
	if auditActor != "user:"+userID || auditBody["via"] != "domain" || auditBody["domain"] != domain || auditBody["state"] != "pending" {
		t.Fatalf("org.member_pending audit row: %s %s", auditActor, auditRaw)
	}
	// Pending confers nothing: the members list is the admin's, and the
	// person's org list says pending.
	if res := env.do(person, http.MethodGet, "/api/v1/orgs/"+org+"/members", nil); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a pending member reading the members list: %d, want 403", res.StatusCode)
	}
	if len(u.Orgs) != 1 || u.Orgs[0].State != "pending" {
		t.Fatalf("orgs on GET /user: %+v", u.Orgs)
	}

	// The second sign-in writes nothing more.
	if again, _ := signInThroughFakeOIDC(t, env, idp); again != userID {
		t.Fatalf("second sign-in resolved another account: %s vs %s", again, userID)
	}
	if n := pendingAudits(t, env, org, userID); n != 1 {
		t.Fatalf("org.member_pending audited %d times, want once", n)
	}

	// An unverified address at the domain: nothing.
	unverified := newFakeOIDC(t)
	unverified.emailUnverified = true
	unverified.email = "unverified-" + env.sfx + "@" + domain
	env2 := newDirectoryEnv(t, unverified)
	uid, c := signInThroughFakeOIDC(t, env2, unverified)
	if state, _ := membershipOf(t, env2, org, uid); state != "" {
		t.Fatalf("an unverified address was folded in: %q", state)
	}
	if u := env2.userOf(c); u.PendingOrg != nil {
		t.Fatalf("pendingOrg for an unverified address: %+v", u.PendingOrg)
	}

	// A public mail domain: nothing, even with an organization row at it
	// (which the API never records, so it is planted).
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE orgs SET domain = 'gmail.com' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, org); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = env.st.Pool().Exec(context.Background(),
			`UPDATE orgs SET domain = $2 WHERE id = (SELECT id FROM handles WHERE handle = $1)`, org, domain)
	})
	public := newFakeOIDC(t)
	public.email = "public-" + env.sfx + "@gmail.com"
	env3 := newDirectoryEnv(t, public)
	uid, _ = signInThroughFakeOIDC(t, env3, public)
	if state, _ := membershipOf(t, env3, org, uid); state != "" {
		t.Fatalf("a public mail domain was folded in: %q", state)
	}
	// Nor does the sweep fold in the accounts known at a public mail domain
	// for an organization that carries one.
	var plantedOrgID uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT id FROM handles WHERE handle = $1`, org).Scan(&plantedOrgID); err != nil {
		t.Fatal(err)
	}
	if n, err := env.srvObj.RunFoldInSweep(context.Background(), plantedOrgID, "gmail.com"); err != nil || n != 0 {
		t.Fatalf("the sweep folded %d accounts in at a public mail domain (err %v)", n, err)
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE orgs SET domain = $2 WHERE id = (SELECT id FROM handles WHERE handle = $1)`, org, domain); err != nil {
		t.Fatal(err)
	}

	// A suspended organization folds nobody in, and is absent from the
	// notice of the person it had folded in; reinstated, the notice is
	// back and the next newcomer is folded in.
	setOrgState := func(state string) {
		t.Helper()
		if _, err := env.st.Pool().Exec(context.Background(),
			`UPDATE orgs SET state = $2 WHERE id = (SELECT id FROM handles WHERE handle = $1)`, org, state); err != nil {
			t.Fatal(err)
		}
	}
	setOrgState("suspended")
	t.Cleanup(func() { setOrgState("active") })
	if u := env.userOf(person); u.PendingOrg != nil {
		t.Fatalf("pendingOrg names a suspended organization: %+v", u.PendingOrg)
	}
	held := newFakeOIDC(t)
	held.email = "held-" + env.sfx + "@" + domain
	env5 := newDirectoryEnv(t, held)
	uid, _ = signInThroughFakeOIDC(t, env5, held)
	if state, _ := membershipOf(t, env5, org, uid); state != "" {
		t.Fatalf("folded into a suspended organization: %q", state)
	}
	var orgID uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT id FROM handles WHERE handle = $1`, org).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if n, err := env.srvObj.RunFoldInSweep(context.Background(), orgID, domain); err != nil || n != 0 {
		t.Fatalf("the sweep folded %d into a suspended organization (err %v)", n, err)
	}
	setOrgState("active")
	if u := env.userOf(person); u.PendingOrg == nil {
		t.Fatal("pendingOrg gone after the organization was reinstated")
	}
	if n, err := env.srvObj.RunFoldInSweep(context.Background(), orgID, domain); err != nil || n != 1 {
		t.Fatalf("the sweep after reinstatement folded %d (err %v), want the one held back", n, err)
	}

	// A member of another organization: nothing. Alice founds her own
	// organization (at no domain) and then signs in with an address at
	// Fold Corp's domain.
	other := newFakeOIDC(t)
	other.email = "elsewhere-" + env.sfx + "@" + domain
	env4 := newDirectoryEnv(t, other)
	uid, c = signInThroughFakeOIDC(t, env4, other)
	// The first sign-in folded them in (they belonged to nothing); undo
	// that by declining, then make them a member elsewhere and sign in
	// again: the decline alone would stop the fold-in, so clear it too.
	env4.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+org+"/members/"+c.name+"/decline", nil, nil, http.StatusNoContent)
	if _, err := env4.st.Pool().Exec(context.Background(), `DELETE FROM fold_in_declines WHERE user_id = $1::uuid`, uid); err != nil {
		t.Fatal(err)
	}
	env4.doJSON(c, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "elsewhere" + env.sfx, "displayName": "Elsewhere", "domain": "none"}, nil, http.StatusCreated)
	signInThroughFakeOIDC(t, env4, other)
	if state, _ := membershipOf(t, env4, org, uid); state != "" {
		t.Fatalf("a member of another organization was folded in: %q", state)
	}
	if u := env4.userOf(c); u.PendingOrg != nil {
		t.Fatalf("pendingOrg for a member elsewhere: %+v", u.PendingOrg)
	}

	// A domain an organization has claimed but not proved is not its domain:
	// nobody is folded in until the claim is verified.
	claimDomain := "claim" + env.sfx + ".io"
	founderH := env.register("fold-claimer")
	env.verifyEmail(founderH)
	claimOrg := "claimorg" + env.sfx
	env.doJSON(env.login(founderH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": claimOrg, "displayName": "Claim Corp", "domain": "none"}, nil, http.StatusCreated)
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO domain_claims (id, org_id, domain, verification_token) SELECT gen_random_uuid(), id, $2, 'claim-token' FROM handles WHERE handle = $1`,
		claimOrg, claimDomain); err != nil {
		t.Fatal(err)
	}
	claimant := newFakeOIDC(t)
	claimant.email = "before-" + env.sfx + "@" + claimDomain
	envC := newDirectoryEnv(t, claimant)
	uid, _ = signInThroughFakeOIDC(t, envC, claimant)
	if state, _ := membershipOf(t, envC, claimOrg, uid); state != "" {
		t.Fatalf("folded in at an unverified domain claim: %q", state)
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE domain_claims SET verified_at = now() WHERE domain = $1`, claimDomain); err != nil {
		t.Fatal(err)
	}
	proven := newFakeOIDC(t)
	proven.email = "after-" + env.sfx + "@" + claimDomain
	envP := newDirectoryEnv(t, proven)
	uid, _ = signInThroughFakeOIDC(t, envP, proven)
	if state, via := membershipOf(t, envP, claimOrg, uid); state != "pending" || !via {
		t.Fatalf("after the claim was verified: state=%q viaDomain=%v, want pending via the domain", state, via)
	}
}

// TestFoldInSweepAndDecisions: the sweep on creation finds the accounts
// already known at the domain (verified, members of nothing) and none
// other; approval makes a member and pendingOrg goes; a decline is
// remembered across the next sign-in and pendingOrg goes; an admin's
// invitation supersedes the decline.
func TestFoldInSweepAndDecisions(t *testing.T) {
	idp := newFakeOIDC(t)
	env := newDirectoryEnv(t, idp)
	domain := "sweep" + env.sfx + ".io"
	// Known before the organization exists: Bob and Carol, verified; Dave,
	// unverified; Erin, verified but a member elsewhere.
	bobH := env.registerEmail("sw-bob", "bob@"+domain)
	env.verifyEmail(bobH)
	carolH := env.registerEmail("sw-carol", "carol@"+domain)
	env.verifyEmail(carolH)
	daveH := env.registerEmailUnverified("sw-dave", "dave@"+domain)
	erinH := env.registerEmail("sw-erin", "erin@"+domain)
	env.verifyEmail(erinH)
	env.doJSON(env.login(erinH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "erins" + env.sfx, "displayName": "Erin's", "domain": "none"}, nil, http.StatusCreated)
	// Hank, verified, but suspended; Ivan, verified at a subdomain of the
	// domain, which is another domain.
	hankH := env.registerEmail("sw-hank", "hank@"+domain)
	env.verifyEmail(hankH)
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE users SET state = 'suspended' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, hankH); err != nil {
		t.Fatal(err)
	}
	ivanH := env.registerEmail("sw-ivan", "ivan@mail."+domain)
	env.verifyEmail(ivanH)
	// Frank, verified, already waiting in Erin's organization (as the
	// IdP's door would leave him): one pending place per person.
	frankH := env.registerEmail("sw-frank", "frank@"+domain)
	env.verifyEmail(frankH)
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO memberships (org_id, user_id, role, via_scim, state)
		 SELECT o.id, u.id, 'member', true, 'pending' FROM handles o, handles u WHERE o.handle = $1 AND u.handle = $2`,
		"erins"+env.sfx, frankH); err != nil {
		t.Fatal(err)
	}

	adminH := env.registerEmail("sw-admin", "admin@"+domain)
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	org := "sweeporg" + env.sfx
	var created orgOut
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "Sweep Corp"}, &created, http.StatusCreated)
	var orgID uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT id FROM handles WHERE handle = $1`, org).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	// Without a worker the sweep is run by hand, as the job would.
	n, err := env.srvObj.RunFoldInSweep(context.Background(), orgID, domain)
	if err != nil || n != 2 {
		t.Fatalf("sweep folded %d (err %v), want 2 (bob, carol)", n, err)
	}
	for _, h := range []string{bobH, carolH} {
		var state string
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT m.state FROM memberships m JOIN handles h ON h.id = m.user_id WHERE h.handle = $1 AND m.org_id = $2`, h, orgID).Scan(&state); err != nil || state != "pending" {
			t.Fatalf("%s after the sweep: %q %v, want pending", h, state, err)
		}
	}
	for _, h := range []string{daveH, erinH, frankH, hankH, ivanH} {
		var cnt int
		_ = env.st.Pool().QueryRow(context.Background(),
			`SELECT count(*) FROM memberships m JOIN handles h ON h.id = m.user_id WHERE h.handle = $1 AND m.org_id = $2`, h, orgID).Scan(&cnt)
		if cnt != 0 {
			t.Fatalf("%s was folded in by the sweep", h)
		}
	}
	// The founder is not double-counted and a second sweep finds nobody.
	if n, err := env.srvObj.RunFoldInSweep(context.Background(), orgID, domain); err != nil || n != 0 {
		t.Fatalf("second sweep folded %d (err %v), want 0", n, err)
	}
	// The members list says how they arrived.
	var members []struct {
		User struct {
			Handle string `json:"handle"`
		} `json:"user"`
		State     string `json:"state"`
		ViaDomain bool   `json:"viaDomain"`
		ViaScim   bool   `json:"viaScim"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+org+"/members", nil, &members, http.StatusOK)
	viaDomain := 0
	for _, m := range members {
		if m.ViaDomain && m.State == "pending" && !m.ViaScim {
			viaDomain++
		}
	}
	if viaDomain != 2 {
		t.Fatalf("members via the domain: %d in %+v, want 2", viaDomain, members)
	}

	// A person already waiting in another organization is not folded in at
	// sign-in either, nor does the sign-in disturb the place they hold.
	frankIdp := newFakeOIDC(t)
	frankIdp.email = "frank@" + domain
	frankID, _ := signInThroughFakeOIDC(t, newDirectoryEnv(t, frankIdp), frankIdp)
	if state, _ := membershipOf(t, env, org, frankID); state != "" {
		t.Fatalf("frank, waiting in another organization, was folded in at sign-in: %q", state)
	}
	if state, _ := membershipOf(t, env, "erins"+env.sfx, frankID); state != "pending" {
		t.Fatalf("frank's place in the other organization: %q, want pending", state)
	}

	// Approval: Bob is a member, the flag stays, pendingOrg goes.
	bob := env.login(bobH)
	if u := env.userOf(bob); u.PendingOrg == nil || u.PendingOrg.Handle != org {
		t.Fatalf("bob's pendingOrg before approval: %+v", u.PendingOrg)
	}
	var approved struct {
		State     string `json:"state"`
		ViaDomain bool   `json:"viaDomain"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+org+"/members/"+bobH+"/approve", map[string]any{"role": "member"}, &approved, http.StatusOK)
	if approved.State != "active" || !approved.ViaDomain {
		t.Fatalf("approved: %+v", approved)
	}
	if u := env.userOf(bob); u.PendingOrg != nil || len(u.Orgs) != 1 || u.Orgs[0].State != "active" {
		t.Fatalf("bob after approval: pendingOrg=%+v orgs=%+v", u.PendingOrg, u.Orgs)
	}

	// A decline is remembered: Carol signs in through the directory
	// afterwards and is not folded in again; pendingOrg is gone.
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+org+"/members/"+carolH+"/decline", nil, nil, http.StatusNoContent)
	idp.email = "carol@" + domain
	carolID, carol := signInThroughFakeOIDC(t, env, idp)
	if state, _ := membershipOf(t, env, org, carolID); state != "" {
		t.Fatalf("carol folded in again after a decline: %q", state)
	}
	if u := env.userOf(carol); u.PendingOrg != nil {
		t.Fatalf("carol's pendingOrg after a decline: %+v", u.PendingOrg)
	}
	if n, err := env.srvObj.RunFoldInSweep(context.Background(), orgID, domain); err != nil || n != 0 {
		t.Fatalf("the sweep folded a declined person back in: %d %v", n, err)
	}
	// Unless an admin invites her: accepting makes her a member and the
	// decline is forgotten.
	token := inviteTo(t, env, admin, org, "carol@"+domain)
	env.doJSON(carol, http.MethodPost, "/api/v1/invitations/"+token, nil, nil, http.StatusOK)
	if state, _ := membershipOf(t, env, org, carolID); state != "active" {
		t.Fatalf("carol after accepting the invitation: %q", state)
	}
	var declines int
	_ = env.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM fold_in_declines WHERE user_id = $1::uuid`, carolID).Scan(&declines)
	if declines != 0 {
		t.Fatalf("the decline outlived the invitation: %d rows", declines)
	}

	// The domain is compared the way a mail domain is read: whatever its
	// case, and only the domain itself.
	ginaH := env.registerEmail("sw-gina", "gina@"+strings.ToUpper(domain))
	env.verifyEmail(ginaH)
	if n, err := env.srvObj.RunFoldInSweep(context.Background(), orgID, domain); err != nil || n != 1 {
		t.Fatalf("the sweep after an upper-case address at the domain folded %d (err %v), want 1 (gina)", n, err)
	}
	var ginaState string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT m.state FROM memberships m JOIN handles h ON h.id = m.user_id WHERE h.handle = $1 AND m.org_id = $2`, ginaH, orgID).Scan(&ginaState); err != nil || ginaState != "pending" {
		t.Fatalf("gina after the sweep: %q %v, want pending", ginaState, err)
	}
}

// digestNotifier records the pending-members digests.
type digestNotifier struct {
	notify.Notifier
	mu   sync.Mutex
	sent []notify.PendingMembersNotice
	// fail makes every delivery fail, the way an SMTP outage does.
	fail bool
}

func (n *digestNotifier) OrgPendingMembers(_ context.Context, d notify.PendingMembersNotice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail {
		return errors.New("smtp: down")
	}
	n.sent = append(n.sent, d)
	return nil
}

func (n *digestNotifier) to(email string) []notify.PendingMembersNotice {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []notify.PendingMembersNotice
	for _, d := range n.sent {
		if strings.EqualFold(d.ToEmail, email) {
			out = append(out, d)
		}
	}
	return out
}

// TestPendingMembersDigestIsBatchedAndVerifiedOnly: one digest per admin
// per organization names every pending member not yet named, whichever
// door; an admin without a verified address gets none; the next run mails
// nothing; a person who arrives later is named in the next digest, alone.
func TestPendingMembersDigestIsBatchedAndVerifiedOnly(t *testing.T) {
	mails := &digestNotifier{Notifier: notify.LogNotifier{}}
	env := newTestEnvCfg(t, func(c *config.Config) { c.Web.URL = "https://site.example" }, func(s *api.Server) { s.SetNotifier(mails) })
	domain := "digest" + env.sfx + ".io"
	adminH := env.registerEmail("dg-admin", "admin@"+domain)
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	org := "digestorg" + env.sfx
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "Digest Corp"}, nil, http.StatusCreated)
	var orgID uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT id FROM handles WHERE handle = $1`, org).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	// A second admin whose address was never verified: the rule says no
	// mail to them. Made an admin directly — the doors need a verified
	// address, which is the point.
	otherH := env.registerEmailUnverified("dg-other", "other@"+domain)
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO memberships (org_id, user_id, role, state) SELECT $1, id, 'admin', 'active' FROM handles WHERE handle = $2`, orgID, otherH); err != nil {
		t.Fatal(err)
	}
	// Admins and members who must not be mailed: an admin who turned the
	// organization mails off, one who is suspended, and a plain member.
	quietH := env.registerEmail("dg-quiet", "quiet@"+domain)
	env.verifyEmail(quietH)
	env.doJSON(env.login(quietH), http.MethodPut, "/api/v1/user/notifications", map[string]any{
		"email": map[string]any{"dependencyAlerts": false, "quarantine": false, "reviewDecisions": false, "advisories": false, "orgInvites": false},
		"web":   map[string]any{"dependencyAlerts": false},
	}, nil, http.StatusOK)
	for h, seat := range map[string]struct{ role, state string }{
		quietH: {"admin", "active"},
		env.registerEmail("dg-susp", "susp@"+domain):   {"admin", "active"},
		env.registerEmail("dg-plain", "plain@"+domain): {"member", "active"},
	} {
		env.verifyEmail(h)
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO memberships (org_id, user_id, role, state) SELECT $1, id, $3, $4 FROM handles WHERE handle = $2`, orgID, h, seat.role, seat.state); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE users SET state = 'suspended' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, "dg-susp"+env.sfx); err != nil {
		t.Fatal(err)
	}
	// Two people at the domain, folded in by the sweep.
	for _, h := range []string{"dg-bob", "dg-carol"} {
		env.verifyEmail(env.registerEmail(h, h+"@"+domain))
	}
	if n, err := env.srvObj.RunFoldInSweep(context.Background(), orgID, domain); err != nil || n != 2 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	// A delivery that fails leaves them for the next run: nobody was told.
	mails.fail = true
	if mailed, err := env.srvObj.RunPendingMembersDigest(context.Background(), orgID); err != nil || mailed != 0 {
		t.Fatalf("digest with deliveries failing: mailed %d, err %v", mailed, err)
	}
	var unmarked int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM memberships WHERE org_id = $1 AND state = 'pending' AND admins_notified_at IS NULL`, orgID).Scan(&unmarked); err != nil {
		t.Fatal(err)
	}
	if unmarked != 2 {
		t.Fatalf("members marked told although no mail went: %d unmarked, want 2", unmarked)
	}
	mails.fail = false
	// One organization's digest, as the sweep enqueues it.
	if mailed, err := env.srvObj.RunPendingMembersDigest(context.Background(), orgID); err != nil || mailed != 1 {
		t.Fatalf("digest for the organization: mailed %d (err %v), want 1", mailed, err)
	}
	got := mails.to("admin@" + domain)
	if len(got) != 1 || got[0].Org != org || got[0].OrgDisplayName != "Digest Corp" || len(got[0].Members) != 2 {
		t.Fatalf("the admin's digest: %+v", got)
	}
	for _, m := range got[0].Members {
		if m.Via != "domain" || !strings.HasSuffix(m.Email, "@"+domain) || m.Handle == "" || m.Since.IsZero() {
			t.Fatalf("member in the digest: %+v", m)
		}
	}
	if want := "https://site.example/orgs/" + org + "/admin"; got[0].ConsoleURL != want {
		t.Fatalf("the digest's console link = %q, want %q", got[0].ConsoleURL, want)
	}
	if len(mails.to("other@"+domain)) != 0 {
		t.Fatal("an admin with an unverified address was mailed")
	}
	for _, addr := range []string{"quiet", "susp", "plain"} {
		if len(mails.to(addr+"@"+domain)) != 0 {
			t.Fatalf("%s@%s was mailed the digest", addr, domain)
		}
	}
	// Named once: the next run has nothing to say to this admin.
	if _, err := env.srvObj.RunPendingMembersDigest(context.Background(), uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if got := mails.to("admin@" + domain); len(got) != 1 {
		t.Fatalf("second digest mailed the admin again: %+v", got)
	}
	// A latecomer is named in the next digest, alone.
	env.verifyEmail(env.registerEmail("dg-dave", "dg-dave@"+domain))
	if n, err := env.srvObj.RunFoldInSweep(context.Background(), orgID, domain); err != nil || n != 1 {
		t.Fatalf("sweep for the latecomer: %d %v", n, err)
	}
	if _, err := env.srvObj.RunPendingMembersDigest(context.Background(), uuid.Nil); err != nil {
		t.Fatal(err)
	}
	got = mails.to("admin@" + domain)
	if len(got) != 2 || len(got[1].Members) != 1 || !strings.HasPrefix(got[1].Members[0].Handle, "dg-dave") {
		t.Fatalf("the latecomer's digest: %+v", got)
	}

	// Whichever door they came through: a person provisioned by the
	// directory is named as such, and an admin who has not been approved
	// yet is named, not mailed. An organization that is suspended is mailed
	// nothing, and the person waits for the day it is not.
	erinH := env.registerEmail("dg-erin", "erin@"+domain)
	env.verifyEmail(erinH)
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO memberships (org_id, user_id, role, via_scim, state) SELECT $1, id, 'admin', true, 'pending' FROM handles WHERE handle = $2`, orgID, erinH); err != nil {
		t.Fatal(err)
	}
	setOrgState := func(state string) {
		t.Helper()
		if _, err := env.st.Pool().Exec(context.Background(), `UPDATE orgs SET state = $2 WHERE id = $1`, orgID, state); err != nil {
			t.Fatal(err)
		}
	}
	setOrgState("suspended")
	t.Cleanup(func() { setOrgState("active") })
	if mailed, err := env.srvObj.RunPendingMembersDigest(context.Background(), orgID); err != nil || mailed != 0 {
		t.Fatalf("digest for a suspended organization: mailed %d (err %v), want 0", mailed, err)
	}
	if got := mails.to("admin@" + domain); len(got) != 2 {
		t.Fatalf("a suspended organization's admin was mailed: %+v", got)
	}
	setOrgState("active")
	if mailed, err := env.srvObj.RunPendingMembersDigest(context.Background(), orgID); err != nil || mailed != 1 {
		t.Fatalf("digest once the organization is active again: mailed %d (err %v), want 1", mailed, err)
	}
	got = mails.to("admin@" + domain)
	if len(got) != 3 || len(got[2].Members) != 1 || got[2].Members[0].Via != "scim" || !strings.HasPrefix(got[2].Members[0].Handle, "dg-erin") {
		t.Fatalf("the provisioned person's digest: %+v", got)
	}
	if len(mails.to("erin@"+domain)) != 0 {
		t.Fatal("an admin who is still pending was mailed")
	}

	// One organization's digest leaves the others' to their own run.
	otherAdminH := env.registerEmail("dg-b-admin", "admin@digestb"+env.sfx+".io")
	env.verifyEmail(otherAdminH)
	orgB := "digestb" + env.sfx
	env.doJSON(env.login(otherAdminH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": orgB, "displayName": "Digest B"}, nil, http.StatusCreated)
	var orgBID uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT id FROM handles WHERE handle = $1`, orgB).Scan(&orgBID); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"dg-b-pending", "dg-a-pending"} {
		env.verifyEmail(env.registerEmail(h, h+"@elsewhere"+env.sfx+".io"))
	}
	for h, target := range map[string]uuid.UUID{"dg-b-pending": orgBID, "dg-a-pending": orgID} {
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO memberships (org_id, user_id, role, state) SELECT $1, id, 'member', 'pending' FROM handles WHERE handle = $2`, target, h+env.sfx); err != nil {
			t.Fatal(err)
		}
	}
	if mailed, err := env.srvObj.RunPendingMembersDigest(context.Background(), orgID); err != nil || mailed != 1 {
		t.Fatalf("digest for one organization: mailed %d (err %v), want 1", mailed, err)
	}
	var waiting int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM memberships WHERE org_id = $1 AND state = 'pending' AND admins_notified_at IS NULL`, orgBID).Scan(&waiting); err != nil || waiting != 1 {
		t.Fatalf("the other organization's waiting members after the first one's digest: %d (%v), want 1", waiting, err)
	}
	if len(mails.to("admin@digestb"+env.sfx+".io")) != 0 {
		t.Fatal("the other organization's admin was mailed by the first one's digest")
	}
	if _, err := env.srvObj.RunPendingMembersDigest(context.Background(), uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if len(mails.to("admin@digestb"+env.sfx+".io")) != 1 {
		t.Fatal("the other organization's admin was not mailed by the run for every organization")
	}

	// An organization none of whose admins can be written to has its
	// pending members marked told all the same: they are on the console,
	// and a daily retry would never end.
	silentAdminH := env.registerEmail("dg-c-admin", "admin@digestc"+env.sfx+".io")
	env.verifyEmail(silentAdminH)
	orgC := "digestc" + env.sfx
	env.doJSON(env.login(silentAdminH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": orgC, "displayName": "Digest C"}, nil, http.StatusCreated)
	var orgCID uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT id FROM handles WHERE handle = $1`, orgC).Scan(&orgCID); err != nil {
		t.Fatal(err)
	}
	env.verifyEmail(env.registerEmail("dg-c-pending", "dg-c-pending@elsewhere"+env.sfx+".io"))
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO memberships (org_id, user_id, role, state) SELECT $1, id, 'member', 'pending' FROM handles WHERE handle = $2`, orgCID, "dg-c-pending"+env.sfx); err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE users SET email_verified_at = NULL WHERE id = (SELECT id FROM handles WHERE handle = $1)`, silentAdminH); err != nil {
		t.Fatal(err)
	}
	if mailed, err := env.srvObj.RunPendingMembersDigest(context.Background(), orgCID); err != nil || mailed != 0 {
		t.Fatalf("digest for an organization no admin of which can be mailed: mailed %d (err %v), want 0", mailed, err)
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM memberships WHERE org_id = $1 AND state = 'pending' AND admins_notified_at IS NULL`, orgCID).Scan(&waiting); err != nil || waiting != 0 {
		t.Fatalf("pending members left unmarked in an organization no admin of which can be mailed: %d (%v)", waiting, err)
	}
}

// TestFoldInJobsRunOnTheQueue: an organization created at a domain makes the
// sweep a job; the worker folds in the accounts already known at the domain,
// and that organization's admins are mailed the digest at once, while another
// organization's pending members wait for the daily run, whose period is the
// configured one or a day.
func TestFoldInJobsRunOnTheQueue(t *testing.T) {
	mails := &digestNotifier{Notifier: notify.LogNotifier{}}
	env := newTestEnvWith(t, func(s *api.Server) { s.SetNotifier(mails) })
	ctx := context.Background()
	domain := "jobs" + env.sfx + ".io"
	bobH := env.registerEmail("jb-bob", "bob@"+domain)
	env.verifyEmail(bobH)

	// Another organization with a pending member nobody has been told about.
	otherAdminH := env.registerEmail("jb-oa", "admin@jobsother"+env.sfx+".io")
	env.verifyEmail(otherAdminH)
	otherOrg := "jobsother" + env.sfx
	env.doJSON(env.login(otherAdminH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": otherOrg, "displayName": "Jobs Other"}, nil, http.StatusCreated)
	waitingH := env.registerEmail("jb-wait", "wait@elsewhere"+env.sfx+".io")
	env.verifyEmail(waitingH)
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO memberships (org_id, user_id, role, state) SELECT o.id, u.id, 'member', 'pending' FROM handles o, handles u WHERE o.handle = $1 AND u.handle = $2`,
		otherOrg, waitingH); err != nil {
		t.Fatal(err)
	}

	adminH := env.registerEmail("jb-admin", "admin@"+domain)
	env.verifyEmail(adminH)
	org := "jobsorg" + env.sfx
	env.doJSON(env.login(adminH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "Jobs Corp"}, nil, http.StatusCreated)
	if _, folded := membershipOf(t, env, org, userIDOf(t, env, bobH).String()); folded {
		t.Fatal("bob was folded in before any worker ran")
	}

	// The worker: the sweep job folds bob in and asks for this organization's
	// digest, which is the next job.
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	env.srvObj.RegisterQueueHandlers(q)
	for range 3 {
		q.Drain(ctx, "core")
	}
	if state, via := membershipOf(t, env, org, userIDOf(t, env, bobH).String()); state != "pending" || !via {
		t.Fatalf("bob after the worker ran: state=%q viaDomain=%v, want pending via the domain", state, via)
	}
	got := mails.to("admin@" + domain)
	if len(got) != 1 || got[0].Org != org || len(got[0].Members) != 1 || got[0].Members[0].Handle != bobH {
		t.Fatalf("the organization's admin was mailed %+v, want one digest naming bob", got)
	}
	var waiting int
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM memberships m JOIN handles h ON h.id = m.org_id WHERE h.handle = $1 AND m.state = 'pending' AND m.admins_notified_at IS NULL`, otherOrg).Scan(&waiting); err != nil || waiting != 1 {
		t.Fatalf("the other organization's waiting members after the sweep's digest: %d (%v), want 1", waiting, err)
	}

	if got := api.PendingDigestPeriod(config.Config{}); got != 24*time.Hour {
		t.Fatalf("the digest period of a configuration that names none = %s, want a day", got)
	}
	cfg := config.Default()
	cfg.Orgs.PendingDigestEvery = 6 * time.Hour
	if got := api.PendingDigestPeriod(cfg); got != 6*time.Hour {
		t.Fatalf("the configured digest period = %s, want 6h", got)
	}
}
