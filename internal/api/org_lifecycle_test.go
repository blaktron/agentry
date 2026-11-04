package api_test

// The organization's lifecycle and its domain: one organization per
// domain, the request for access, suspension and the decommission hold
// enforced in one place, the erasure that ends the hold, and the two
// doors closed on the way — creating an organization while a member of
// another and erasing the last admin's account.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/notify"
)

// orgOut is an organization as the API answers it.
type orgOut struct {
	Handle          string     `json:"handle"`
	DisplayName     string     `json:"displayName"`
	Domain          *string    `json:"domain"`
	VerifiedDomains []string   `json:"verifiedDomains"`
	State           string     `json:"state"`
	DecommissionAt  *time.Time `json:"decommissionAt"`
}

func (env *testEnv) orgOf(c caller, handle string, want int) orgOut {
	env.t.Helper()
	var out orgOut
	env.doJSON(c, http.MethodGet, "/api/v1/orgs/"+handle, nil, &out, want)
	return out
}

// TestOneOrgPerDomain: an organization records its creator's verified
// email domain; a second at that domain is refused naming the first; the
// body may ask for none, or spell the creator's own domain, and nothing
// else; a public mail provider records none; a domain another
// organization verified over DNS is claimed too; and the database holds
// verified claims unique across organizations.
func TestOneOrgPerDomain(t *testing.T) {
	env := newTestEnv(t)
	domain := "acme" + env.sfx + ".io"
	aliceH := env.registerEmail("dom-alice", "alice@"+domain)
	env.verifyEmail(aliceH)
	alice := env.login(aliceH)
	first := "domorg" + env.sfx
	var created orgOut
	env.doJSON(alice, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": first, "displayName": "Acme"}, &created, http.StatusCreated)
	if created.Domain == nil || *created.Domain != domain || created.State != "active" {
		t.Fatalf("created org = %+v, want domain %s and state active", created, domain)
	}

	// A colleague at the domain cannot make a second one; the refusal
	// names the first, which is what the sign-up page and the request for
	// access build on.
	bobH := env.registerEmail("dom-bob", "bob@"+domain)
	env.verifyEmail(bobH)
	bob := env.login(bobH)
	res := env.do(bob, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "domorg2" + env.sfx, "displayName": "Acme again"})
	if code, slug, detail := problemOf(t, res); code != http.StatusConflict || slug != "domain-claimed" || !strings.Contains(detail, first) || !strings.Contains(detail, domain) {
		t.Fatalf("second org at the domain: %d %s %q, want 409 domain-claimed naming %s", code, slug, detail, first)
	}
	// Unless it records no domain.
	var second orgOut
	env.doJSON(bob, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "domorg2" + env.sfx, "displayName": "Bob's", "domain": "none"}, &second, http.StatusCreated)
	if second.Domain != nil {
		t.Fatalf("domain: none recorded %q", *second.Domain)
	}

	// Any domain but the creator's own is claimed over DNS, not here.
	carolH := env.registerEmail("dom-carol", "carol@carol"+env.sfx+".io")
	env.verifyEmail(carolH)
	carol := env.login(carolH)
	res = env.do(carol, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "domorg3" + env.sfx, "displayName": "C", "domain": "other" + env.sfx + ".io"})
	if code, _, _ := problemOf(t, res); code != http.StatusUnprocessableEntity {
		t.Fatalf("another domain in the body: %d, want 422", code)
	}
	var third orgOut
	env.doJSON(carol, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "domorg3" + env.sfx, "displayName": "C", "domain": "Carol" + env.sfx + ".io"}, &third, http.StatusCreated)
	if third.Domain == nil || *third.Domain != "carol"+env.sfx+".io" {
		t.Fatalf("own domain spelled out: %+v", third)
	}

	// The spelling is forgiven: case, the space around it and a trailing dot
	// all name the same domain.
	frankH := env.registerEmail("dom-frank", "frank@frank"+env.sfx+".io")
	env.verifyEmail(frankH)
	var spelled orgOut
	env.doJSON(env.login(frankH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "domorg6" + env.sfx, "displayName": "F", "domain": " Frank" + env.sfx + ".IO. "}, &spelled, http.StatusCreated)
	if spelled.Domain == nil || *spelled.Domain != "frank"+env.sfx+".io" {
		t.Fatalf("own domain spelled with case, space and a trailing dot: %+v", spelled)
	}

	// A public mail provider is nobody's.
	daveH := env.registerEmail("dom-dave", "dave"+env.sfx+"@gmail.com")
	env.verifyEmail(daveH)
	var fourth orgOut
	env.doJSON(env.login(daveH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "domorg4" + env.sfx, "displayName": "D"}, &fourth, http.StatusCreated)
	if fourth.Domain != nil {
		t.Fatalf("gmail.com recorded as a domain: %q", *fourth.Domain)
	}

	// A claim that has not been proved holds nothing: the domain it names
	// stays open to the person whose address is there.
	unprovedDomain := "unproved" + env.sfx + ".io"
	env.doJSON(bob, http.MethodPost, "/api/v1/orgs/"+second.Handle+"/domain-claims", map[string]any{"domain": unprovedDomain}, nil, http.StatusCreated)
	ginaH := env.registerEmail("dom-gina", "gina@"+unprovedDomain)
	env.verifyEmail(ginaH)
	var unproved orgOut
	env.doJSON(env.login(ginaH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "domorg7" + env.sfx, "displayName": "G"}, &unproved, http.StatusCreated)
	if unproved.Domain == nil || *unproved.Domain != unprovedDomain {
		t.Fatalf("org at a domain with only an unproved claim: %+v, want the domain recorded", unproved)
	}

	// A domain an organization verified over DNS belongs to it as well:
	// nobody creates an organization at it.
	dnsDomain := "dns" + env.sfx + ".io"
	env.verifyOrgDomain(second.Handle, dnsDomain)
	erinH := env.registerEmail("dom-erin", "erin@"+dnsDomain)
	env.verifyEmail(erinH)
	res = env.do(env.login(erinH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "domorg5" + env.sfx, "displayName": "E"})
	if code, slug, detail := problemOf(t, res); code != http.StatusConflict || slug != "domain-claimed" || !strings.Contains(detail, second.Handle) {
		t.Fatalf("org at a DNS-verified domain: %d %s %q, want 409 domain-claimed naming %s", code, slug, detail, second.Handle)
	}
	// And the verified claims are unique across organizations at the
	// database: the migration's index refuses a duplicate outright.
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO domain_claims (id, org_id, domain, verification_token, verified_at)
		 SELECT gen_random_uuid(), id, $2, 'dup', now() FROM handles WHERE handle = $1`, first, dnsDomain); err == nil || !strings.Contains(err.Error(), "domain_claims_verified_domain_idx") {
		t.Fatalf("a second verified claim on one domain: err = %v, want the unique index", err)
	}
	// GET carries both facts.
	got := env.orgOf(anonymous, second.Handle, http.StatusOK)
	if len(got.VerifiedDomains) != 1 || got.VerifiedDomains[0] != dnsDomain || got.Domain != nil {
		t.Fatalf("org after verifying: %+v", got)
	}
}

// TestCreatingAnOrganizationIsTheThirdDoor: POST /orgs
// refuses a caller who is an active member of another organization, staff
// and first-party handles included; leaving first opens it; and the last
// admin cannot leave (409 last-admin).
func TestCreatingAnOrganizationIsTheThirdDoor(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("td-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgA := "tdorga" + env.sfx
	orgAID := env.createOrg(admin, orgA)
	personH := env.register("td-person")
	env.joinOrg(admin, orgA, personH)
	person := env.login(personH)
	// A token bound to the organization, to see what leaving does to it.
	env.insertPAT(env.userID(personH), orgAID, "org:read")

	res := env.do(person, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "tdorgb" + env.sfx, "displayName": "B"})
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "already-a-member" {
		t.Fatalf("a member creating an org: %d %s, want 409 already-a-member", code, slug)
	}
	// Waiting for approval somewhere is not belonging there: a person who is
	// only pending can found their own organization.
	waitingH := env.register("td-waiting")
	env.verifyEmail(waitingH)
	env.seedMembership(orgA, waitingH, "member", "pending")
	env.createOrg(env.login(waitingH), "tdorgw"+env.sfx)

	// Leaving is for oneself: a member can remove nobody else, the admin or
	// another member.
	otherH := env.register("td-other")
	env.joinOrg(admin, orgA, otherH)
	for _, target := range []string{adminH, otherH} {
		res = env.do(person, http.MethodDelete, "/api/v1/orgs/"+orgA+"/members/"+target, nil)
		if code, _, _ := problemOf(t, res); code != http.StatusForbidden {
			t.Fatalf("a member removing %s: %d, want 403", target, code)
		}
	}
	// Platform staff are held to it too, first-party handle or not: the
	// membership rule runs before the handle is even looked at.
	env.makePlatformStaff(t, personH)
	person = env.login(personH)
	res = env.do(person, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "secureagentry", "displayName": "First party"})
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "already-a-member" {
		t.Fatalf("staff creating a first-party org while a member elsewhere: %d %s, want 409 already-a-member", code, slug)
	}

	// The last admin cannot leave: the organization must keep one.
	res = env.do(admin, http.MethodDelete, "/api/v1/orgs/"+orgA+"/members/"+adminH, nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "last-admin" {
		t.Fatalf("the last admin leaving: %d %s, want 409 last-admin", code, slug)
	}
	// A member leaves on their own — no admin needed — and may then create.
	env.doJSON(person, http.MethodDelete, "/api/v1/orgs/"+orgA+"/members/"+personH, nil, nil, http.StatusNoContent)
	// Leaving takes the organization's tokens with it.
	var liveBound int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM pats WHERE user_id = $1::uuid AND org_id = $2::uuid AND revoked_at IS NULL`, env.userID(personH), orgAID).Scan(&liveBound); err != nil {
		t.Fatal(err)
	}
	if liveBound != 0 {
		t.Fatalf("tokens bound to the organization after the member left: %d live, want 0", liveBound)
	}
	env.createOrg(person, "tdorgb"+env.sfx)
	var me struct {
		Orgs []struct {
			Handle string `json:"handle"`
		} `json:"orgs"`
	}
	env.doJSON(person, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if len(me.Orgs) != 1 || me.Orgs[0].Handle != "tdorgb"+env.sfx {
		t.Fatalf("after leaving and creating: orgs = %+v", me.Orgs)
	}
	// An outsider cannot remove a member by the leave route.
	strangerH := env.register("td-stranger")
	env.verifyEmail(strangerH)
	res = env.do(env.login(strangerH), http.MethodDelete, "/api/v1/orgs/"+orgA+"/members/"+adminH, nil)
	if code, _, _ := problemOf(t, res); code != http.StatusForbidden {
		t.Fatalf("a stranger removing the admin: %d, want 403", code)
	}
}

// accessNotifier records the access requests a test's server mailed.
type accessNotifier struct {
	notify.Notifier
	mu       sync.Mutex
	requests []notify.AccessRequestNotice
}

func (n *accessNotifier) OrgAccessRequest(_ context.Context, r notify.AccessRequestNotice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.requests = append(n.requests, r)
	return nil
}

// TestDomainOrgLookupAndRequestAccess: a signed-in person learns which
// organization their verified address's domain belongs to; a request for
// access mails only that organization's admins, once a day, audited; a
// shared domain belongs to nobody; a member is told so; a token cannot
// ask.
func TestDomainOrgLookupAndRequestAccess(t *testing.T) {
	mails := &accessNotifier{Notifier: notify.LogNotifier{}}
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.BaseURL = "https://registry.example"
		c.Web.URL = "https://site.example"
	}, func(s *api.Server) { s.SetNotifier(mails) })
	domain := "corp" + env.sfx + ".io"
	adminH := env.registerEmail("dq-admin", "admin@"+domain)
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "dqorg" + env.sfx
	env.createOrg(admin, orgH)
	// A second admin whose address is not verified: never mailed.
	silentH := env.register("dq-silent")
	env.joinOrg(admin, orgH, silentH)
	env.doJSON(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+silentH, map[string]any{"role": "admin"}, nil, http.StatusOK)
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE users SET email_verified_at = NULL WHERE id = (SELECT id FROM handles WHERE handle = $1)`, silentH); err != nil {
		t.Fatal(err)
	}

	// Neither a plain member nor an admin still waiting for approval is an
	// administrator to write to.
	plainH := env.register("dq-plain")
	env.joinOrg(admin, orgH, plainH)
	waitingAdminH := env.register("dq-waiting-admin")
	env.verifyEmail(waitingAdminH)
	env.seedMembership(orgH, waitingAdminH, "admin", "pending")

	newH := env.registerEmailUnverified("dq-new", "new@"+domain)
	newc := env.login(newH)
	res := env.do(newc, http.MethodGet, "/api/v1/user/domain-org", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusForbidden || slug != "email-unverified" {
		t.Fatalf("lookup with an unverified address: %d %s, want 403 email-unverified", code, slug)
	}
	res = env.do(newc, http.MethodPost, "/api/v1/user/domain-org/request-access", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusForbidden || slug != "account-unactivated" {
		t.Fatalf("request with an unverified address: %d %s, want 403 account-unactivated", code, slug)
	}
	env.verifyEmail(newH)

	type domainOrg struct {
		Domain string `json:"domain"`
		Org    *struct {
			Handle      string `json:"handle"`
			DisplayName string `json:"displayName"`
		} `json:"org"`
		Member         *bool `json:"member"`
		RequestedToday *bool `json:"requestedToday"`
	}
	var dq domainOrg
	env.doJSON(newc, http.MethodGet, "/api/v1/user/domain-org", nil, &dq, http.StatusOK)
	if dq.Domain != domain || dq.Org == nil || dq.Org.Handle != orgH || (dq.Member != nil && *dq.Member) || (dq.RequestedToday != nil && *dq.RequestedToday) {
		t.Fatalf("domain org for a newcomer: %+v", dq)
	}

	var result struct {
		Org          string `json:"org"`
		MailedAdmins int    `json:"mailedAdmins"`
	}
	env.doJSON(newc, http.MethodPost, "/api/v1/user/domain-org/request-access", nil, &result, http.StatusAccepted)
	if result.Org != orgH || result.MailedAdmins != 1 {
		t.Fatalf("request: %+v, want the one admin with a verified address mailed", result)
	}
	mails.mu.Lock()
	sent := append([]notify.AccessRequestNotice(nil), mails.requests...)
	mails.mu.Unlock()
	if len(sent) != 1 || sent[0].ToEmail != "admin@"+domain || sent[0].Requester != newH || sent[0].RequesterEmail != "new@"+domain ||
		sent[0].Org != orgH || sent[0].ConsoleURL != "https://site.example/orgs/"+orgH+"/admin" {
		t.Fatalf("mail: %+v", sent)
	}
	// Once a day: the audit row is the record.
	res = env.do(newc, http.MethodPost, "/api/v1/user/domain-org/request-access", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusTooManyRequests || slug != "rate-limited" {
		t.Fatalf("second request in a day: %d %s, want 429 rate-limited", code, slug)
	}
	env.doJSON(newc, http.MethodGet, "/api/v1/user/domain-org", nil, &dq, http.StatusOK)
	if dq.RequestedToday == nil || !*dq.RequestedToday {
		t.Fatalf("requestedToday after asking: %+v", dq)
	}
	var audited int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'org.access_request' AND actor_id = (SELECT id FROM handles WHERE handle = $1)`, newH).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("org.access_request audit rows = %d, want 1", audited)
	}

	// A token cannot ask on a person's behalf.
	_, pat := env.mintPAT(newc, "dq", "user:profile")
	res = env.do(caller{name: "pat", pat: pat}, http.MethodPost, "/api/v1/user/domain-org/request-access", nil)
	if code, _, _ := problemOf(t, res); code != http.StatusForbidden {
		t.Fatalf("a PAT asking: %d, want 403", code)
	}
	// A member is told they are one.
	env.doJSON(admin, http.MethodGet, "/api/v1/user/domain-org", nil, &dq, http.StatusOK)
	if dq.Member == nil || !*dq.Member {
		t.Fatalf("an admin's own lookup: %+v, want member", dq)
	}
	res = env.do(admin, http.MethodPost, "/api/v1/user/domain-org/request-access", nil)
	if code, _, detail := problemOf(t, res); code != http.StatusConflict || !strings.Contains(detail, "already a member") {
		t.Fatalf("a member asking: %d %q, want 409 saying they are a member", code, detail)
	}
	// Someone already waiting for an admin is told so.
	waitingH := env.registerEmail("dq-waiting", "waiting@"+domain)
	env.verifyEmail(waitingH)
	env.seedMembership(orgH, waitingH, "member", "pending")
	res = env.do(env.login(waitingH), http.MethodPost, "/api/v1/user/domain-org/request-access", nil)
	if code, _, detail := problemOf(t, res); code != http.StatusConflict || !strings.Contains(detail, "waiting") {
		t.Fatalf("a person already waiting asking: %d %q, want 409 saying they are waiting", code, detail)
	}
	// A shared domain belongs to nobody.
	gmailH := env.registerEmail("dq-gmail", "someone"+env.sfx+"@gmail.com")
	env.verifyEmail(gmailH)
	gm := env.login(gmailH)
	var shared domainOrg
	env.doJSON(gm, http.MethodGet, "/api/v1/user/domain-org", nil, &shared, http.StatusOK)
	if shared.Domain != "" || shared.Org != nil {
		t.Fatalf("a gmail address: %+v, want no domain and no org", shared)
	}
	res = env.do(gm, http.MethodPost, "/api/v1/user/domain-org/request-access", nil)
	if code, _, _ := problemOf(t, res); code != http.StatusNotFound {
		t.Fatalf("a gmail address asking: %d, want 404", code)
	}

	// The once-a-day rule looks back a day and no further: a request made 23
	// hours ago still counts, one made 25 hours ago does not.
	askedAgo := func(handle, age string) {
		t.Helper()
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO audit_events (id, occurred_at, actor_id, actor_kind, org_id, action, target_kind, target_id)
			 SELECT gen_random_uuid(), now() - $3::interval, u.id, 'user', o.id, 'org.access_request', 'org', o.id
			   FROM handles u, handles o WHERE u.handle = $1 AND o.handle = $2`, handle, orgH, age); err != nil {
			t.Fatal(err)
		}
	}
	recentH := env.registerEmail("dq-recent", "recent@"+domain)
	env.verifyEmail(recentH)
	askedAgo(recentH, "23 hours")
	res = env.do(env.login(recentH), http.MethodPost, "/api/v1/user/domain-org/request-access", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusTooManyRequests || slug != "rate-limited" {
		t.Fatalf("a request 23 hours after the last: %d %s, want 429 rate-limited", code, slug)
	}
	staleH := env.registerEmail("dq-stale", "stale@"+domain)
	env.verifyEmail(staleH)
	askedAgo(staleH, "25 hours")
	env.doJSON(env.login(staleH), http.MethodPost, "/api/v1/user/domain-org/request-access", nil, nil, http.StatusAccepted)

	// A suspended organization is absent to everyone, so nobody is pointed to
	// it and nobody may ask it for access; platform staff suspend with a
	// reason of at most 500 characters.
	staffH := env.register("dq-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)
	lateH := env.registerEmail("dq-late", "late@"+domain)
	env.verifyEmail(lateH)
	late := env.login(lateH)
	env.doJSON(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/suspend", map[string]any{"reason": strings.Repeat("r", 500)}, nil, http.StatusOK)
	var hidden domainOrg
	env.doJSON(late, http.MethodGet, "/api/v1/user/domain-org", nil, &hidden, http.StatusOK)
	if hidden.Org != nil {
		t.Fatalf("the domain's suspended organization is shown: %+v", hidden)
	}
	res = env.do(late, http.MethodPost, "/api/v1/user/domain-org/request-access", nil)
	if code, _, _ := problemOf(t, res); code != http.StatusNotFound {
		t.Fatalf("asking a suspended organization for access: %d, want 404", code)
	}
	env.doJSON(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/reinstate", nil, nil, http.StatusOK)
	env.doJSON(late, http.MethodGet, "/api/v1/user/domain-org", nil, &dq, http.StatusOK)
	if dq.Org == nil || dq.Org.Handle != orgH {
		t.Fatalf("domain org after reinstating: %+v, want %s", dq, orgH)
	}
}

// privateCapResolver caps private agents at max for every subject and
// leaves the rest of the core's answer — seats included — as it is, the
// way a tier's resolver overrides rather than constructs.
type privateCapResolver struct {
	entitlements.Resolver
	max int64
}

func (c privateCapResolver) Features(ctx context.Context, s entitlements.Subject) (entitlements.Features, error) {
	f, err := c.Resolver.Features(ctx, s)
	if err != nil {
		return f, err
	}
	f.PrivateAgents = entitlements.Cap{Enabled: true, Max: c.max}
	return f, nil
}

// recordedEvents collects the extension events a test's server fired.
type recordedEvents struct {
	mu    sync.Mutex
	kinds []string
	last  map[string]api.Event
}

func (r *recordedEvents) hook() func(*api.Server) {
	r.last = map[string]api.Event{}
	return func(s *api.Server) {
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.kinds = append(r.kinds, ev.Kind)
			r.last[ev.Kind] = ev
		})
	}
}

func (r *recordedEvents) count(kind string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, k := range r.kinds {
		if k == kind {
			n++
		}
	}
	return n
}

// TestSuspendedOrgIsRefusedEverywhere: platform staff suspend an
// organization and it answers as absent — its page, its members, its
// agents by name and in every listing, its provisioning, anything created
// under it — to members and strangers alike, until it is reinstated. A
// decommission then puts it in a read-only hold: reads and the audit log
// go on for its members, a private agent stays invisible to a non-reader
// through every state, every change is 409 org-decommissioning, and staff
// can still reinstate it. The git transport's half of the same gate is in
// internal/gitsrv.
func TestSuspendedOrgIsRefusedEverywhere(t *testing.T) {
	events := &recordedEvents{}
	env := newTestEnvCfg(t, func(c *config.Config) { c.Orgs.DecommissionHold = time.Hour }, events.hook())
	staffH := env.register("su-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)
	adminH := env.register("su-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "suorg" + env.sfx
	orgID := uuid.MustParse(env.createOrg(admin, orgH))
	memberH := env.register("su-member")
	env.joinOrg(admin, orgH, memberH)
	member := env.login(memberH)
	strangerH := env.register("su-stranger")
	env.verifyEmail(strangerH)
	stranger := env.login(strangerH)
	env.doJSON(admin, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": orgH, "name": "su-agent", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	env.doJSON(admin, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": orgH, "name": "su-private", "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)
	// A published release, so the listings have something to show.
	env.publishUnder(t, admin, orgH, "su-pub")
	listed := func() bool {
		t.Helper()
		var out struct {
			Results []struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"results"`
		}
		env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q=su-pub", nil, &out, http.StatusOK)
		for _, r := range out.Results {
			if r.Namespace == orgH && r.Name == "su-pub" {
				return true
			}
		}
		return false
	}
	if !listed() {
		t.Fatal("the published agent is not in search before suspension")
	}
	// provision is the identity provider's door through the members seam;
	// n names a fresh person each time.
	provision := func(n string) error {
		t.Helper()
		_, err := env.srvObj.ProvisionMember(context.Background(), "probe", orgID,
			api.ProvisionedMember{Email: "su-" + n + "-" + env.sfx + "@acme.example"})
		return err
	}

	status := func(c caller, method, path string, body any) int {
		t.Helper()
		res := env.do(c, method, path, body)
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		return res.StatusCode
	}
	// Before: everything answers; the private agent to its readers only.
	if got := status(anonymous, http.MethodGet, "/api/v1/agents/"+orgH+"/su-agent", nil); got != http.StatusOK {
		t.Fatalf("agent before suspension: %d", got)
	}
	if got := status(member, http.MethodGet, "/api/v1/agents/"+orgH+"/su-private", nil); got != http.StatusOK {
		t.Fatalf("private agent for a member: %d", got)
	}
	if got := status(stranger, http.MethodGet, "/api/v1/agents/"+orgH+"/su-private", nil); got != http.StatusNotFound {
		t.Fatalf("private agent for a stranger: %d, want 404", got)
	}
	if err := provision("before"); err != nil {
		t.Fatalf("provisioning before suspension: %v", err)
	}
	// An invitation sent before the suspension, to be answered during it and
	// after.
	inviteeH := env.register("su-invitee")
	env.verifyEmail(inviteeH)
	invitation := inviteTo(t, env, admin, orgH, inviteeH+"@example.test")
	invitee := env.login(inviteeH)

	// Only staff suspend; the reason is required.
	if got := status(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/suspend", map[string]any{"reason": "x"}); got != http.StatusForbidden {
		t.Fatalf("an admin suspending: %d, want 403", got)
	}
	if got := status(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/suspend", map[string]any{"reason": ""}); got != http.StatusUnprocessableEntity {
		t.Fatalf("suspending without a reason: %d, want 422", got)
	}
	for _, reason := range []string{"   ", strings.Repeat("r", 501)} {
		if got := status(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/suspend", map[string]any{"reason": reason}); got != http.StatusUnprocessableEntity {
			t.Fatalf("suspending with a reason of %d characters, spaces included: %d, want 422", len(reason), got)
		}
	}
	var suspended orgOut
	env.doJSON(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/suspend", map[string]any{"reason": "abuse report 42"}, &suspended, http.StatusOK)
	if suspended.State != "suspended" {
		t.Fatalf("after suspend: %+v", suspended)
	}
	if events.count("org.suspended") != 1 {
		t.Fatalf("org.suspended fired %d times", events.count("org.suspended"))
	}
	// Absent to everyone, over every route that names it, and from every
	// listing.
	if listed() {
		t.Fatal("a suspended organization's agent is still in search")
	}
	if got := status(anonymous, http.MethodGet, "/api/v1/agents?namespace="+orgH, nil); got != http.StatusNotFound {
		t.Fatalf("a suspended organization's namespace listing: %d, want 404", got)
	}
	for _, c := range []caller{anonymous, member, admin, staff, stranger} {
		for _, probe := range []struct {
			method, path string
			body         any
		}{
			{http.MethodGet, "/api/v1/orgs/" + orgH, nil},
			{http.MethodGet, "/api/v1/orgs/" + orgH + "/members", nil},
			{http.MethodGet, "/api/v1/agents/" + orgH + "/su-agent", nil},
			{http.MethodGet, "/api/v1/agents/" + orgH + "/su-private", nil},
			{http.MethodGet, "/api/v1/agents/" + orgH + "/su-agent/versions", nil},
			{http.MethodPost, "/api/v1/orgs/" + orgH + "/invitations", map[string]any{"email": "x@example.test"}},
			{http.MethodPost, "/api/v1/agents", map[string]any{"namespace": orgH, "name": "another", "modes": []string{"autonomous"}}},
			{http.MethodPost, "/api/v1/orgs/" + orgH + "/decommission", map[string]any{"confirm": orgH}},
		} {
			got := status(c, probe.method, probe.path, probe.body)
			if got != http.StatusNotFound && (c.name != "anonymous" || got != http.StatusUnauthorized) {
				t.Fatalf("%s %s as %s while suspended: %d, want 404", probe.method, probe.path, c.name, got)
			}
		}
	}
	if err := provision("suspended"); !errors.Is(err, api.ErrOrgNotProvisionable) {
		t.Fatalf("provisioning while suspended: %v, want ErrOrgNotProvisionable", err)
	}
	// Only staff lift a suspension: the organization's own admin and members
	// are not staff. An invitation is not answered while the organization is
	// out, and nothing is spent by the refusal. The last admin's account is
	// held by the organization all the same.
	for _, c := range []caller{admin, member} {
		if got := status(c, http.MethodPost, "/api/v1/orgs/"+orgH+"/reinstate", nil); got != http.StatusForbidden {
			t.Fatalf("%s reinstating a suspended organization: %d, want 403", c.name, got)
		}
	}
	if got := status(invitee, http.MethodPost, "/api/v1/invitations/"+invitation, nil); got != http.StatusNotFound {
		t.Fatalf("accepting an invitation to a suspended organization: %d, want 404", got)
	}
	res := env.do(admin, http.MethodPost, "/api/v1/user/delete", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "last-admin" {
		t.Fatalf("the last admin erasing their account while the organization is suspended: %d %s, want 409 last-admin", code, slug)
	}
	// Suspending twice is a conflict, not a second suspension.
	if got := status(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/suspend", map[string]any{"reason": "again"}); got != http.StatusConflict {
		t.Fatalf("suspending a suspended org: %d, want 409", got)
	}
	// Reinstated: everything is back, and nothing was lost.
	var back orgOut
	env.doJSON(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/reinstate", nil, &back, http.StatusOK)
	if back.State != "active" {
		t.Fatalf("after reinstate: %+v", back)
	}
	if got := status(member, http.MethodGet, "/api/v1/orgs/"+orgH+"/members", nil); got != http.StatusOK {
		t.Fatalf("members after reinstate: %d", got)
	}
	if !listed() {
		t.Fatal("the reinstated organization's agent is not back in search")
	}
	if err := provision("reinstated"); err != nil {
		t.Fatalf("provisioning after reinstate: %v", err)
	}
	if got := status(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/reinstate", nil); got != http.StatusConflict {
		t.Fatalf("reinstating an active org: %d, want 409", got)
	}

	// The decommission hold: the admin's act, confirmed by handle, session only.
	if got := status(member, http.MethodPost, "/api/v1/orgs/"+orgH+"/decommission", map[string]any{"confirm": orgH}); got != http.StatusForbidden {
		t.Fatalf("a member decommissioning: %d, want 403", got)
	}
	_, adminPAT := env.mintPAT(admin, "su", "org:admin")
	if got := status(caller{name: "pat", pat: adminPAT}, http.MethodPost, "/api/v1/orgs/"+orgH+"/decommission", map[string]any{"confirm": orgH}); got != http.StatusForbidden {
		t.Fatalf("a token decommissioning: %d, want 403", got)
	}
	if got := status(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/decommission", map[string]any{"confirm": "wrong"}); got != http.StatusUnprocessableEntity {
		t.Fatalf("decommission with the wrong confirmation: %d, want 422", got)
	}
	var held orgOut
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/decommission", map[string]any{"confirm": orgH, "reason": "moving on"}, &held, http.StatusOK)
	if held.State != "decommissioning" || held.DecommissionAt == nil || held.DecommissionAt.Before(time.Now().Add(50*time.Minute)) {
		t.Fatalf("after decommission: %+v, want decommissioning with the hold an hour out", held)
	}
	if held.DecommissionAt.After(time.Now().Add(70 * time.Minute)) {
		t.Fatalf("after decommission: the hold ends at %s, want about an hour out", held.DecommissionAt)
	}
	if events.count("org.decommissioning") != 1 {
		t.Fatalf("org.decommissioning fired %d times", events.count("org.decommissioning"))
	}
	// Read-only: reads and the audit log for members, every change refused.
	for _, probe := range []struct {
		c            caller
		method, path string
	}{
		{member, http.MethodGet, "/api/v1/orgs/" + orgH},
		{member, http.MethodGet, "/api/v1/orgs/" + orgH + "/members"},
		{member, http.MethodGet, "/api/v1/orgs/" + orgH + "/teams"},
		{admin, http.MethodGet, "/api/v1/orgs/" + orgH + "/audit"},
		{anonymous, http.MethodGet, "/api/v1/agents/" + orgH + "/su-agent"},
		{member, http.MethodGet, "/api/v1/agents/" + orgH + "/su-private"},
	} {
		if got := status(probe.c, probe.method, probe.path, nil); got != http.StatusOK {
			t.Fatalf("%s %s as %s during the hold: %d, want 200", probe.method, probe.path, probe.c.name, got)
		}
	}
	if got := status(stranger, http.MethodGet, "/api/v1/agents/"+orgH+"/su-private", nil); got != http.StatusNotFound {
		t.Fatalf("private agent for a stranger during the hold: %d, want 404", got)
	}
	if !listed() {
		t.Fatal("an organization in its hold is not read: its agent left search")
	}
	for _, probe := range []struct {
		c            caller
		method, path string
		body         any
	}{
		{admin, http.MethodPatch, "/api/v1/orgs/" + orgH, map[string]any{"displayName": "renamed"}},
		{admin, http.MethodPost, "/api/v1/orgs/" + orgH + "/invitations", map[string]any{"email": "x@example.test"}},
		{admin, http.MethodPost, "/api/v1/agents", map[string]any{"namespace": orgH, "name": "another", "modes": []string{"autonomous"}}},
		{admin, http.MethodPatch, "/api/v1/agents/" + orgH + "/su-agent", map[string]any{"summary": "renamed"}},
		{admin, http.MethodPost, "/api/v1/orgs/" + orgH + "/decommission", map[string]any{"confirm": orgH}},
	} {
		res := env.do(probe.c, probe.method, probe.path, probe.body)
		if code, slug, detail := problemOf(t, res); code != http.StatusConflict || slug != "org-decommissioning" || !strings.Contains(detail, orgH) {
			t.Fatalf("%s %s during the hold: %d %s %q, want 409 org-decommissioning", probe.method, probe.path, code, slug, detail)
		}
	}
	if err := provision("hold"); !errors.Is(err, api.ErrOrgNotProvisionable) {
		t.Fatalf("provisioning during the hold: %v, want ErrOrgNotProvisionable", err)
	}
	// Nothing moves the organization meanwhile: staff cannot suspend what is
	// in its hold, the sweep leaves it until the hold is over, and only staff
	// cancel the hold. The invitation sent earlier is not answered, and the
	// last admin's account stays.
	if got := status(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/suspend", map[string]any{"reason": "during the hold"}); got != http.StatusConflict {
		t.Fatalf("suspending an organization in its hold: %d, want 409", got)
	}
	if _, err := env.srvObj.RunOrgDecommissionSweep(context.Background()); err != nil {
		t.Fatalf("sweep during the hold: %v", err)
	}
	if got := env.orgOf(member, orgH, http.StatusOK); got.State != "decommissioning" {
		t.Fatalf("organization after a sweep during its hold: %+v, want still decommissioning", got)
	}
	for _, c := range []caller{admin, member} {
		if got := status(c, http.MethodPost, "/api/v1/orgs/"+orgH+"/reinstate", nil); got != http.StatusForbidden {
			t.Fatalf("%s cancelling the hold: %d, want 403", c.name, got)
		}
	}
	res = env.do(invitee, http.MethodPost, "/api/v1/invitations/"+invitation, nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "org-decommissioning" {
		t.Fatalf("accepting an invitation during the hold: %d %s, want 409 org-decommissioning", code, slug)
	}
	res = env.do(admin, http.MethodPost, "/api/v1/user/delete", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "last-admin" {
		t.Fatalf("the last admin erasing their account during the hold: %d %s, want 409 last-admin", code, slug)
	}
	// Nobody joins an organization on its way out: the invitation door is
	// closed above, and the chokepoint refuses an approval too.
	pendingH := env.register("su-pending")
	env.seedMembership(orgH, pendingH, "member", "pending")
	res = env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+pendingH+"/approve", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "org-decommissioning" {
		t.Fatalf("approving during the hold: %d %s, want 409 org-decommissioning", code, slug)
	}
	// A member may still leave — they belong to one organization at a time
	// and this one is going.
	if got := status(member, http.MethodDelete, "/api/v1/orgs/"+orgH+"/members/"+memberH, nil); got != http.StatusNoContent {
		t.Fatalf("leaving during the hold: %d, want 204", got)
	}
	// Staff cancel the hold.
	env.doJSON(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/reinstate", nil, &back, http.StatusOK)
	if back.State != "active" || back.DecommissionAt != nil {
		t.Fatalf("after cancelling the hold: %+v", back)
	}
	if got := status(admin, http.MethodPatch, "/api/v1/orgs/"+orgH, map[string]any{"displayName": "renamed"}); got != http.StatusOK {
		t.Fatalf("a change after the hold was cancelled: %d", got)
	}
	// The invitation that was refused twice was never spent: it answers now.
	env.doJSON(invitee, http.MethodPost, "/api/v1/invitations/"+invitation, nil, nil, http.StatusOK)
	if events.count("org.reinstated") != 2 {
		t.Fatalf("org.reinstated fired %d times, want 2", events.count("org.reinstated"))
	}
}

// TestOrgDecommissionErasesAfterTheHold: when the hold ends the sweep
// yanks every release, deletes the archives, ends every membership and
// invitation, retires the agents, scrubs the row and releases the handle
// and the domain — both are free for a new organization — audits it and
// fires org.decommissioned; a second sweep finds nothing; an organization
// with a version still in the pipeline waits for the next sweep; and the
// extension's Decommission takes the same path. It runs with an admission
// extension wired, the hosted product's shape, so the organization is
// created awaiting activation: the erasure must release its founder from
// the pending rule too.
func TestOrgDecommissionErasesAfterTheHold(t *testing.T) {
	events := &recordedEvents{}
	var srv *api.Server
	gitDir := t.TempDir()
	env := newTestEnvCfg(t, func(c *config.Config) { c.Orgs.DecommissionHold = 0; c.Git.DataDir = gitDir },
		events.hook(), func(s *api.Server) {
			srv = s
			s.Reg().SetAdmitter(&recordingAdmitter{})
		})
	ctx := context.Background()
	domain := "gone" + env.sfx + ".io"
	adminH := env.registerEmail("er-admin", "admin@"+domain)
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "erorg" + env.sfx
	orgID := env.createOrg(admin, orgH)
	memberH := env.register("er-member")
	env.joinOrg(admin, orgH, memberH)
	env.publishUnder(t, admin, orgH, "er-agent")
	// A member's account install of the organization's QuickAgent:
	// erased with the organization, as a star is, rather
	// than left as a bare ref to a retired name.
	member := env.login(memberH)
	if code, _, _ := env.putInstall(t, member, orgH+"/er-agent", map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
		t.Fatalf("member's account install: %d", code)
	}
	inviteTo(t, env, admin, orgH, "someone@"+domain)
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/teams", map[string]any{"slug": "er-team"}, nil, http.StatusCreated)

	var archiveKey string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT av.archive_key FROM agent_versions av JOIN agents a ON a.id = av.agent_id WHERE a.namespace_id = $1`, orgID).Scan(&archiveKey); err != nil {
		t.Fatal(err)
	}
	if ok, err := srv.Blobs().Exists(ctx, archiveKey); err != nil || !ok {
		t.Fatalf("archive before erasure: %v %v", ok, err)
	}

	// An organization's knowledge pack goes when it is
	// erased; this one is put straight through the store.
	kn := seedKnowledge(t, env, knowledge.Org(uuid.MustParse(orgID)))

	// Everything else the organization owned, one of each: an audit export
	// with its object, a webhook, a policy, a verified domain, a remembered
	// decline, a grant and a star on its agent, a token bound to it, and the
	// agent's repository on disk.
	memberID := env.userID(memberH)
	exportKey := "exports/er-" + env.sfx + ".ndjson"
	if err := srv.Blobs().Put(ctx, exportKey, strings.NewReader("{}\n")); err != nil {
		t.Fatal(err)
	}
	env.verifyOrgDomain(orgH, "claimed"+env.sfx+".io")
	boundToken := env.insertPAT(memberID, orgID, "org:admin")
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO webhook_endpoints (id, org_id, url, secret_enc, events) VALUES (gen_random_uuid(), $1, 'https://hooks.example.test/er', '\x00', '{}')`, []any{orgID}},
		{`INSERT INTO policies (id, org_id, document) VALUES (gen_random_uuid(), $1, '{}')`, []any{orgID}},
		{`INSERT INTO audit_exports (id, org_id, status, object_key) VALUES (gen_random_uuid(), $1, 'completed', $2)`, []any{orgID, exportKey}},
		{`INSERT INTO fold_in_declines (org_id, user_id) VALUES ($1, $2::uuid)`, []any{orgID, memberID}},
		{`INSERT INTO org_report_designs (org_id, document) VALUES ($1, '{"name": "house"}')`, []any{orgID}},
		{`INSERT INTO agent_user_grants (agent_id, user_id, role) SELECT a.id, $2::uuid, 'read' FROM agents a WHERE a.namespace_id = $1`, []any{orgID, memberID}},
		{`INSERT INTO stars (user_id, agent_id) SELECT $2::uuid, a.id FROM agents a WHERE a.namespace_id = $1`, []any{orgID, memberID}},
		{`UPDATE agents SET summary = 'a summary', readme_text = 'a readme' WHERE namespace_id = $1`, []any{orgID}},
	} {
		if _, err := env.st.Pool().Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatalf("seeding %q: %v", seed.sql, err)
		}
	}
	var repoID string
	if err := env.st.Pool().QueryRow(ctx, `SELECT repo_id::text FROM agents WHERE namespace_id = $1`, orgID).Scan(&repoID); err != nil {
		t.Fatal(err)
	}
	repoDir := gitDir + "/" + repoID[:2] + "/" + repoID + ".git"
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatal(err)
	}

	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/decommission", map[string]any{"confirm": orgH}, nil, http.StatusOK)
	// The single sign-on requirement is the organization's own policy and is
	// scrubbed with the rest of the row.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET sso_required = true WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}
	n, err := srv.RunOrgDecommissionSweep(ctx)
	if err != nil || n != 1 {
		t.Fatalf("sweep: erased %d, err %v; want 1", n, err)
	}
	assertKnowledgeGone(t, env, kn)

	// Gone from every surface; the handle and the domain are free.
	res := env.do(admin, http.MethodGet, "/api/v1/orgs/"+orgH, nil)
	if code, _, _ := problemOf(t, res); code != http.StatusNotFound {
		t.Fatalf("erased org: %d, want 404", code)
	}
	res = env.do(anonymous, http.MethodGet, "/api/v1/agents/"+orgH+"/er-agent", nil)
	if code, _, _ := problemOf(t, res); code != http.StatusNotFound {
		t.Fatalf("erased org's agent: %d, want 404", code)
	}
	var me struct {
		Orgs []any `json:"orgs"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if len(me.Orgs) != 0 {
		t.Fatalf("the admin's memberships after erasure: %v", me.Orgs)
	}
	if installs := env.listInstalls(t, member); len(installs) != 0 {
		t.Fatalf("the member's account installs after erasure: %+v, want none", installs)
	}
	// The founder is free to start again — the erased organization was
	// never activated, and must not count as their pending one — and the
	// domain and the handle are free for them.
	var reborn orgOut
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": orgH, "displayName": "Reborn"}, &reborn, http.StatusCreated)
	if reborn.Domain == nil || *reborn.Domain != domain || reborn.State != "active" {
		t.Fatalf("the founder's fresh start: %+v, want the same handle at the same domain", reborn)
	}
	// And that one is erased too, so the rest of the test sees a clean slate;
	// the handle that confirms it may carry the space around it.
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/decommission", map[string]any{"confirm": " " + orgH + " "}, nil, http.StatusOK)
	if n, err := srv.RunOrgDecommissionSweep(ctx); err != nil || n != 1 {
		t.Fatalf("sweep of the reborn org: erased %d, err %v; want 1", n, err)
	}
	// The record: versions yanked, the archive gone, the agent retired
	// private under the released handle, the row scrubbed, the act audited.
	var status, visibility, orgState, orgName, handle string
	var orgDomain *string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT av.status, a.visibility, o.state, o.display_name, o.domain, h.handle::text
		 FROM orgs o JOIN handles h ON h.id = o.id
		 JOIN agents a ON a.namespace_id = o.id JOIN agent_versions av ON av.agent_id = a.id
		 WHERE o.id = $1`, orgID).Scan(&status, &visibility, &orgState, &orgName, &orgDomain, &handle); err != nil {
		t.Fatal(err)
	}
	if status != "yanked" || visibility != "private" || orgState != "decommissioned" || orgName != "decommissioned organization" || orgDomain != nil || !strings.HasPrefix(handle, "del-") {
		t.Fatalf("after erasure: version %s, agent %s, org %s %q domain %v handle %s", status, visibility, orgState, orgName, orgDomain, handle)
	}
	if ok, err := srv.Blobs().Exists(ctx, archiveKey); err != nil || ok {
		t.Fatalf("archive after erasure: %v %v, want gone", ok, err)
	}
	var members, invitations, teams, audited int
	if err := env.st.Pool().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM memberships WHERE org_id = $1),
		(SELECT count(*) FROM org_invitations WHERE org_id = $1),
		(SELECT count(*) FROM teams WHERE org_id = $1),
		(SELECT count(*) FROM audit_events WHERE action = 'org.erase' AND org_id = $1)`, orgID).Scan(&members, &invitations, &teams, &audited); err != nil {
		t.Fatal(err)
	}
	if members != 0 || invitations != 0 || teams != 0 || audited != 1 {
		t.Fatalf("after erasure: %d memberships, %d invitations, %d teams, %d org.erase rows", members, invitations, teams, audited)
	}
	var webhooks, claims, policies, exports, declines, grants, stars, liveTokens, designs int
	if err := env.st.Pool().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM org_report_designs WHERE org_id = $1),
		(SELECT count(*) FROM webhook_endpoints WHERE org_id = $1),
		(SELECT count(*) FROM domain_claims WHERE org_id = $1),
		(SELECT count(*) FROM policies WHERE org_id = $1),
		(SELECT count(*) FROM audit_exports WHERE org_id = $1),
		(SELECT count(*) FROM fold_in_declines WHERE org_id = $1),
		(SELECT count(*) FROM agent_user_grants g JOIN agents a ON a.id = g.agent_id WHERE a.namespace_id = $1),
		(SELECT count(*) FROM stars s JOIN agents a ON a.id = s.agent_id WHERE a.namespace_id = $1),
		(SELECT count(*) FROM pats WHERE org_id = $1 AND revoked_at IS NULL)`, orgID).Scan(
		&designs, &webhooks, &claims, &policies, &exports, &declines, &grants, &stars, &liveTokens); err != nil {
		t.Fatal(err)
	}
	if designs+webhooks+claims+policies+exports+declines+grants+stars+liveTokens != 0 {
		t.Fatalf("after erasure: %d house designs, %d webhooks, %d domain claims, %d policies, %d audit exports, %d declines, %d grants, %d stars, %d live tokens; want none",
			designs, webhooks, claims, policies, exports, declines, grants, stars, liveTokens)
	}
	if ok, err := srv.Blobs().Exists(ctx, exportKey); err != nil || ok {
		t.Fatalf("audit export object after erasure: %v %v, want gone", ok, err)
	}
	if _, err := os.Stat(repoDir); !os.IsNotExist(err) {
		t.Fatalf("the agent's repository after erasure: %v, want gone", err)
	}
	var ssoRequired, bare bool
	var summary, readme string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT o.sso_required, a.summary, a.readme_text, a.latest_published_version_id IS NULL
		   FROM orgs o JOIN agents a ON a.namespace_id = o.id WHERE o.id = $1`, orgID).Scan(&ssoRequired, &summary, &readme, &bare); err != nil {
		t.Fatal(err)
	}
	if ssoRequired || summary != "" || readme != "" || !bare {
		t.Fatalf("after erasure: sso required %v, agent summary %q, readme %q, no release pointer %v; want false, empty, empty, true", ssoRequired, summary, readme, bare)
	}
	_ = boundToken
	// An erased organization does not come back: staff reinstating the
	// retired handle are told it has been erased.
	reinstaterH := env.register("er-staff")
	env.verifyEmail(reinstaterH)
	env.makePlatformStaff(t, reinstaterH)
	res = env.do(env.login(reinstaterH), http.MethodPost, "/api/v1/orgs/del-"+strings.ReplaceAll(orgID, "-", "")+"/reinstate", nil)
	if code, _, detail := problemOf(t, res); code != http.StatusConflict || !strings.Contains(detail, "erased") {
		t.Fatalf("reinstating an erased organization: %d %q, want 409 saying it was erased", code, detail)
	}
	// Once per erasure: the organization, and its reborn namesake above.
	if events.count("org.decommissioned") != 2 {
		t.Fatalf("org.decommissioned fired %d times, want 2", events.count("org.decommissioned"))
	}
	// A further sweep has nothing to do.
	if n, err := srv.RunOrgDecommissionSweep(ctx); err != nil || n != 0 {
		t.Fatalf("second sweep: %d %v, want 0", n, err)
	}

	// A version still in the pipeline defers the erasure to a later sweep.
	holdH := env.register("er-hold")
	env.verifyEmail(holdH)
	holder := env.login(holdH)
	waitOrg := "erwait" + env.sfx
	waitID := env.createOrg(holder, waitOrg)
	env.doJSON(holder, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": waitOrg, "name": "inflight", "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO agent_versions (id, agent_id, version, manifest, submitted_by, source, status)
		 SELECT gen_random_uuid(), a.id, '0.0.1', '{}', (SELECT id FROM handles WHERE handle = $2), 'cli-upload', 'submitted'
		 FROM agents a WHERE a.namespace_id = $1`, waitID, holdH); err != nil {
		t.Fatal(err)
	}
	did, err := srv.DecommissionOrgByExtension(ctx, uuid.MustParse(waitID), "never paid")
	if err != nil || !did {
		t.Fatalf("Deps.Orgs.Decommission: %v %v, want true", did, err)
	}
	if did, err := srv.DecommissionOrgByExtension(ctx, uuid.MustParse(waitID), "again"); err != nil || did {
		t.Fatalf("Deps.Orgs.Decommission twice: %v %v, want false and no error", did, err)
	}
	if did, err := srv.DecommissionOrgByExtension(ctx, uuid.New(), "nobody"); err != nil || did {
		t.Fatalf("Deps.Orgs.Decommission of nobody: %v %v, want false and no error", did, err)
	}
	if ev := events.lastOf("org.decommissioning"); ev.OrgID.String() != waitID || ev.Payload["reason"] != "never paid" {
		t.Fatalf("org.decommissioning from the extension: %+v", ev)
	}
	if n, err := srv.RunOrgDecommissionSweep(ctx); err != nil || n != 0 {
		t.Fatalf("sweep with a version in flight: %d %v, want 0 and no error", n, err)
	}
	if got := env.orgOf(holder, waitOrg, http.StatusOK); got.State != "decommissioning" {
		t.Fatalf("deferred org: %+v", got)
	}
	// A version being scanned is in flight as well.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE agent_versions SET status = 'scanning' WHERE agent_id IN (SELECT id FROM agents WHERE namespace_id = $1)`, waitID); err != nil {
		t.Fatal(err)
	}
	if n, err := srv.RunOrgDecommissionSweep(ctx); err != nil || n != 0 {
		t.Fatalf("sweep with a version being scanned: %d %v, want 0 and no error", n, err)
	}
	// Versions waiting on a review or held in quarantine do not hold the
	// erasure back; they end rejected and yanked with it.
	for _, extra := range []struct{ version, status string }{{"0.0.2", "needs_review"}, {"0.0.3", "quarantined"}} {
		if _, err := env.st.Pool().Exec(ctx,
			`INSERT INTO agent_versions (id, agent_id, version, manifest, submitted_by, source, status)
			 SELECT gen_random_uuid(), a.id, $3, '{}', (SELECT id FROM handles WHERE handle = $2), 'cli-upload', $4
			 FROM agents a WHERE a.namespace_id = $1`, waitID, holdH, extra.version, extra.status); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE agent_versions SET status = 'rejected' WHERE version = '0.0.1' AND agent_id IN (SELECT id FROM agents WHERE namespace_id = $1)`, waitID); err != nil {
		t.Fatal(err)
	}
	if n, err := srv.RunOrgDecommissionSweep(ctx); err != nil || n != 1 {
		t.Fatalf("sweep once the pipeline is done: %d %v, want 1", n, err)
	}
	versionStates := func() string {
		t.Helper()
		rows, err := env.st.Pool().Query(ctx,
			`SELECT av.version || ':' || av.status FROM agent_versions av JOIN agents a ON a.id = av.agent_id
			  WHERE a.namespace_id = $1 ORDER BY av.version`, waitID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var states []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			states = append(states, s)
		}
		return strings.Join(states, ",")
	}
	if got := versionStates(); got != "0.0.1:rejected,0.0.2:rejected,0.0.3:yanked" {
		t.Fatalf("versions after the erasure: %s, want 0.0.1:rejected,0.0.2:rejected,0.0.3:yanked", got)
	}
	// An erasure interrupted after its point of no return is finished by the
	// next sweep: a release found live under the erased organization is yanked.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE agent_versions SET status = 'published' WHERE version = '0.0.2' AND agent_id IN (SELECT id FROM agents WHERE namespace_id = $1)`, waitID); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.RunOrgDecommissionSweep(ctx); err != nil {
		t.Fatalf("sweep resuming an erasure: %v", err)
	}
	if got := versionStates(); got != "0.0.1:rejected,0.0.2:yanked,0.0.3:yanked" {
		t.Fatalf("versions after the resumed erasure: %s, want 0.0.1:rejected,0.0.2:yanked,0.0.3:yanked", got)
	}
}

func (r *recordedEvents) lastOf(kind string) api.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last[kind]
}

// TestErasureTransferRespectsThePrivateAgentCap: handing an erased
// account's private agents to an organization at its cap is 422
// private-agent-cap with nothing erased and nothing moved; under the cap
// the transfer goes through.
func TestErasureTransferRespectsThePrivateAgentCap(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetEntitlements(privateCapResolver{Resolver: entitlements.NewConfigResolver(config.Default().Limits), max: 1})
	})
	adminH := env.register("cap-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "caporg" + env.sfx
	env.createOrg(admin, orgH)
	// The organization already holds its one private agent.
	env.doJSON(admin, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": orgH, "name": "org-private", "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)
	userH := env.register("cap-leaver")
	env.joinOrg(admin, orgH, userH)
	env.doJSON(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+userH, map[string]any{"role": "admin"}, nil, http.StatusOK)
	user := env.login(userH)
	env.doJSON(user, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": userH, "name": "mine", "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)

	// The transfer names its organization, and the person must administer
	// it: a plain member of it, or of nowhere near it, is refused.
	res := env.do(user, http.MethodPost, "/api/v1/user/delete?publishedContent=transfer", nil)
	if code, _, _ := problemOf(t, res); code != http.StatusBadRequest {
		t.Fatalf("transfer naming no organization: %d, want 400", code)
	}
	plainH := env.register("cap-plain")
	env.joinOrg(admin, orgH, plainH)
	strayH := env.register("cap-stray")
	for _, h := range []string{plainH, strayH} {
		res = env.do(env.login(h), http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+orgH, nil)
		if code, _, detail := problemOf(t, res); code != http.StatusForbidden || !strings.Contains(detail, orgH) {
			t.Fatalf("transfer into an organization %s does not administer: %d %q, want 403 naming it", h, code, detail)
		}
	}

	res = env.do(user, http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+orgH, nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusUnprocessableEntity || slug != "private-agent-cap" {
		t.Fatalf("transfer over the cap: %d %s, want 422 private-agent-cap", code, slug)
	}
	// Nothing happened: the account and its agent are where they were.
	var ns string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT h.handle::text FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE a.name = 'mine' AND h.handle = $1`, userH).Scan(&ns); err != nil {
		t.Fatalf("the agent moved or the account went: %v", err)
	}
	env.doJSON(user, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)
	// Public agents are not counted against the cap.
	env.doJSON(user, http.MethodPatch, "/api/v1/agents/"+userH+"/mine", map[string]any{"visibility": "public"}, nil, http.StatusOK)
	env.doJSON(user, http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+orgH, nil, nil, http.StatusNoContent)
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT h.handle::text FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE a.name = 'mine' AND h.handle = $1`, orgH).Scan(&ns); err != nil {
		t.Fatalf("the public agent did not move: %v", err)
	}

	// A retired agent holds no place under the cap and a deleted one does not
	// move: of three private agents, one retired and one deleted, only the
	// live one counts, and one more private agent is exactly the cap of an
	// organization that holds none.
	ctx := context.Background()
	admin3H := env.register("cap-admin3")
	env.verifyEmail(admin3H)
	admin3 := env.login(admin3H)
	org3 := "caporgc" + env.sfx
	env.createOrg(admin3, org3)
	user3H := env.register("cap-user3")
	env.joinOrg(admin3, org3, user3H)
	env.doJSON(admin3, http.MethodPut, "/api/v1/orgs/"+org3+"/members/"+user3H, map[string]any{"role": "admin"}, nil, http.StatusOK)
	user3 := env.login(user3H)
	for _, name := range []string{"live", "old", "gone"} {
		env.doJSON(user3, http.MethodPost, "/api/v1/agents", map[string]any{
			"namespace": user3H, "name": name, "modes": []string{"autonomous"}, "visibility": "public",
		}, nil, http.StatusCreated)
	}
	for _, q := range []string{
		`UPDATE agents SET visibility = 'private' WHERE name = 'live' AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`,
		`UPDATE agents SET visibility = 'private', retired_at = now(), retired_visibility = 'public' WHERE name = 'old' AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`,
		`UPDATE agents SET visibility = 'private', deleted_at = now() WHERE name = 'gone' AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`,
	} {
		if _, err := env.st.Pool().Exec(ctx, q, user3H); err != nil {
			t.Fatal(err)
		}
	}
	env.doJSON(user3, http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+org3, nil, nil, http.StatusNoContent)
	var moved []string
	rows, err := env.st.Pool().Query(ctx,
		`SELECT a.name FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 ORDER BY a.name`, org3)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		moved = append(moved, name)
	}
	if strings.Join(moved, ",") != "live,old" {
		t.Fatalf("agents in the organization after the transfer: %v, want live and old", moved)
	}

	// A name the organization already has stops the transfer, and the account
	// is left as it was.
	admin6H := env.register("cap-admin6")
	env.verifyEmail(admin6H)
	admin6 := env.login(admin6H)
	org6 := "caporge" + env.sfx
	env.createOrg(admin6, org6)
	user6H := env.register("cap-user6")
	env.joinOrg(admin6, org6, user6H)
	env.doJSON(admin6, http.MethodPut, "/api/v1/orgs/"+org6+"/members/"+user6H, map[string]any{"role": "admin"}, nil, http.StatusOK)
	user6 := env.login(user6H)
	for _, ns := range []string{org6, user6H} {
		env.doJSON(user6, http.MethodPost, "/api/v1/agents", map[string]any{
			"namespace": ns, "name": "dup", "modes": []string{"autonomous"}, "visibility": "public",
		}, nil, http.StatusCreated)
	}
	res = env.do(user6, http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+org6, nil)
	if code, _, detail := problemOf(t, res); code != http.StatusConflict || !strings.Contains(detail, "same name") {
		t.Fatalf("transfer of a name the organization has: %d %q, want 409 about the name", code, detail)
	}
	env.doJSON(user6, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)

	// Nothing moves into an organization in its hold.
	admin4H := env.register("cap-admin4")
	env.verifyEmail(admin4H)
	admin4 := env.login(admin4H)
	org4 := "caporgd" + env.sfx
	env.createOrg(admin4, org4)
	user4H := env.register("cap-user4")
	env.joinOrg(admin4, org4, user4H)
	env.doJSON(admin4, http.MethodPut, "/api/v1/orgs/"+org4+"/members/"+user4H, map[string]any{"role": "admin"}, nil, http.StatusOK)
	env.doJSON(admin4, http.MethodPost, "/api/v1/orgs/"+org4+"/decommission", map[string]any{"confirm": org4}, nil, http.StatusOK)
	res = env.do(env.login(user4H), http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+org4, nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "org-decommissioning" {
		t.Fatalf("transfer into an organization in its hold: %d %s, want 409 org-decommissioning", code, slug)
	}
}
