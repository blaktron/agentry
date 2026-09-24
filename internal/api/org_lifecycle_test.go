package api_test

// The organization's lifecycle and its domain (agentry#363, plan
// organization-subscriptions §4, §5.4; D13, D14, D21, D23, D26): one
// organization per domain, the request for access, suspension and the
// decommission hold enforced in one place, the erasure that ends the
// hold, and the two doors the milestone closes on the way — creating an
// organization while a member of another (agentry#370) and erasing the
// last admin's account.

import (
	"context"
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

	// A public mail provider is nobody's.
	daveH := env.registerEmail("dom-dave", "dave"+env.sfx+"@gmail.com")
	env.verifyEmail(daveH)
	var fourth orgOut
	env.doJSON(env.login(daveH), http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "domorg4" + env.sfx, "displayName": "D"}, &fourth, http.StatusCreated)
	if fourth.Domain != nil {
		t.Fatalf("gmail.com recorded as a domain: %q", *fourth.Domain)
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

// TestCreatingAnOrganizationIsTheThirdDoor (agentry#370, D26): POST /orgs
// refuses a caller who is an active member of another organization, staff
// and first-party handles included; leaving first opens it; and the last
// admin cannot leave (409 last-admin).
func TestCreatingAnOrganizationIsTheThirdDoor(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("td-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgA := "tdorga" + env.sfx
	env.createOrg(admin, orgA)
	personH := env.register("td-person")
	env.joinOrg(admin, orgA, personH)
	person := env.login(personH)

	res := env.do(person, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "tdorgb" + env.sfx, "displayName": "B"})
	if code, slug, _ := problemOf(t, res); code != http.StatusConflict || slug != "already-a-member" {
		t.Fatalf("a member creating an org: %d %s, want 409 already-a-member", code, slug)
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
	env := newTestEnvCfg(t, func(c *config.Config) { c.BaseURL = "https://registry.example" },
		func(s *api.Server) { s.SetNotifier(mails) })
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

	newH := env.registerEmail("dq-new", "new@"+domain)
	newc := env.login(newH)
	res := env.do(newc, http.MethodGet, "/api/v1/user/domain-org", nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusForbidden || slug != "email-unverified" {
		t.Fatalf("lookup with an unverified address: %d %s, want 403 email-unverified", code, slug)
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
		sent[0].Org != orgH || !strings.Contains(sent[0].ConsoleURL, "/ui/orgs/"+orgH) {
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
	if code, _, _ := problemOf(t, res); code != http.StatusConflict {
		t.Fatalf("a member asking: %d, want 409", code)
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
}

// privateCapResolver caps private agents at max for every subject and
// leaves the rest of the core's answer — seats included — as it is, the
// way a tier's resolver overrides rather than constructs (DEV-107).
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
// agents by name and in every listing, its SCIM plane, anything created
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
	env.createOrg(admin, orgH)
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
	var scim struct {
		Token string `json:"token"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/scim/tokens", map[string]any{}, &scim, http.StatusCreated)
	scimCaller := caller{name: "scim", pat: scim.Token}

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
	if got := status(scimCaller, http.MethodGet, "/scim/v2/Users", nil); got != http.StatusOK {
		t.Fatalf("scim before suspension: %d", got)
	}

	// Only staff suspend; the reason is required.
	if got := status(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/suspend", map[string]any{"reason": "x"}); got != http.StatusForbidden {
		t.Fatalf("an admin suspending: %d, want 403", got)
	}
	if got := status(staff, http.MethodPost, "/api/v1/orgs/"+orgH+"/suspend", map[string]any{"reason": ""}); got != http.StatusUnprocessableEntity {
		t.Fatalf("suspending without a reason: %d, want 422", got)
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
	if got := status(scimCaller, http.MethodGet, "/scim/v2/Users", nil); got != http.StatusForbidden {
		t.Fatalf("scim while suspended: %d, want 403", got)
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
	if got := status(scimCaller, http.MethodGet, "/scim/v2/Users", nil); got != http.StatusOK {
		t.Fatalf("scim after reinstate: %d", got)
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
	if got := status(scimCaller, http.MethodGet, "/scim/v2/Users", nil); got != http.StatusForbidden {
		t.Fatalf("scim during the hold: %d, want 403", got)
	}
	// Nobody joins an organization on its way out: the invitation door is
	// closed above, and the chokepoint refuses an approval too.
	pendingH := env.register("su-pending")
	env.seedMembership(orgH, pendingH, "member", "pending")
	res := env.do(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/members/"+pendingH+"/approve", nil)
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
// the pending rule too, which is what the live check on dev found missing.
func TestOrgDecommissionErasesAfterTheHold(t *testing.T) {
	events := &recordedEvents{}
	var srv *api.Server
	env := newTestEnvCfg(t, func(c *config.Config) { c.Orgs.DecommissionHold = 0 },
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
	// A member's account install of the organization's BriefAgent
	// (agentry#448): erased with the organization, as a star is, rather
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

	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/decommission", map[string]any{"confirm": orgH}, nil, http.StatusOK)
	n, err := srv.RunOrgDecommissionSweep(ctx)
	if err != nil || n != 1 {
		t.Fatalf("sweep: erased %d, err %v; want 1", n, err)
	}

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
	// And that one is erased too, so the rest of the test sees a clean slate.
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/decommission", map[string]any{"confirm": orgH}, nil, http.StatusOK)
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
	if _, err := env.st.Pool().Exec(ctx, `UPDATE agent_versions SET status = 'rejected' WHERE agent_id IN (SELECT id FROM agents WHERE namespace_id = $1)`, waitID); err != nil {
		t.Fatal(err)
	}
	if n, err := srv.RunOrgDecommissionSweep(ctx); err != nil || n != 1 {
		t.Fatalf("sweep once the pipeline is done: %d %v, want 1", n, err)
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

	res := env.do(user, http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+orgH, nil)
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
	env.doJSON(user, http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+orgH, nil, nil, http.StatusOK)
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT h.handle::text FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE a.name = 'mine' AND h.handle = $1`, orgH).Scan(&ns); err != nil {
		t.Fatalf("the public agent did not move: %v", err)
	}
}
