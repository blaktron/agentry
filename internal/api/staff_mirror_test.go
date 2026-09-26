package api_test

// The directory's mirror of platform staff (agentry#598): the registry keeps
// one directory group equal to its platform staff, so an application that
// signs in through the directory (the log stack's Dashboards) admits staff
// alone. The group is written from the registry's flag, which only the staff
// organization's rule sets (agentry#556), and never read back as a source.
// These tests drive membership the way a person does and read the fake
// directory's group the way Dashboards would.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/queue"
)

// fakeGroupDirectory is authentik's groups and users API, enough for the
// mirror: accounts by address, one group by name, add_user and remove_user.
type fakeGroupDirectory struct {
	prefix   string
	mu       sync.Mutex
	next     int
	accounts map[int]string // pk → address
	service  map[int]bool
	inactive map[int]bool
	// failSearch answers 500 to every account search, as a directory
	// failing midway through a run does.
	failSearch bool
	groups     map[string]map[int]bool
	groupID    map[string]string
	calls      []string
}

func newFakeGroupDirectory() *fakeGroupDirectory {
	return &fakeGroupDirectory{prefix: fmt.Sprintf("%08x", rand.Int63n(1<<32)), next: 100, accounts: map[int]string{}, service: map[int]bool{}, inactive: map[int]bool{}, //nolint:gosec // test names
		groups: map[string]map[int]bool{}, groupID: map[string]string{}}
}

// uid is the fake's uid for an account: the sub the registry's provider
// issues for it (sub_mode hashed_user_id). The prefix keeps fixtures'
// subjects apart in the shared test database.
func (d *fakeGroupDirectory) uid(pk int) string { return fmt.Sprintf("uid-%s-%d", d.prefix, pk) }

func (d *fakeGroupDirectory) account(email string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.next++
	d.accounts[d.next] = email
	return d.next
}

func (d *fakeGroupDirectory) members(group string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for pk := range d.groups[group] {
		out = append(out, d.accounts[pk])
	}
	sort.Strings(out)
	return out
}

func (d *fakeGroupDirectory) has(group, email string) bool {
	for _, m := range d.members(group) {
		if strings.EqualFold(m, email) {
			return true
		}
	}
	return false
}

func (d *fakeGroupDirectory) handler(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer dir-admin-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	d.calls = append(d.calls, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	users := func(pks []int) map[string]any {
		var res []map[string]any
		sort.Ints(pks)
		for _, pk := range pks {
			typ := "internal"
			if d.service[pk] {
				typ = "service_account"
			}
			res = append(res, map[string]any{"pk": pk, "uid": d.uid(pk), "email": d.accounts[pk], "type": typ, "is_active": !d.inactive[pk]})
		}
		return map[string]any{"pagination": map[string]any{"next": 0}, "results": res}
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/groups/":
		name := r.URL.Query().Get("name")
		var res []map[string]any
		if id, ok := d.groupID[name]; ok {
			res = append(res, map[string]any{"pk": id, "name": name})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v3/core/groups/":
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := fmt.Sprintf("group-%d", len(d.groupID)+1)
		d.groupID[body.Name], d.groups[body.Name] = id, map[int]bool{}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"pk": id, "name": body.Name})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/users/":
		var pks []int
		if g := r.URL.Query().Get("groups_by_name"); g != "" {
			for pk := range d.groups[g] {
				pks = append(pks, pk)
			}
		} else if e := r.URL.Query().Get("email"); e != "" {
			for pk, a := range d.accounts {
				if a == e { // authentik 2026.8: exact and case-sensitive
					pks = append(pks, pk)
				}
			}
		} else if e := r.URL.Query().Get("search"); e != "" {
			if d.failSearch {
				http.Error(w, "unavailable", http.StatusInternalServerError)
				return
			}
			for pk, a := range d.accounts {
				if strings.Contains(strings.ToLower(a), strings.ToLower(e)) { // case-blind, parts too
					pks = append(pks, pk)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(users(pks))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v3/core/groups/"):
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // api v3 core groups <id> <op>
		id, op := parts[4], parts[5]
		var body struct {
			PK int `json:"pk"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for name, gid := range d.groupID {
			if gid != id {
				continue
			}
			switch op {
			case "add_user":
				d.groups[name][body.PK] = true
			case "remove_user":
				delete(d.groups[name], body.PK)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "no such group", http.StatusNotFound)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusNotFound)
	}
}

// mirrorFixture is a staff fixture whose configuration also names a mirror
// group written to a fake directory.
type mirrorFixture struct {
	*staffFixture
	dir   *fakeGroupDirectory
	group string
}

func newMirrorFixture(t *testing.T) *mirrorFixture {
	t.Helper()
	dir := newFakeGroupDirectory()
	ts := httptest.NewServer(http.HandlerFunc(dir.handler))
	t.Cleanup(ts.Close)
	m := &mirrorFixture{dir: dir}
	m.staffFixture = newStaffFixtureWith(t, func(cfg *config.Config, org string) {
		m.group = "mirror-" + org
		cfg.Auth.IdPAdminURL, cfg.Auth.IdPAdminToken = ts.URL, "dir-admin-token"
		cfg.Auth.IdPStaffMirrorGroup = m.group
	})
	return m
}

// link records that handle signed in through the directory as account pk,
// as the registry's directory sign-in does (identities, "authentik:<sub>").
func (m *mirrorFixture) link(handle string, pk int) {
	m.env.t.Helper()
	if _, err := m.env.st.Pool().Exec(context.Background(),
		`INSERT INTO identities (id, user_id, provider_kind, sso_connection_id, subject)
		 VALUES (gen_random_uuid(), (SELECT id FROM handles WHERE handle = $1), 'social', NULL, $2)`,
		handle, "authentik:"+m.dir.uid(pk)); err != nil {
		m.env.t.Fatal(err)
	}
}

func (m *mirrorFixture) reconcile() {
	m.env.t.Helper()
	if _, err := m.srv.ReconcileStaffMirror(context.Background()); err != nil {
		m.env.t.Fatalf("reconcile: %v", err)
	}
}

func (m *mirrorFixture) mirrorAudits(handle, member string) int {
	m.env.t.Helper()
	var n int
	if err := m.env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'directory.staff_mirror'
		   AND target_id = (SELECT id FROM handles WHERE handle = $1)
		   AND detail->>'group' = $2 AND detail->>'member' = $3`, handle, m.group, member).Scan(&n); err != nil {
		m.env.t.Fatal(err)
	}
	return n
}

// TestStaffMirrorFollowsTheStaffOrg: a member of the staff organization is
// added to the mirror, a removed member taken out, a pending member never
// put in, an address outside the domain (a look-alike included) never put in
// whatever the directory holds, and an account the directory put in the
// group by hand, staff in nothing but that, taken out. Every change is
// audited against the registry account.
func TestStaffMirrorFollowsTheStaffOrg(t *testing.T) {
	m := newMirrorFixture(t)
	founderEmail := "founder-" + m.env.sfx + "@" + m.domain
	// The directory holds this one with capitals: found case-blind.
	m.link(m.founded, m.dir.account(strings.ToUpper(founderEmail[:1])+founderEmail[1:]))

	aliceEmail := "alice-" + m.env.sfx + "@" + m.domain
	alice := m.person("alice")
	m.link(alice, m.dir.account(aliceEmail))
	m.join(alice, aliceEmail)
	// A second directory account at alice's address, which the registry
	// never linked: authentik does not keep addresses unique.
	impostor := m.dir.account(aliceEmail)

	// Pending: seeded as the fold-in or SCIM would, never approved.
	pendingEmail := "pat-" + m.env.sfx + "@" + m.domain
	pat := m.person("pat")
	m.link(pat, m.dir.account(pendingEmail))
	m.env.seedMembership(m.org, pat, "member", "pending")

	// A look-alike of the staff domain: the door refuses it, and the
	// directory's account at it is never mirrored.
	lookalike := "eve-" + m.env.sfx + "@" + strings.Replace(m.domain, "s", "ѕ", 1)
	eve := m.env.registerEmail("eve", lookalike)
	m.env.verifyEmail(eve)
	m.link(eve, m.dir.account(lookalike))

	// Someone put in the group by hand in the directory: a directory
	// account at the domain whose registry account is not staff.
	handEmail := "mallory-" + m.env.sfx + "@" + m.domain
	mallory := m.person("mallory")
	pk := m.dir.account(handEmail)
	m.reconcile() // creates the group
	m.dir.mu.Lock()
	m.dir.groups[m.group][pk] = true
	m.dir.mu.Unlock()

	m.reconcile()
	if !m.dir.has(m.group, founderEmail) || !m.dir.has(m.group, aliceEmail) {
		t.Fatalf("staff missing from the mirror: %v", m.dir.members(m.group))
	}
	m.dir.mu.Lock()
	impostorIn := m.dir.groups[m.group][impostor]
	m.dir.mu.Unlock()
	if impostorIn || len(m.dir.members(m.group)) != 2 {
		t.Fatalf("an unlinked account at a staff address is in the mirror: %v", m.dir.members(m.group))
	}
	for _, e := range []string{pendingEmail, lookalike, handEmail} {
		if m.dir.has(m.group, e) {
			t.Fatalf("%s is in the mirror and is not staff: %v", e, m.dir.members(m.group))
		}
	}
	if m.mirrorAudits(alice, "true") != 1 || m.mirrorAudits(mallory, "false") != 1 {
		t.Fatalf("audits: alice added %d, mallory removed %d", m.mirrorAudits(alice, "true"), m.mirrorAudits(mallory, "false"))
	}
	if m.mirrorAudits(pat, "true")+m.mirrorAudits(eve, "true") != 0 {
		t.Fatal("a pending member or a look-alike was audited as added")
	}

	// A second run changes nothing.
	m.reconcile()
	if m.mirrorAudits(alice, "true") != 1 {
		t.Fatal("an unchanged mirror was written again")
	}

	// Removed from the staff organization: out of the mirror.
	m.env.doJSON(m.founder, http.MethodDelete, "/api/v1/orgs/"+m.org+"/members/"+alice, nil, nil, http.StatusNoContent)
	m.reconcile()
	if m.dir.has(m.group, aliceEmail) {
		t.Fatalf("a removed member is still in the mirror: %v", m.dir.members(m.group))
	}
	if m.mirrorAudits(alice, "false") != 1 {
		t.Fatal("the removal was not audited")
	}
}

// TestStaffMirrorIsNudgedByAStaffChange: a change to someone's staff flag
// queues a run, which puts them in the mirror when the queue drains.
func TestStaffMirrorIsNudgedByAStaffChange(t *testing.T) {
	m := newMirrorFixture(t)
	q := queue.NewRiverClient(m.env.st, nil)
	q.SetTestOnly(true)
	m.srv.RegisterQueueHandlers(q)

	bobEmail := "bob-" + m.env.sfx + "@" + m.domain
	bob := m.person("bob")
	m.link(bob, m.dir.account(bobEmail))
	m.join(bob, bobEmail)

	var nudges int
	if err := m.env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM river_job WHERE kind = 'directory.staff_mirror_nudge' AND state IN ('available','scheduled')`).Scan(&nudges); err != nil {
		t.Fatal(err)
	}
	if nudges == 0 {
		t.Fatal("joining the staff organization queued no mirror run")
	}
	if _, err := m.env.st.Pool().Exec(context.Background(),
		`UPDATE river_job SET scheduled_at = now() WHERE kind LIKE 'directory.staff_mirror%' AND state IN ('available','scheduled')`); err != nil {
		t.Fatal(err)
	}
	q.Drain(context.Background(), "core")
	if !m.dir.has(m.group, bobEmail) {
		t.Fatalf("the nudged run did not mirror the new member: %v", m.dir.members(m.group))
	}
}

// TestStaffMirrorWithoutADirectoryAccount: platform staff with no directory
// account, or with one the registry has no directory sign-in linked to, is
// nothing to add, and no error.
func TestStaffMirrorWithoutADirectoryAccount(t *testing.T) {
	m := newMirrorFixture(t)
	carolEmail := "carol-" + m.env.sfx + "@" + m.domain
	carol := m.person("carol")
	m.join(carol, carolEmail)
	danEmail := "dan-" + m.env.sfx + "@" + m.domain
	dan := m.person("dan")
	m.dir.account(danEmail) // in the directory, never signed in through it
	m.join(dan, danEmail)
	out, err := m.srv.ReconcileStaffMirror(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m.dir.has(m.group, carolEmail) || m.dir.has(m.group, danEmail) {
		t.Fatalf("staff with no linked directory account were mirrored: %v", m.dir.members(m.group))
	}
	if m.mirrorAudits(carol, "true")+m.mirrorAudits(dan, "true") != 0 || out.NoAccount < 2 {
		t.Fatalf("audits or the count: %+v", out)
	}
}

// TestStaffMirrorUnconfiguredDoesNothing: no mirror group, no directory
// call, whatever the staff organization does.
func TestStaffMirrorUnconfiguredDoesNothing(t *testing.T) {
	f := newStaffFixture(t)
	out, err := f.srv.ReconcileStaffMirror(context.Background())
	if err != nil || out != (api.StaffMirrorOutcome{}) {
		t.Fatalf("unconfigured: %+v %v", out, err)
	}
}

// TestStaffOrgMembersWhoAreNotStaffAreReported: a member of the staff
// organization from before its door checked the domain is reported by the
// start-up check, and stays a member.
func TestStaffOrgMembersWhoAreNotStaffAreReported(t *testing.T) {
	f := newStaffFixture(t)
	old := f.env.registerEmail("oldtimer", "oldtimer-"+f.env.sfx+"@elsewhere.test")
	f.env.verifyEmail(old)
	f.env.seedMembership(f.org, old, "member", "active") // admitted before the rule
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

// TestStaffMirrorAddsOnlyTheLinkedActiveAccount: of the directory accounts
// a search for a staff address returns, only the active one carrying the
// registry's linked uid is added: never a service account at the address,
// an address that merely contains it, or the linked account while it is
// inactive (enrolled and never confirmed, or switched off), which is also
// taken out if it was in.
func TestStaffMirrorAddsOnlyTheLinkedActiveAccount(t *testing.T) {
	m := newMirrorFixture(t)
	erinEmail := "erin-" + m.env.sfx + "@" + m.domain
	erin := m.person("erin")
	linked := m.dir.account(erinEmail)
	m.link(erin, linked)
	m.join(erin, erinEmail)
	svc := m.dir.account(erinEmail)
	m.dir.mu.Lock()
	m.dir.service[svc] = true
	m.dir.inactive[linked] = true
	m.dir.mu.Unlock()
	m.dir.account("x" + erinEmail) // search= returns it; the address differs
	m.reconcile()
	if m.dir.has(m.group, erinEmail) || m.dir.has(m.group, "x"+erinEmail) {
		t.Fatalf("an inactive, service or look-alike account was mirrored: %v", m.dir.members(m.group))
	}
	m.dir.mu.Lock()
	m.dir.inactive[linked] = false
	m.dir.mu.Unlock()
	m.reconcile()
	m.dir.mu.Lock()
	in, svcIn := m.dir.groups[m.group][linked], m.dir.groups[m.group][svc]
	m.dir.mu.Unlock()
	if !in || svcIn {
		t.Fatalf("once active, only the linked account: linked %v service %v", in, svcIn)
	}
	// Switched off again: out.
	m.dir.mu.Lock()
	m.dir.inactive[linked] = true
	m.dir.mu.Unlock()
	m.reconcile()
	if m.dir.has(m.group, erinEmail) {
		t.Fatal("an inactive account stayed in the mirror")
	}
}

// TestStaffMirrorKeepsTheAuditOfAHalfFinishedRun: a run that removes
// someone from the group and then fails keeps the removal's audit row; the
// directory change stays, so no later run would record it.
func TestStaffMirrorKeepsTheAuditOfAHalfFinishedRun(t *testing.T) {
	m := newMirrorFixture(t)
	fayEmail := "fay-" + m.env.sfx + "@" + m.domain
	fay := m.person("fay")
	pk := m.dir.account(fayEmail)
	m.reconcile() // creates the group
	m.dir.mu.Lock()
	m.dir.groups[m.group][pk] = true // not staff: to be removed
	m.dir.mu.Unlock()
	gus := m.person("gus")
	gusEmail := "gus-" + m.env.sfx + "@" + m.domain
	m.link(gus, m.dir.account(gusEmail))
	m.join(gus, gusEmail) // to be added, which needs a search
	m.dir.mu.Lock()
	m.dir.failSearch = true
	m.dir.mu.Unlock()
	if _, err := m.srv.ReconcileStaffMirror(context.Background()); err == nil {
		t.Fatal("the run with a failing directory reported success")
	}
	if m.dir.has(m.group, fayEmail) {
		t.Fatal("the removal made before the failure did not happen")
	}
	if m.mirrorAudits(fay, "false") != 1 {
		t.Fatalf("the removal's audit row was lost with the failed run: %d", m.mirrorAudits(fay, "false"))
	}
}
