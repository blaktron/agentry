package api_test

// The identity seam: one generic OpenID sign-in that keeps every account
// the directory linked, a directory an extension supplies, the events and
// reads that let an extension follow erasures and platform staff, the
// sign-in hook with the token's claims, and the remembered browser an
// extension may mint under the core's rules.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/testidp"
)

// TestOIDCProviderSignsPeopleIn: the generic provider is offered under its
// id, makes an account at a person's first sign-in and links it by
// "oidc:<sub>", and finds the same account at the next.
func TestOIDCProviderSignsPeopleIn(t *testing.T) {
	env, idp := newOIDCTestEnv(t, nil)
	var meta struct {
		SignInProviders []string `json:"signInProviders"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
	if len(meta.SignInProviders) != 1 || meta.SignInProviders[0] != "oidc" {
		t.Fatalf("signInProviders = %v, want [oidc]", meta.SignInProviders)
	}
	// The directory's id is not served for it.
	res := env.do(anonymous, http.MethodGet, "/api/v1/auth/oidc/authentik/start", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("authentik start on a deployment whose provider is oidc: %d, want 404", res.StatusCode)
	}

	c := env.mintAccount(t, idp, "oidc-person")
	uid := env.selfID(c)
	var subject string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT subject FROM identities WHERE user_id = $1::uuid`, uid).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject != "oidc:sub-"+c.name {
		t.Fatalf("identity %q, want oidc:sub-%s", subject, c.name)
	}
	again := env.signInOIDC(t, idp, "oidc", testidp.Person{Subject: "sub-" + c.name, Email: c.name + "@example.test", EmailVerified: true})
	if again.status != http.StatusOK || again.userID != uid {
		t.Fatalf("second sign-in: %d, account %s, want %s", again.status, again.userID, uid)
	}
}

// TestExistingDirectoryIdentitiesKeepTheirAccounts: every account linked as
// "authentik:<sub>" is the same account at every later sign-in through the
// generic provider configured with the id "authentik", on this server or a
// new one: no account is re-created or re-linked.
func TestExistingDirectoryIdentitiesKeepTheirAccounts(t *testing.T) {
	idp := testidp.New(t)
	cfg := func(c *config.Config) {
		c.Auth.OIDC = config.OIDCProvider{ID: config.AuthentikProviderID, Issuer: idp.URL, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret}
	}
	first := newTestEnvCfg(t, cfg, func(s *api.Server) { s.SetOIDCHTTPClient(idp.Client()) })
	second := newTestEnvCfg(t, cfg, func(s *api.Server) { s.SetOIDCHTTPClient(idp.Client()) })

	ctx := context.Background()
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := first.st.Pool().QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	people := []testidp.Person{
		{Subject: "keep-a-" + first.sfx, Email: "keep-a-" + first.sfx + "@example.test", EmailVerified: true, Username: "keep-a-" + first.sfx},
		{Subject: "keep-b-" + first.sfx, Email: "keep-b-" + first.sfx + "@example.test", EmailVerified: true},
		// An unverified address: the account is linked by its subject alone.
		{Subject: "keep-c-" + first.sfx, Email: "keep-c-" + first.sfx + "@example.test"},
	}
	accounts := map[string]string{}
	for _, p := range people {
		in := first.signInOIDC(t, idp, "authentik", p)
		if in.status != http.StatusOK {
			t.Fatalf("first sign-in %s: %d %s", p.Subject, in.status, in.body)
		}
		accounts[p.Subject] = in.userID
		if n := count(`SELECT count(*) FROM identities WHERE user_id = $1::uuid AND subject = $2`, in.userID, "authentik:"+p.Subject); n != 1 {
			t.Fatalf("%s is not linked as authentik:<sub>", p.Subject)
		}
	}
	users := count(`SELECT count(*) FROM users`)
	idents := count(`SELECT count(*) FROM identities`)

	for _, env := range []*testEnv{second, first} {
		for _, p := range people {
			in := env.signInOIDC(t, idp, "authentik", p)
			if in.status != http.StatusOK || in.userID != accounts[p.Subject] {
				t.Fatalf("sign-in of authentik:%s: %d, account %s, want %s", p.Subject, in.status, in.userID, accounts[p.Subject])
			}
			if n := count(`SELECT count(*) FROM identities WHERE user_id = $1::uuid`, in.userID); n != 1 {
				t.Errorf("authentik:%s: %d identities, want the one it had", p.Subject, n)
			}
		}
	}
	if got := count(`SELECT count(*) FROM users`); got != users {
		t.Errorf("users went from %d to %d: an account was re-created", users, got)
	}
	if got := count(`SELECT count(*) FROM identities`); got != idents {
		t.Errorf("identities went from %d to %d: an account was re-linked", idents, got)
	}
}

// fakeDirectory is a directory an extension supplies: one account, named
// by address, with one authenticator, and a record of what it was asked.
type fakeDirectory struct {
	mu      sync.Mutex
	email   string
	devices []api.DirectoryDevice
	erased  []api.DirectoryLink
	removed []string
	fail    error
	// lookup, when set, is how every lookup ends, with nothing erased.
	lookup api.DirectoryLookup
}

func (d *fakeDirectory) owns(l api.DirectoryLink) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.email != "" && l.Email == d.email
}

func (d *fakeDirectory) EraseAccount(_ context.Context, l api.DirectoryLink) (bool, api.DirectoryLookup, error) {
	if d.fail != nil {
		return false, "", d.fail
	}
	if d.lookup != "" {
		return false, d.lookup, nil
	}
	if !d.owns(l) {
		return false, api.DirectoryLookupByAddress, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.erased = append(d.erased, l)
	return true, api.DirectoryLookupByAddress, nil
}

func (d *fakeDirectory) Devices(_ context.Context, l api.DirectoryLink) ([]api.DirectoryDevice, error) {
	if !d.owns(l) {
		return []api.DirectoryDevice{}, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]api.DirectoryDevice(nil), d.devices...), nil
}

func (d *fakeDirectory) DeleteDevice(_ context.Context, l api.DirectoryLink, kind, id string) (bool, error) {
	if !d.owns(l) {
		return false, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, dev := range d.devices {
		if dev.Kind == kind && dev.ID == id {
			d.devices = append(d.devices[:i], d.devices[i+1:]...)
			d.removed = append(d.removed, kind+"/"+id)
			return true, nil
		}
	}
	return false, nil
}

func (d *fakeDirectory) SignInFacts(context.Context, api.DirectoryLink) (api.DirectorySignInFacts, error) {
	yes := true
	return api.DirectorySignInFacts{HasPassword: &yes}, nil
}

func (d *fakeDirectory) AccountGone(context.Context, api.DirectoryLink) (bool, error) {
	return false, nil
}

func (d *fakeDirectory) GroupMembers(context.Context, string) (string, []api.DirectoryAccount, error) {
	return "", nil, nil
}

func (d *fakeDirectory) AccountsByEmail(context.Context, string) ([]api.DirectoryAccount, error) {
	return nil, nil
}

func (d *fakeDirectory) SetMember(context.Context, string, int, bool) error { return nil }

var _ api.Directory = (*fakeDirectory)(nil)

// TestADirectoryFromAnExtensionServesTheRegistry: with a directory set by
// an extension, erasure deletes the directory account and says so, and the
// extensions hear the erasure with the identities and the address it held.
func TestADirectoryFromAnExtensionServesTheRegistry(t *testing.T) {
	dir := &fakeDirectory{}
	var mu sync.Mutex
	var heard []api.Event
	env, idp := newOIDCTestEnv(t, nil,
		func(s *api.Server) {
			s.SetDirectory(dir)
			s.AddEventHook(func(_ context.Context, ev api.Event) {
				mu.Lock()
				defer mu.Unlock()
				heard = append(heard, ev)
			})
		})
	c := env.mintAccount(t, idp, "ext-dir")
	uid := env.selfID(c)
	dir.mu.Lock()
	dir.email = c.name + "@example.test"
	dir.mu.Unlock()

	if got := eraseAndReadOutcome(t, env, c); got != "deleted" {
		t.Fatalf("X-Agentry-Directory-Erasure = %q, want deleted", got)
	}
	if len(dir.erased) != 1 || dir.erased[0].Email != c.name+"@example.test" {
		t.Fatalf("the directory erased %+v", dir.erased)
	}
	mu.Lock()
	defer mu.Unlock()
	var erased *api.Event
	for i := range heard {
		if heard[i].Kind == "account.erased" {
			erased = &heard[i]
		}
	}
	if erased == nil {
		t.Fatalf("no account.erased among %d events", len(heard))
	}
	if erased.UserID.String() != uid || erased.Email != c.name+"@example.test" ||
		len(erased.Identities) != 1 || erased.Identities[0] != "oidc:sub-"+c.name {
		t.Fatalf("account.erased = %+v", *erased)
	}
}

// TestWithNoDirectoryTheRegistryStandsAlone: a deployment whose credentials
// live at an OpenID provider, with no extension's directory, erases at the
// registry alone, and says and audits so.
func TestWithNoDirectoryTheRegistryStandsAlone(t *testing.T) {
	env, idp := newOIDCTestEnv(t, nil)
	c := env.mintAccount(t, idp, "no-dir")
	uid := env.selfID(c)
	if got := eraseAndReadOutcome(t, env, c); got != "not-configured" {
		t.Fatalf("X-Agentry-Directory-Erasure = %q, want not-configured", got)
	}
	if outcome, _ := lastDirectoryErasure(t, env, uid); outcome != "not-configured" {
		t.Fatalf("the erasure's audit row says %q, want not-configured", outcome)
	}
}

// eraseAndReadOutcome erases the caller's account and returns the
// directory outcome the 204 carries.
func eraseAndReadOutcome(t *testing.T, env *testEnv, c caller) string {
	t.Helper()
	res := env.do(c, http.MethodPost, "/api/v1/user/delete", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("erase: %d, want 204", res.StatusCode)
	}
	return res.Header.Get("X-Agentry-Directory-Erasure")
}

// lastDirectoryErasure is the outcome and lookup of the person's latest
// user.directory_erase audit row.
func lastDirectoryErasure(t *testing.T, env *testEnv, userID string) (outcome, lookup string) {
	t.Helper()
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'directoryErasure', coalesce(detail->>'directoryLookup', '') FROM audit_events
		 WHERE action = 'user.directory_erase' AND target_id = $1::uuid ORDER BY occurred_at DESC LIMIT 1`, userID).Scan(&outcome, &lookup); err != nil {
		t.Fatal(err)
	}
	return outcome, lookup
}

// TestSignInHookHearsTheClaimsAndMayRememberTheBrowser: an extension hears
// every claim of the token before the session is issued, and may mint a
// remembered browser from a sign-in that answered a second factor just
// now; the record is the core's, stored as SHA-256 and bound to the
// account.
func TestSignInHookHearsTheClaimsAndMayRememberTheBrowser(t *testing.T) {
	var srv *api.Server
	var heard []api.SignIn
	var firstSaw, secondSaw any
	env, idp := newOIDCTestEnv(t, nil, func(s *api.Server) {
		srv = s
		s.AddSignInHook(func(_ context.Context, in api.SignIn) {
			heard = append(heard, in)
			firstSaw = in.Claims["x_org"]
			if in.Claims["x_remember"] != true {
				return
			}
			tok, ttl, err := in.RememberBrowser(map[string]any{"via": "test-directory"})
			if err != nil {
				t.Errorf("mint: %v", err)
				return
			}
			in.SetCookie(&http.Cookie{Name: "x_remembered", Value: tok, MaxAge: int(ttl.Seconds())})
			// A hook's changes to the claims are its own.
			in.Claims["agentry_remember_device"] = true
			in.Claims["x_org"] = "changed"
		})
		s.AddSignInHook(func(_ context.Context, in api.SignIn) { secondSaw = in.Claims["x_org"] })
	})
	h := "hooked" + env.sfx
	person := testidp.Person{
		Subject: "sub-" + h, Email: h + "@example.test", EmailVerified: true, Username: h,
		AMR: []string{"pwd", "mfa"}, AuthTime: time.Now(), Claims: map[string]any{"x_remember": true, "x_org": "acme"},
	}
	in := env.signInOIDC(t, idp, "oidc", person)
	if in.status != http.StatusOK || len(heard) != 1 {
		t.Fatalf("sign-in: %d, %d hooks heard", in.status, len(heard))
	}
	if secondSaw != "acme" {
		t.Fatalf("the second hook read x_org %v: the first hook's change reached it", secondSaw)
	}
	got := heard[0]
	if got.UserID.String() != in.userID || got.Provider != "oidc" || got.Subject != "oidc:sub-"+h ||
		firstSaw != "acme" || len(got.AMR) != 2 || got.AuthTime.IsZero() {
		t.Fatalf("the hook heard %+v", got)
	}
	var token string
	for _, c := range in.cookies {
		if c.Name == "x_remembered" {
			token = c.Value
		}
	}
	if token == "" || in.caller.session == "" {
		t.Fatal("the hook's cookie and the session did not ride the same response")
	}
	var stored string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT encode(token_sha256, 'hex') FROM trusted_devices WHERE user_id = $1::uuid`, in.userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if want := auth.HashToken(token); stored != hex.EncodeToString(want) {
		t.Fatal("the remembered browser is not stored as the token's SHA-256")
	}

	r := httptest.NewRequest(http.MethodPost, "/internal/x/test/check", nil)
	uid := uuid.MustParse(in.userID)
	if ok, err := srv.UseRememberedBrowser(r, uid, token, map[string]any{"via": "test-directory"}); err != nil || !ok {
		t.Fatalf("use by its account: %v %v", ok, err)
	}
	if ok, err := srv.UseRememberedBrowser(r, uuid.New(), token, nil); err != nil || ok {
		t.Fatalf("use by another account: %v %v, want false", ok, err)
	}
	if ok, err := srv.UseRememberedBrowser(r, uid, token+"x", nil); err != nil || ok {
		t.Fatalf("a token that is not the record: %v %v, want false", ok, err)
	}
	var uses int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.trusted_device_use' AND target_id = $1::uuid AND detail->>'via' = 'test-directory'`, in.userID).Scan(&uses); err != nil {
		t.Fatal(err)
	}
	if uses != 1 {
		t.Fatalf("%d audited uses, want the one granted", uses)
	}

	// The evidence rules hold whoever asks.
	for name, ev := range map[string]struct {
		amr []string
		at  time.Time
	}{
		"no second factor":  {[]string{"pwd"}, time.Now()},
		"an old sign-in":    {[]string{"pwd", "mfa"}, time.Now().Add(-10 * time.Minute)},
		"no time":           {[]string{"pwd", "mfa"}, time.Time{}},
		"a time from ahead": {[]string{"pwd", "mfa"}, time.Now().Add(10 * time.Minute)},
	} {
		if _, _, err := srv.MintRememberedBrowser(r, uid, ev.amr, ev.at, nil); !errors.Is(err, api.ErrNoSecondFactor) {
			t.Errorf("%s: %v, want ErrNoSecondFactor", name, err)
		}
	}
	if _, _, err := srv.MintRememberedBrowser(r, uuid.New(), []string{"mfa"}, time.Now(), nil); err == nil {
		t.Error("a remembered browser was minted for an account that does not exist")
	}
}

// TestASignInHookMayAssertAnOrganizationsSSO: a session whose sign-in a
// hook said came through an organization's own single sign-on satisfies
// that organization's enforced SSO, and no other organization's; a sign-in
// no hook said it of satisfies none. The login's audit row names it.
func TestASignInHookMayAssertAnOrganizationsSSO(t *testing.T) {
	var asserted uuid.UUID
	env, idp := newOIDCTestEnv(t, nil, func(s *api.Server) {
		s.AddSignInHook(func(_ context.Context, in api.SignIn) {
			if asserted != uuid.Nil {
				in.AssertSSO(asserted)
				in.AssertSSO(asserted)
			}
		})
	})
	h := "asserted" + env.sfx
	person := testidp.Person{Subject: "sub-" + h, Email: h + "@example.test", EmailVerified: true, Username: h}
	first := env.signInOIDC(t, idp, "oidc", person)
	if first.status != http.StatusOK {
		t.Fatalf("first sign-in: %d %s", first.status, first.body)
	}
	// A person belongs to one organization at a time, so the other
	// organization is someone else's.
	other := env.mintAccount(t, idp, "asserted-other")
	orgA, orgB := "ssoa"+env.sfx, "ssob"+env.sfx
	idA := env.createOrg(first.caller, orgA)
	idB := env.createOrg(other, orgB)
	env.doJSON(first.caller, http.MethodPatch, "/api/v1/orgs/"+orgA, map[string]any{"ssoRequired": true}, nil, http.StatusOK)
	refused := func(c caller) bool {
		t.Helper()
		res := env.do(c, http.MethodPatch, "/api/v1/orgs/"+orgA, map[string]any{"displayName": "Renamed " + orgA})
		code, slug, _ := problemOf(t, res)
		if code != http.StatusOK && (code != http.StatusForbidden || slug != "sso-required") {
			t.Fatalf("PATCH %s: %d %s, want 200 or 403 sso-required", orgA, code, slug)
		}
		return code == http.StatusForbidden
	}
	if !refused(first.caller) {
		t.Fatal("a session no hook asserted SSO for passed the organization's enforced SSO")
	}

	asserted = uuid.MustParse(idB)
	elsewhere := env.signInOIDC(t, idp, "oidc", person)
	if elsewhere.status != http.StatusOK || !refused(elsewhere.caller) {
		t.Fatalf("a sign-in asserted for another organization: %d, or it satisfied this one's enforced SSO", elsewhere.status)
	}

	asserted = uuid.MustParse(idA)
	second := env.signInOIDC(t, idp, "oidc", person)
	if second.status != http.StatusOK || second.userID != first.userID {
		t.Fatalf("second sign-in: %d, account %s", second.status, second.userID)
	}
	if refused(second.caller) {
		t.Fatal("the session whose sign-in asserted the organization's SSO was refused by it")
	}
	if !refused(first.caller) {
		t.Fatal("an earlier session gained the later sign-in's assertion")
	}
	var named int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.login' AND target_id = $1::uuid AND detail->'ssoOrgs' = jsonb_build_array($2::text)`,
		first.userID, idA).Scan(&named); err != nil {
		t.Fatal(err)
	}
	if named != 1 {
		t.Fatalf("%d login rows name the asserted organization once, want 1", named)
	}
	var orgRows int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'sso.login' AND org_id = $1::uuid AND target_id = $2::uuid`,
		idA, first.userID).Scan(&orgRows); err != nil {
		t.Fatal(err)
	}
	if orgRows != 1 {
		t.Fatalf("%d sso.login rows in the organization's audit log, want 1", orgRows)
	}
}

// TestStaffChangedIsHeardAndTheSetIsRead: a change to platform staff is
// heard as staff.changed once its transaction has had time to commit, and
// the set an extension reads is the registry's.
func TestStaffChangedIsHeardAndTheSetIsRead(t *testing.T) {
	f := newStaffFixture(t)
	var mu sync.Mutex
	staffEvents := 0
	f.srv.AddEventHook(func(_ context.Context, ev api.Event) {
		if ev.Kind == "staff.changed" {
			mu.Lock()
			staffEvents++
			mu.Unlock()
		}
	})
	alice := f.person("alice")
	f.join(alice, "alice-"+f.env.sfx+"@"+f.domain)

	members, err := f.srv.PlatformStaff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, m := range members {
		found[m.Handle] = m.Email
	}
	if found[alice] != "alice-"+f.env.sfx+"@"+f.domain || found[f.founded] == "" {
		t.Fatalf("platform staff %v, want alice and the founder among them", found)
	}

	q := queue.NewRiverClient(f.env.st, nil)
	q.SetTestOnly(true)
	f.srv.RegisterQueueHandlers(q)
	for i := 0; i < 5; i++ {
		if _, err := f.env.st.Pool().Exec(context.Background(),
			`UPDATE river_job SET scheduled_at = now() WHERE kind = 'staff.changed_event' AND state IN ('available', 'retryable', 'scheduled')`); err != nil {
			t.Fatal(err)
		}
		q.Drain(context.Background(), "core")
		mu.Lock()
		n := staffEvents
		mu.Unlock()
		if n > 0 {
			return
		}
	}
	t.Fatal("staff.changed was never heard")
}

// TestAccountErasedCarriesTheIdentitiesWithoutAnyDirectory: the event is the
// core's, so it is heard with no directory at all.
func TestAccountErasedCarriesTheIdentitiesWithoutAnyDirectory(t *testing.T) {
	var heard []api.Event
	env, idp := newOIDCTestEnv(t, nil, func(s *api.Server) {
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "account.erased" {
				heard = append(heard, ev)
			}
		})
	})
	c := env.mintAccount(t, idp, "erased")
	uid := env.selfID(c)
	eraseAndReadOutcome(t, env, c)
	if len(heard) != 1 {
		t.Fatalf("heard account.erased %d times, want once", len(heard))
	}
	raw, _ := json.Marshal(heard[0].Identities)
	if heard[0].UserID.String() != uid || heard[0].Email != c.name+"@example.test" || string(raw) != `["oidc:sub-`+c.name+`"]` {
		t.Fatalf("account.erased = %+v", heard[0])
	}
}

// TestADirectoryWithoutItsOwnErasureIsAskedOnce: a directory that does not
// erase on its own is asked once through the port, and the outcome is
// reported on the response and in the audit row; a failure is reported as
// failed, never retried by the core.
func TestADirectoryWithoutItsOwnErasureIsAskedOnce(t *testing.T) {
	for _, tc := range []struct {
		name            string
		fail            error
		lookup          api.DirectoryLookup
		header, outcome string
	}{
		{"deleted", nil, "", "deleted", "deleted"},
		{"the directory fails", errors.New("the directory is down"), "", "failed", "failed"},
		{"an account it cannot tell apart", nil, api.DirectoryLookupAddressShared, "unresolved", "unresolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := &fakeDirectory{fail: tc.fail, lookup: tc.lookup}
			mx, err := metrics.New(context.Background(), metrics.Config{ServiceName: "agentryd", Role: "all", Env: "dev"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mx.Shutdown(context.Background()) })
			env, idp := newOIDCTestEnv(t, nil, func(s *api.Server) {
				s.SetDirectory(dir)
				s.SetMetrics(mx)
			})
			c := env.mintAccount(t, idp, "asked-once")
			dir.mu.Lock()
			dir.email = c.name + "@example.test"
			dir.mu.Unlock()
			uid := env.selfID(c)
			if got := eraseAndReadOutcome(t, env, c); got != tc.header {
				t.Fatalf("X-Agentry-Directory-Erasure = %q, want %q", got, tc.header)
			}
			outcome, lookup := lastDirectoryErasure(t, env, uid)
			wantLookup := map[bool]string{true: "address", false: string(tc.lookup)}[tc.lookup == ""]
			if outcome != tc.outcome || (tc.fail == nil && lookup != wantLookup) {
				t.Fatalf("the audit row says %q by %q, want %q", outcome, lookup, tc.outcome)
			}
			dir.mu.Lock()
			erased := len(dir.erased)
			dir.mu.Unlock()
			if want := map[bool]int{true: 1, false: 0}[tc.fail == nil && tc.lookup == ""]; erased != want {
				t.Fatalf("the directory erased %d accounts, want %d", erased, want)
			}
			// A directory half that did not happen is raised: the fail-open
			// count the operator's alarm reads.
			b, err := mx.Gather(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if raised := strings.Contains(string(b), metrics.FailOpenDirectoryErasure); raised != (tc.outcome != "deleted") {
				t.Fatalf("fail-open %s raised = %v for %s", metrics.FailOpenDirectoryErasure, raised, tc.outcome)
			}
			var jobs int
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT count(*) FROM river_job WHERE args->>'userId' = $1 AND kind LIKE '%directory%'`, uid).Scan(&jobs); err != nil {
				t.Fatal(err)
			}
			if jobs != 0 {
				t.Fatalf("the core queued %d directory jobs", jobs)
			}
		})
	}
}
