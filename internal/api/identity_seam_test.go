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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
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

// TestExistingDirectoryIdentitiesKeepTheirAccounts: every account the
// directory linked as "authentik:<sub>" under the older social.authentik
// keys is the same account when the same provider is configured as the
// generic one with the id "authentik": no account is re-created or
// re-linked.
func TestExistingDirectoryIdentitiesKeepTheirAccounts(t *testing.T) {
	idp := testidp.New(t)
	legacy := newTestEnvCfg(t, func(c *config.Config) {
		c.Social.Authentik = config.SocialProvider{ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, Issuer: idp.URL}
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.Client()) })
	generic := newTestEnvCfg(t, func(c *config.Config) {
		c.Auth.OIDC = config.OIDCProvider{ID: config.DirectoryProviderID, Issuer: idp.URL, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret}
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.Client()) })

	ctx := context.Background()
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := legacy.st.Pool().QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	people := []testidp.Person{
		{Subject: "keep-a-" + legacy.sfx, Email: "keep-a-" + legacy.sfx + "@example.test", EmailVerified: true, Username: "keep-a-" + legacy.sfx},
		{Subject: "keep-b-" + legacy.sfx, Email: "keep-b-" + legacy.sfx + "@example.test", EmailVerified: true},
		// An unverified address: the account is linked by its subject alone.
		{Subject: "keep-c-" + legacy.sfx, Email: "keep-c-" + legacy.sfx + "@example.test"},
	}
	accounts := map[string]string{}
	for _, p := range people {
		in := legacy.signInOIDC(t, idp, "authentik", p)
		if in.status != http.StatusOK {
			t.Fatalf("legacy sign-in %s: %d %s", p.Subject, in.status, in.body)
		}
		accounts[p.Subject] = in.userID
	}
	users := count(`SELECT count(*) FROM users`)
	idents := count(`SELECT count(*) FROM identities`)

	for _, env := range []*testEnv{generic, legacy} {
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
// an extension, the settings page lists the account's authenticators and
// removes the caller's own, erasure deletes the directory account and says
// so, and the extensions hear the erasure with the identities and the
// address it held.
func TestADirectoryFromAnExtensionServesTheRegistry(t *testing.T) {
	dir := &fakeDirectory{devices: []api.DirectoryDevice{{ID: "7", Kind: "totp", Name: "Phone"}}}
	var mu sync.Mutex
	var heard []api.Event
	env, idp := newOIDCTestEnv(t, func(c *config.Config) { c.Auth.ExternalOnly = true },
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

	var got struct {
		Managed           bool    `json:"managed"`
		PasswordChangeUrl *string `json:"passwordChangeUrl"`
		HasPassword       *bool   `json:"hasPassword"`
		Devices           []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"devices"`
	}
	env.doJSON(c, http.MethodGet, "/api/v1/user/directory", nil, &got, http.StatusOK)
	if !got.Managed || got.PasswordChangeUrl != nil || len(got.Devices) != 1 || got.Devices[0].ID != "7" || got.HasPassword == nil || !*got.HasPassword {
		t.Fatalf("settings through the extension's directory: %+v", got)
	}
	env.doJSON(c, http.MethodDelete, "/api/v1/user/directory/devices/totp/8", nil, nil, http.StatusNotFound)
	env.doJSON(c, http.MethodDelete, "/api/v1/user/directory/devices/totp/7", nil, nil, http.StatusNoContent)
	if len(dir.removed) != 1 || dir.removed[0] != "totp/7" {
		t.Fatalf("removed %v, want totp/7 alone", dir.removed)
	}

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
// live at an OpenID provider that is no directory, with no extension's
// directory, says the account is not the directory's and erases at the
// registry alone.
func TestWithNoDirectoryTheRegistryStandsAlone(t *testing.T) {
	env, idp := newOIDCTestEnv(t, func(c *config.Config) { c.Auth.ExternalOnly = true })
	c := env.mintAccount(t, idp, "no-dir")
	var got map[string]any
	env.doJSON(c, http.MethodGet, "/api/v1/user/directory", nil, &got, http.StatusOK)
	if got["managed"] != false || len(got) != 1 {
		t.Fatalf("GET /user/directory = %v, want managed:false alone", got)
	}
	env.doJSON(c, http.MethodDelete, "/api/v1/user/directory/devices/totp/1", nil, nil, http.StatusNotFound)
	if got := eraseAndReadOutcome(t, env, c); got != "not-configured" {
		t.Fatalf("X-Agentry-Directory-Erasure = %q, want not-configured", got)
	}
}

// TestSignInHookHearsTheClaimsAndMayRememberTheBrowser: an extension hears
// every claim of the token before the session is issued, and may mint a
// remembered browser from a sign-in that answered a second factor just
// now; the record is the core's, stored as SHA-256 and bound to the
// account.
func TestSignInHookHearsTheClaimsAndMayRememberTheBrowser(t *testing.T) {
	var srv *api.Server
	var heard []api.SignIn
	env, idp := newOIDCTestEnv(t, nil, func(s *api.Server) {
		srv = s
		s.AddSignInHook(func(_ context.Context, in api.SignIn) {
			heard = append(heard, in)
			if in.Claims["x_remember"] != true {
				return
			}
			tok, ttl, err := s.MintRememberedBrowser(in.Request, in.UserID, in.AMR, in.AuthTime, map[string]any{"via": "test-directory"})
			if err != nil {
				t.Errorf("mint: %v", err)
				return
			}
			in.SetCookie(&http.Cookie{Name: "x_remembered", Value: tok, MaxAge: int(ttl.Seconds())})
		})
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
	got := heard[0]
	if got.UserID.String() != in.userID || got.Provider != "oidc" || got.Subject != "oidc:sub-"+h ||
		got.Claims["x_org"] != "acme" || len(got.AMR) != 2 || got.AuthTime.IsZero() {
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
