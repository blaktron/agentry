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
	"slices"
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
	env, idp := newOIDCTestEnv(t, func(c *config.Config) { c.Auth.CookieSecure = true })
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
	// The session cookie keeps every attribute the sign-in gives it.
	var session *http.Cookie
	for _, ck := range again.cookies {
		if ck.Name == "agentry_session" {
			session = ck
		}
	}
	if session == nil {
		t.Fatal("the sign-in set no session cookie")
	}
	if !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteLaxMode || session.Path != "/" || session.MaxAge != 3600 {
		t.Fatalf("session cookie attributes: HttpOnly=%v Secure=%v SameSite=%v Path=%q MaxAge=%d, want HttpOnly, Secure, Lax, /, 3600",
			session.HttpOnly, session.Secure, session.SameSite, session.Path, session.MaxAge)
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
	var regMu sync.Mutex
	verified := map[string]any{} // handle -> what user.registered said of the address
	first := newTestEnvCfg(t, cfg, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.Client())
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "user.registered" {
				regMu.Lock()
				verified[ev.Payload["email"].(string)] = ev.Payload["emailVerified"]
				regMu.Unlock()
			}
		})
	})
	second := newTestEnvCfg(t, cfg, func(s *api.Server) { s.SetOIDCHTTPClient(idp.Client()) })

	// The provider is offered, and served, under the id "authentik" only.
	var meta struct {
		SignInProviders []string `json:"signInProviders"`
	}
	first.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
	if len(meta.SignInProviders) != 1 || meta.SignInProviders[0] != "authentik" {
		t.Fatalf("signInProviders = %v, want [authentik]", meta.SignInProviders)
	}
	res := first.do(anonymous, http.MethodGet, "/api/v1/auth/oidc/oidc/start", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("oidc start on a deployment whose provider is authentik: %d, want 404", res.StatusCode)
	}

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
	// The address is said to be verified only where the provider vouched for it.
	regMu.Lock()
	for i, p := range people {
		if got := verified[p.Email]; got != (i < 2) {
			regMu.Unlock()
			t.Fatalf("user.registered said emailVerified = %v for %s, want %v", got, p.Email, i < 2)
		}
	}
	regMu.Unlock()
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
	// links is every link EraseAccount was asked about, in order.
	links []api.DirectoryLink
	// byUID answers the link with that uid in place of the rest.
	byUID map[string]fakeAnswer
}

// fakeAnswer is how a lookup of one link ends: the lookup it reports with
// nothing erased, or the error it fails with.
type fakeAnswer struct {
	lookup api.DirectoryLookup
	fail   error
}

func (d *fakeDirectory) owns(l api.DirectoryLink) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.email != "" && l.Email == d.email
}

func (d *fakeDirectory) EraseAccount(_ context.Context, l api.DirectoryLink) (bool, api.DirectoryLookup, error) {
	d.mu.Lock()
	d.links = append(d.links, l)
	ans, answered := d.byUID[l.UID]
	d.mu.Unlock()
	if answered {
		if ans.fail != nil {
			return false, "", ans.fail
		}
		return false, ans.lookup, nil
	}
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
	erasedWhenHeard := -1
	env, idp := newOIDCTestEnv(t, nil,
		func(s *api.Server) {
			s.SetDirectory(dir)
			s.AddEventHook(func(_ context.Context, ev api.Event) {
				if ev.Kind == "account.erased" {
					// The directory's attempt has been made by the time the
					// extensions hear the erasure.
					dir.mu.Lock()
					erasedWhenHeard = len(dir.erased)
					dir.mu.Unlock()
				}
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
	if erasedWhenHeard != 1 {
		t.Fatalf("account.erased was heard with %d directory erasures made, want the one attempt already made", erasedWhenHeard)
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
	var firstAMR, secondAMR []string
	var mintErr error
	env, idp := newOIDCTestEnv(t, func(c *config.Config) { c.Auth.TrustedDeviceTTL = deviceTTL }, func(s *api.Server) {
		srv = s
		s.AddSignInHook(func(_ context.Context, in api.SignIn) {
			heard = append(heard, in)
			firstSaw = in.Claims["x_org"]
			firstAMR = slices.Clone(in.AMR)
			// A hook's changes to the amr are its own.
			if len(in.AMR) > 0 {
				in.AMR[0] = "changed"
			}
			if in.Claims["x_remember"] != true {
				return
			}
			tok, ttl, err := in.RememberBrowser(map[string]any{"via": "test-directory"})
			if in.Claims["x_expect"] == "refused" {
				mintErr = err
				return
			}
			if err != nil {
				t.Errorf("mint: %v", err)
				return
			}
			in.SetCookie(&http.Cookie{Name: "x_remembered", Value: tok, MaxAge: int(ttl.Seconds())})
			// A hook's changes to the claims are its own.
			in.Claims["agentry_remember_device"] = true
			in.Claims["x_org"] = "changed"
		})
		// A hook that falls over does not stop the sign-in or the hooks after it.
		s.AddSignInHook(func(context.Context, api.SignIn) { panic("a sign-in hook that fell over") })
		s.AddSignInHook(func(_ context.Context, in api.SignIn) {
			secondSaw = in.Claims["x_org"]
			secondAMR = slices.Clone(in.AMR)
		})
	})
	h := "hooked" + env.sfx
	person := testidp.Person{
		Subject: "sub-" + h, Email: h + "@example.test", EmailVerified: true, Username: h,
		AMR: []string{"pwd", "mfa"}, AuthTime: time.Now().Add(-2 * time.Minute), Claims: map[string]any{"x_remember": true, "x_org": "acme"},
	}
	in := env.signInOIDC(t, idp, "oidc", person)
	if in.status != http.StatusOK || len(heard) != 1 {
		t.Fatalf("sign-in: %d, %d hooks heard", in.status, len(heard))
	}
	if secondSaw != "acme" {
		t.Fatalf("the second hook read x_org %v: the first hook's change reached it", secondSaw)
	}
	if want := []string{"pwd", "mfa"}; !slices.Equal(firstAMR, want) || !slices.Equal(secondAMR, want) {
		t.Fatalf("the hooks heard amr %v and %v, want %v for both (a hook's change reached the next)", firstAMR, secondAMR, want)
	}
	got := heard[0]
	if got.UserID.String() != in.userID || got.Provider != "oidc" || got.Subject != "oidc:sub-"+h ||
		firstSaw != "acme" || len(got.AMR) != 2 || got.AuthTime.IsZero() {
		t.Fatalf("the hook heard %+v", got)
	}
	if got.AuthTime.Unix() != person.AuthTime.Unix() {
		t.Fatalf("the hook heard auth_time %v, want the token's %v", got.AuthTime, person.AuthTime)
	}
	if got.Request == nil || got.Request.URL.Path != "/api/v1/auth/oidc/oidc/callback" {
		t.Fatalf("the hook heard the request %v, want the callback's", got.Request)
	}
	var token string
	var cookieMaxAge int
	for _, c := range in.cookies {
		if c.Name == "x_remembered" {
			token, cookieMaxAge = c.Value, c.MaxAge
		}
	}
	if token == "" || in.caller.session == "" {
		t.Fatal("the hook's cookie and the session did not ride the same response")
	}
	if cookieMaxAge != int(deviceTTL.Seconds()) {
		t.Fatalf("the remembered browser's lifetime was reported as %ds, want the configured %ds", cookieMaxAge, int(deviceTTL.Seconds()))
	}
	if !strings.HasPrefix(token, auth.TrustedDevicePrefix) {
		t.Fatalf("the remembered browser's token does not start with %q", auth.TrustedDevicePrefix)
	}
	var stored string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT encode(token_sha256, 'hex') FROM trusted_devices WHERE user_id = $1::uuid`, in.userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if want := auth.HashToken(token); stored != hex.EncodeToString(want) {
		t.Fatal("the remembered browser is not stored as the token's SHA-256")
	}
	// The record keeps the facts the account page describes it by, lives for
	// the configured lifetime, and its minting is audited with the hook's detail.
	var devID string
	var expires time.Time
	var userAgent *string
	var hasIP bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT id::text, expires_at, user_agent, ip IS NOT NULL FROM trusted_devices WHERE user_id = $1::uuid`, in.userID).Scan(&devID, &expires, &userAgent, &hasIP); err != nil {
		t.Fatal(err)
	}
	if userAgent == nil || *userAgent == "" || !hasIP {
		t.Fatalf("the record keeps user agent %v and address recorded %v, want both", userAgent, hasIP)
	}
	if d := time.Until(expires) - deviceTTL; d > time.Minute || d < -time.Minute {
		t.Fatalf("the record expires at %v, want the configured lifetime %v from now", expires, deviceTTL)
	}
	var added int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.trusted_device_add' AND actor_id = $1::uuid AND target_id = $1::uuid AND detail->>'via' = 'test-directory'`, in.userID).Scan(&added); err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("%d user.trusted_device_add rows for the account with the hook's detail, want 1", added)
	}
	// A use moves last_seen_at and never expires_at.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE trusted_devices SET last_seen_at = now() - interval '1 hour' WHERE id = $1::uuid`, devID); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/internal/x/test/check", nil)
	uid := uuid.MustParse(in.userID)
	// The audited device id is the record's, whatever the caller's detail says.
	if ok, err := srv.UseRememberedBrowser(r, uid, token, map[string]any{"via": "test-directory", "device": "forged"}); err != nil || !ok {
		t.Fatalf("use by its account: %v %v", ok, err)
	}
	if ok, err := srv.UseRememberedBrowser(r, uuid.New(), token, nil); err != nil || ok {
		t.Fatalf("use by another account: %v %v, want false", ok, err)
	}
	if ok, err := srv.UseRememberedBrowser(r, uid, token+"x", nil); err != nil || ok {
		t.Fatalf("a token that is not the record: %v %v, want false", ok, err)
	}
	var seenAfter, expiresAfter time.Time
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT last_seen_at, expires_at FROM trusted_devices WHERE id = $1::uuid`, devID).Scan(&seenAfter, &expiresAfter); err != nil {
		t.Fatal(err)
	}
	if time.Since(seenAfter) > time.Minute {
		t.Fatalf("last_seen_at is %v after a use, want it moved to now", seenAfter)
	}
	if !expiresAfter.Equal(expires) {
		t.Fatalf("a use moved expires_at from %v to %v: the lifetime is absolute", expires, expiresAfter)
	}
	var uses int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.trusted_device_use' AND target_id = $1::uuid AND detail->>'via' = 'test-directory'`, in.userID).Scan(&uses); err != nil {
		t.Fatal(err)
	}
	if uses != 1 {
		t.Fatalf("%d audited uses, want the one granted", uses)
	}
	var usedDevice string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT coalesce(detail->>'device', '') FROM audit_events WHERE action = 'user.trusted_device_use' AND actor_id = $1::uuid AND target_id = $1::uuid`, in.userID).Scan(&usedDevice); err != nil {
		t.Fatal(err)
	}
	if usedDevice != devID {
		t.Fatalf("the audited use names device %q, want the record's %q", usedDevice, devID)
	}

	// The evidence rules hold whoever asks.
	for name, ev := range map[string]struct {
		amr []string
		at  time.Time
	}{
		"no second factor":                {[]string{"pwd"}, time.Now()},
		"an old sign-in":                  {[]string{"pwd", "mfa"}, time.Now().Add(-10 * time.Minute)},
		"a sign-in just past the window":  {[]string{"pwd", "mfa"}, time.Now().Add(-6 * time.Minute)},
		"no time":                         {[]string{"pwd", "mfa"}, time.Time{}},
		"a time from ahead":               {[]string{"pwd", "mfa"}, time.Now().Add(10 * time.Minute)},
		"a time just ahead of the window": {[]string{"pwd", "mfa"}, time.Now().Add(6 * time.Minute)},
	} {
		if _, _, err := srv.MintRememberedBrowser(r, uid, ev.amr, ev.at, nil); !errors.Is(err, api.ErrNoSecondFactor) {
			t.Errorf("%s: %v, want ErrNoSecondFactor", name, err)
		}
	}
	// A sign-in inside the window, either side of now, is remembered for the
	// configured lifetime.
	for name, at := range map[string]time.Time{
		"a sign-in four minutes ago": time.Now().Add(-4 * time.Minute),
		"a time four minutes ahead":  time.Now().Add(4 * time.Minute),
	} {
		tok, ttl, err := srv.MintRememberedBrowser(r, uid, []string{"pwd", "mfa"}, at, nil)
		if err != nil || tok == "" || ttl != deviceTTL {
			t.Errorf("%s: token %q, lifetime %v, error %v, want a token for %v", name, tok, ttl, err, deviceTTL)
		}
	}
	if _, _, err := srv.MintRememberedBrowser(r, uuid.New(), []string{"mfa"}, time.Now(), nil); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Errorf("a remembered browser for an account that does not exist: %v, want the account is not active", err)
	}

	// A remembered browser follows the account's state, and the sign-in of a
	// suspended account gets no session and is not heard by the hooks.
	setState := func(state string) {
		t.Helper()
		if _, err := env.st.Pool().Exec(context.Background(), `UPDATE users SET state = $2 WHERE id = $1::uuid`, in.userID, state); err != nil {
			t.Fatal(err)
		}
	}
	setState("suspended")
	if _, _, err := srv.MintRememberedBrowser(r, uid, []string{"pwd", "mfa"}, time.Now(), nil); err == nil || errors.Is(err, api.ErrNoSecondFactor) || !strings.Contains(err.Error(), "not active") {
		t.Errorf("a remembered browser for a suspended account: %v, want the account is not active", err)
	}
	if ok, err := srv.UseRememberedBrowser(r, uid, token, nil); err != nil || ok {
		t.Errorf("use of a suspended account's remembered browser: %v %v, want false", ok, err)
	}
	before := len(heard)
	person.AuthTime = time.Now()
	if susp := env.signInOIDC(t, idp, "oidc", person); susp.status != http.StatusUnauthorized || len(heard) != before {
		t.Errorf("sign-in of a suspended account: %d, %d hooks heard, want 401 and none", susp.status, len(heard)-before)
	}
	setState("active")

	// The evidence is the token's own: a sign-in that did not answer a second
	// factor just now cannot have its browser remembered through the hook.
	for name, ev := range map[string]struct {
		amr []string
		at  time.Time
	}{
		"a password-only sign-in": {[]string{"pwd"}, time.Now()},
		"a stale sign-in":         {[]string{"pwd", "mfa"}, time.Now().Add(-10 * time.Minute)},
	} {
		p := person
		p.AMR, p.AuthTime = ev.amr, ev.at
		p.Claims = map[string]any{"x_remember": true, "x_expect": "refused"}
		mintErr = nil
		if res := env.signInOIDC(t, idp, "oidc", p); res.status != http.StatusOK || !errors.Is(mintErr, api.ErrNoSecondFactor) {
			t.Errorf("%s: sign-in %d, the hook's remember answered %v, want ErrNoSecondFactor", name, res.status, mintErr)
		}
	}
}

// TestASignInHookMayAssertAnOrganizationsSSO: a session whose sign-in a
// hook said came through an organization's own single sign-on satisfies
// that organization's enforced SSO, and no other organization's, as fresh
// as the token's auth_time: a provider session re-used long after its
// sign-in, or a token with no auth_time, satisfies nothing. A sign-in no
// hook said it of satisfies none. The login's audit row names it.
func TestASignInHookMayAssertAnOrganizationsSSO(t *testing.T) {
	var asserted, alsoAsserted uuid.UUID
	env, idp := newOIDCTestEnv(t, nil, func(s *api.Server) {
		s.AddSignInHook(func(_ context.Context, in api.SignIn) {
			// The nil organization is nobody's: asserting it tags nothing.
			in.AssertSSO(uuid.Nil)
			if asserted != uuid.Nil {
				in.AssertSSO(asserted)
				in.AssertSSO(asserted)
			}
			if alsoAsserted != uuid.Nil {
				in.AssertSSO(alsoAsserted)
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

	person.AuthTime = time.Now()
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
	for name, at := range map[string]time.Time{
		"a provider session nine hours old":        time.Now().Add(-9 * time.Hour),
		"a provider session just past eight hours": time.Now().Add(-8*time.Hour - 10*time.Minute),
		"no auth_time":               {},
		"an auth_time an hour ahead": time.Now().Add(time.Hour),
	} {
		stale := person
		stale.AuthTime = at
		in := env.signInOIDC(t, idp, "oidc", stale)
		if in.status != http.StatusOK || !refused(in.caller) {
			t.Errorf("%s: %d, or the session satisfied the organization's enforced SSO", name, in.status)
		}
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
		`SELECT count(*) FROM audit_events WHERE action = 'sso.login' AND org_id = $1::uuid AND target_id = $2::uuid AND actor_id = $2::uuid
		 AND detail->>'provider' = 'oidc' AND detail->>'via' = 'sign-in hook'`,
		idA, first.userID).Scan(&orgRows); err != nil {
		t.Fatal(err)
	}
	if orgRows != 1 {
		t.Fatalf("%d sso.login rows in the organization's audit log, want 1", orgRows)
	}

	// Inside the freshness window the assertion holds: a provider session
	// seven hours old, and a clock a little ahead of the provider's (stamped
	// as of now, never in the future).
	for name, at := range map[string]time.Time{
		"a provider session seven hours old": time.Now().Add(-7 * time.Hour),
		"an auth_time two minutes ahead":     time.Now().Add(2 * time.Minute),
	} {
		fresh := person
		fresh.AuthTime = at
		in := env.signInOIDC(t, idp, "oidc", fresh)
		if in.status != http.StatusOK || refused(in.caller) {
			t.Errorf("%s: %d, or the session did not satisfy the organization's enforced SSO", name, in.status)
		}
		var notAhead bool
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT (sso_tags->>$2)::timestamptz <= now() FROM sessions WHERE token_sha256 = $1`,
			auth.HashToken(in.caller.session), idA).Scan(&notAhead); err != nil || !notAhead {
			t.Errorf("%s: the session's SSO stamp is in the future or missing (%v)", name, err)
		}
	}
	// Two organizations asserted by one sign-in are both tagged.
	asserted, alsoAsserted = uuid.MustParse(idA), uuid.MustParse(idB)
	both := env.signInOIDC(t, idp, "oidc", person)
	if both.status != http.StatusOK || refused(both.caller) {
		t.Fatalf("a sign-in that asserted two organizations: %d, or the first was not satisfied", both.status)
	}
	var tagged bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT sso_tags ? $2 AND sso_tags ? $3 FROM sessions WHERE token_sha256 = $1`,
		auth.HashToken(both.caller.session), idA, idB).Scan(&tagged); err != nil || !tagged {
		t.Fatalf("the session is tagged for both organizations: %v (%v)", tagged, err)
	}
}

// TestStaffChangedIsHeardAndTheSetIsRead: a change to platform staff is
// heard as staff.changed once its transaction has had time to commit, and
// the set an extension reads is the registry's.
func TestStaffChangedIsHeardAndTheSetIsRead(t *testing.T) {
	f := newStaffFixture(t)
	ctx := context.Background()
	staffJobs := func(since int64, extra string) int {
		t.Helper()
		var n int
		if err := f.env.st.Pool().QueryRow(ctx,
			`SELECT count(*) FROM river_job WHERE kind = 'staff.changed_event' AND id > $1 `+extra, since).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	lastJob := func() int64 {
		t.Helper()
		var id int64
		if err := f.env.st.Pool().QueryRow(ctx, `SELECT coalesce(max(id), 0) FROM river_job`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}

	// With no extension listening, a staff change queues no event.
	before := lastJob()
	quiet := f.person("quiet")
	f.join(quiet, "quiet-"+f.env.sfx+"@"+f.domain)
	if !f.staff(quiet) {
		t.Fatal("joining the staff organization made no staff")
	}
	if n := staffJobs(before, ""); n != 0 {
		t.Fatalf("%d staff.changed events queued with no listener, want none", n)
	}

	var mu sync.Mutex
	staffEvents := 0
	f.srv.AddEventHook(func(_ context.Context, ev api.Event) {
		if ev.Kind == "staff.changed" {
			mu.Lock()
			staffEvents++
			mu.Unlock()
		}
	})
	before = lastJob()
	alice := f.person("alice")
	f.join(alice, "alice-"+f.env.sfx+"@"+f.domain)
	// The event is queued for a few seconds ahead, so the change has
	// committed when it is heard, and is retried.
	if n := staffJobs(before, `AND queue = 'core' AND scheduled_at > now() AND max_attempts = 3`); n != 1 {
		t.Fatalf("%d staff.changed events queued to be heard later with three attempts, want 1", n)
	}

	// People who are staff by the flag but are not listed: an account that is
	// no longer active, one whose address is unverified; and one listed with
	// its address lower-cased. A person outside the staff organization is no
	// staff.
	suspended, unverified, mixed, outsider := f.person("suspended"), f.person("unverified"), f.person("mixed"), f.person("outsider")
	for _, prefix := range []string{"suspended", "unverified", "mixed"} {
		f.join(prefix+f.env.sfx, prefix+"-"+f.env.sfx+"@"+f.domain)
	}
	for q, h := range map[string]string{
		`UPDATE users SET state = 'suspended' WHERE id = (SELECT id FROM handles WHERE handle = $1)`:      suspended,
		`UPDATE users SET email_verified_at = NULL WHERE id = (SELECT id FROM handles WHERE handle = $1)`: unverified,
		`UPDATE users SET email = upper(email) WHERE id = (SELECT id FROM handles WHERE handle = $1)`:     mixed,
	} {
		if _, err := f.env.st.Pool().Exec(ctx, q, h); err != nil {
			t.Fatal(err)
		}
	}

	members, err := f.srv.PlatformStaff(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	var order []string
	for _, m := range members {
		found[m.Handle] = m.Email
		order = append(order, m.Handle)
	}
	if found[alice] != "alice-"+f.env.sfx+"@"+f.domain || found[f.founded] == "" {
		t.Fatalf("platform staff %v, want alice and the founder among them", found)
	}
	if got := found[mixed]; got != "mixed-"+f.env.sfx+"@"+f.domain {
		t.Fatalf("platform staff lists %q for an address stored in capitals, want it lower-cased", got)
	}
	for name, h := range map[string]string{"an account that is not active": suspended, "an unverified address": unverified, "an account that is not staff": outsider} {
		if _, listed := found[h]; listed {
			t.Fatalf("platform staff lists %s (%s)", name, h)
		}
	}
	// Ordered by handle, in the database's own order.
	var inOrder []string
	rows, err := f.env.st.Pool().Query(ctx, `SELECT handle FROM handles WHERE handle = ANY($1) ORDER BY handle`, []string{alice, f.founded, mixed})
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		inOrder = append(inOrder, h)
	}
	rows.Close()
	var listedInOrder []string
	for _, h := range order {
		if slices.Contains(inOrder, h) {
			listedInOrder = append(listedInOrder, h)
		}
	}
	if !slices.Equal(listedInOrder, inOrder) {
		t.Fatalf("platform staff is listed in the order %v, want %v (by handle)", listedInOrder, inOrder)
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
	// A second sign-in identity, linked later, is listed after the first.
	// An identity that is not an individual sign-in (another kind, or one
	// through an organization's connection) is not one of the identities
	// the person signs in with.
	for _, ins := range []struct {
		kind, subject string
		connection    bool
	}{
		{"social", "oidc:second-" + c.name, false},
		{"oidc", "oidc:not-a-sign-in-" + c.name, false},
		{"social", "oidc:through-a-connection-" + c.name, true},
	} {
		var conn *uuid.UUID
		if ins.connection {
			id := uuid.New()
			conn = &id
		}
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO identities (id, user_id, provider_kind, sso_connection_id, subject) VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4)`,
			uid, ins.kind, conn, ins.subject); err != nil {
			t.Fatal(err)
		}
	}
	eraseAndReadOutcome(t, env, c)
	if len(heard) != 1 {
		t.Fatalf("heard account.erased %d times, want once", len(heard))
	}
	raw, _ := json.Marshal(heard[0].Identities)
	if heard[0].UserID.String() != uid || heard[0].Email != c.name+"@example.test" ||
		string(raw) != `["oidc:sub-`+c.name+`","oidc:second-`+c.name+`"]` {
		t.Fatalf("account.erased = %+v", heard[0])
	}
}

// TestADirectoryWithoutItsOwnErasureIsAskedOnce: a directory that does not
// erase on its own is asked once through the port for each directory
// account the person is linked to (every sign-in at the sign-in provider,
// oldest first, or the address alone), and the outcome is reported on the
// response and in the audit row; an error stops the asking, an account that
// cannot be told apart is raised, and a failure is reported as failed,
// never retried by the core.
func TestADirectoryWithoutItsOwnErasureIsAskedOnce(t *testing.T) {
	down := errors.New("the directory is down")
	// addSecond links a second sign-in of the account at the provider.
	addSecond := func(t *testing.T, env *testEnv, uid, name string) {
		t.Helper()
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO identities (id, user_id, provider_kind, subject) VALUES (gen_random_uuid(), $1::uuid, 'social', $2)`,
			uid, "oidc:second-"+name); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name            string
		fail            error
		lookup          api.DirectoryLookup
		header, outcome string
		// lookups is the audit row's directoryLookup: each link's lookup, in order.
		lookups string
		// asked names the links the directory was asked about, in order:
		// "first" and "second" are the sign-ins, "address" a link with no uid.
		asked []string
		// erased is how many accounts the directory deleted.
		erased int
		// accountID is the directory's recorded id the first link carries.
		accountID int64
		// errText is the error the audit row records, for a failed erasure.
		errText string
		// noAccount: the directory holds no account at the address.
		noAccount bool
		// noProvider: the deployment has no sign-in provider.
		noProvider bool
		// setup shapes the account's links and the directory's answers.
		setup func(t *testing.T, env *testEnv, dir *fakeDirectory, uid, name string)
	}{
		{name: "deleted", header: "deleted", outcome: "deleted", lookups: "address", asked: []string{"first"}, erased: 1},
		{name: "the directory fails", fail: down, header: "failed", outcome: "failed", lookups: "", asked: []string{"first"}, errText: down.Error()},
		{name: "an account it cannot tell apart", lookup: api.DirectoryLookupAddressShared, header: "unresolved", outcome: "unresolved",
			lookups: "address-shared", asked: []string{"first"}},
		{name: "no account at the directory", noAccount: true, header: "not-found", outcome: "not-found", lookups: "address", asked: []string{"first"}},
		{name: "a recorded directory account id is passed on", header: "deleted", outcome: "deleted", lookups: "address", asked: []string{"first"}, erased: 1,
			accountID: 77,
			setup: func(t *testing.T, env *testEnv, _ *fakeDirectory, uid, _ string) {
				if _, err := env.st.Pool().Exec(context.Background(), `UPDATE identities SET directory_account_id = 77 WHERE user_id = $1::uuid`, uid); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "two sign-ins: the first account is deleted, the second is not there", header: "deleted", outcome: "deleted",
			lookups: "address,address", asked: []string{"first", "second"}, erased: 1,
			setup: func(t *testing.T, env *testEnv, dir *fakeDirectory, uid, name string) {
				addSecond(t, env, uid, name)
				dir.byUID = map[string]fakeAnswer{"second-" + name: {lookup: api.DirectoryLookupByAddress}}
			}},
		{name: "two sign-ins: the first cannot be told apart, the second is deleted", header: "unresolved", outcome: "unresolved",
			lookups: "address-shared,address", asked: []string{"first", "second"}, erased: 1,
			setup: func(t *testing.T, env *testEnv, dir *fakeDirectory, uid, name string) {
				addSecond(t, env, uid, name)
				dir.byUID = map[string]fakeAnswer{"sub-" + name: {lookup: api.DirectoryLookupAddressShared}}
			}},
		{name: "two sign-ins: the first fails, the second is not asked", header: "failed", outcome: "failed",
			lookups: "", asked: []string{"first"}, errText: down.Error(),
			setup: func(t *testing.T, env *testEnv, dir *fakeDirectory, uid, name string) {
				addSecond(t, env, uid, name)
				dir.byUID = map[string]fakeAnswer{"sub-" + name: {fail: down}}
			}},
		{name: "two sign-ins: the first cannot be told apart, the second fails", header: "failed", outcome: "failed",
			lookups: "address-shared,", asked: []string{"first", "second"}, errText: down.Error(),
			setup: func(t *testing.T, env *testEnv, dir *fakeDirectory, uid, name string) {
				addSecond(t, env, uid, name)
				dir.byUID = map[string]fakeAnswer{"sub-" + name: {lookup: api.DirectoryLookupAddressShared}, "second-" + name: {fail: down}}
			}},
		{name: "no sign-in at the provider: the address alone", header: "deleted", outcome: "deleted", lookups: "address", asked: []string{"address"}, erased: 1,
			setup: func(t *testing.T, env *testEnv, _ *fakeDirectory, uid, _ string) {
				if _, err := env.st.Pool().Exec(context.Background(), `UPDATE identities SET subject = 'other:' || subject WHERE user_id = $1::uuid`, uid); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "no sign-in provider at all: the address alone", noProvider: true, header: "deleted", outcome: "deleted", lookups: "address", asked: []string{"address"}, erased: 1},
		{name: "sign-ins that are not the provider's individual ones are no links", header: "deleted", outcome: "deleted", lookups: "address", asked: []string{"first"}, erased: 1,
			setup: func(t *testing.T, env *testEnv, _ *fakeDirectory, uid, name string) {
				for _, ins := range []struct {
					kind, subject string
					connection    bool
				}{
					{"social", "authentik:other-" + name, false},
					{"oidc", "oidc:not-a-sign-in-" + name, false},
					{"social", "oidc:through-a-connection-" + name, true},
				} {
					var conn *uuid.UUID
					if ins.connection {
						id := uuid.New()
						conn = &id
					}
					if _, err := env.st.Pool().Exec(context.Background(),
						`INSERT INTO identities (id, user_id, provider_kind, sso_connection_id, subject) VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4)`,
						uid, ins.kind, conn, ins.subject); err != nil {
						t.Fatal(err)
					}
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := &fakeDirectory{fail: tc.fail, lookup: tc.lookup}
			mx, err := metrics.New(context.Background(), metrics.Config{ServiceName: "agentryd", Role: "all", Env: "dev"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mx.Shutdown(context.Background()) })
			setDir := func(s *api.Server) {
				s.SetDirectory(dir)
				s.SetMetrics(mx)
			}
			var env *testEnv
			var c caller
			if tc.noProvider {
				env = newTestEnvWith(t, setDir)
				c = env.login(env.register("asked-once"))
			} else {
				var idp *testidp.IdP
				env, idp = newOIDCTestEnv(t, nil, setDir)
				c = env.mintAccount(t, idp, "asked-once")
			}
			if !tc.noAccount {
				dir.mu.Lock()
				dir.email = c.name + "@example.test"
				dir.mu.Unlock()
			}
			uid := env.selfID(c)
			if tc.setup != nil {
				tc.setup(t, env, dir, uid, c.name)
			}
			if got := eraseAndReadOutcome(t, env, c); got != tc.header {
				t.Fatalf("X-Agentry-Directory-Erasure = %q, want %q", got, tc.header)
			}
			outcome, lookup := lastDirectoryErasure(t, env, uid)
			if outcome != tc.outcome || lookup != tc.lookups {
				t.Fatalf("the audit row says %q by %q, want %q by %q", outcome, lookup, tc.outcome, tc.lookups)
			}
			var recorded string
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT coalesce(detail->>'error', '') FROM audit_events WHERE action = 'user.directory_erase' AND target_id = $1::uuid`, uid).Scan(&recorded); err != nil {
				t.Fatal(err)
			}
			if recorded != tc.errText {
				t.Fatalf("the audit row records the error %q, want %q", recorded, tc.errText)
			}
			dir.mu.Lock()
			erased := len(dir.erased)
			var asked []string
			for _, l := range dir.links {
				if l.Email != c.name+"@example.test" {
					t.Errorf("a link carries the address %q", l.Email)
				}
				switch l.UID {
				case "":
					asked = append(asked, "address")
				case "sub-" + c.name:
					asked = append(asked, "first")
				case "second-" + c.name:
					asked = append(asked, "second")
				default:
					asked = append(asked, "other:"+l.UID)
				}
			}
			var firstID int64 = -1
			if len(dir.links) > 0 {
				firstID = dir.links[0].AccountID
			}
			dir.mu.Unlock()
			if strings.Join(asked, ",") != strings.Join(tc.asked, ",") {
				t.Fatalf("the directory was asked about %v, want %v", asked, tc.asked)
			}
			if firstID != tc.accountID {
				t.Fatalf("the first link carries directory account id %d, want %d", firstID, tc.accountID)
			}
			if erased != tc.erased {
				t.Fatalf("the directory erased %d accounts, want %d", erased, tc.erased)
			}
			// A directory half that did not happen is raised: the fail-open
			// count the operator's alarm reads.
			b, err := mx.Gather(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wantRaised := tc.outcome == "failed" || tc.outcome == "unresolved"
			if raised := strings.Contains(string(b), metrics.FailOpenDirectoryErasure); raised != wantRaised {
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
