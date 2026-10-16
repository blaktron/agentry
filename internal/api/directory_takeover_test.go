package api_test

// An extension's directory takes the directory's whole path: once one is
// set, the core reads none of the directory's own claims, mints no
// remembered browser for it, answers its checks 404 and keeps no staff
// mirror, and a directory that erases on its own answers the erasure's
// response.

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// TestAnExtensionsDirectoryTakesTheDirectoryPath: the same directory sign-in
// that the built-in path reads three claims from (its account id, the
// promo code, the remembered browser) leaves the core untouched when an
// extension's directory is set, and the extension hears every claim, and
// that the account is new, from the sign-in hook.
func TestAnExtensionsDirectoryTakesTheDirectoryPath(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.amr = []string{"pwd", "mfa"}
	idp.extra = map[string]any{
		"agentry_remember_device": true, "auth_time": fresh(),
		"agentry_directory_id": 42, "agentry_promo_code": "spring-26",
	}
	var mu sync.Mutex
	var registered []api.Event
	var heard []api.SignIn
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.BaseURL = "http://127.0.0.1"
		cfg.Auth.TrustedDeviceTTL = deviceTTL
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.origin()}
		cfg.Auth.IdPTrustCheckToken = directoryTrustToken
	}, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.hostClient())
		s.SetDirectory(&fakeDirectory{})
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "user.registered" {
				mu.Lock()
				registered = append(registered, ev)
				mu.Unlock()
			}
		})
		s.AddSignInHook(func(_ context.Context, in api.SignIn) {
			mu.Lock()
			heard = append(heard, in)
			mu.Unlock()
		})
	})

	res, userID := directorySignIn(t, env, idp, "authentik")
	requireNoCookie(t, res.Cookies(), trustedDeviceCookie)
	if n := trustedDeviceRows(t, env, userID); n != 0 {
		t.Fatalf("the core minted %d remembered browsers beside the extension's directory", n)
	}
	var dirID *int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT directory_account_id FROM identities WHERE user_id = $1::uuid`, userID).Scan(&dirID); err != nil {
		t.Fatal(err)
	}
	if dirID != nil {
		t.Fatalf("the core recorded the directory's account id %d beside the extension's directory", *dirID)
	}
	mu.Lock()
	if len(registered) != 1 {
		mu.Unlock()
		t.Fatalf("heard user.registered %d times, want once", len(registered))
	}
	if code, ok := registered[0].Payload["promoCode"]; ok {
		mu.Unlock()
		t.Fatalf("user.registered carries promoCode %v beside the extension's directory", code)
	}
	if len(heard) != 1 || !heard[0].NewAccount || heard[0].Claims["agentry_promo_code"] != "spring-26" ||
		heard[0].Claims["agentry_remember_device"] != true {
		mu.Unlock()
		t.Fatalf("the sign-in hook heard %+v", heard)
	}
	mu.Unlock()

	// The same person again: not a new account.
	directorySignIn(t, env, idp, "authentik")
	mu.Lock()
	if len(heard) != 2 || heard[1].NewAccount || heard[1].UserID.String() != userID {
		mu.Unlock()
		t.Fatalf("the second sign-in was heard as %+v", heard[1:])
	}
	mu.Unlock()

	// The built-in checks are absent, the right secret or not.
	if status, _ := checkTrust(t, env, directoryTrustToken, map[string]string{"token": "agyd_x", "sub": idp.sub}); status != http.StatusNotFound {
		t.Fatalf("the built-in trust check answered %d beside the extension's directory, want 404", status)
	}
	req, err := http.NewRequest(http.MethodPost, env.srv.URL+"/internal/directory/email-verification", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+directoryTrustToken)
	ver, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = ver.Body.Close()
	if ver.StatusCode != http.StatusNotFound {
		t.Fatalf("the built-in verification check answered %d beside the extension's directory, want 404", ver.StatusCode)
	}
}

// TestTheBuiltInDirectoryStillReadsItsClaims: without an extension's
// directory, the same sign-in records the account id, carries the promo
// code and remembers the browser as before.
func TestTheBuiltInDirectoryStillReadsItsClaims(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.amr = []string{"pwd", "mfa"}
	idp.extra = map[string]any{
		"agentry_remember_device": true, "auth_time": fresh(),
		"agentry_directory_id": 42, "agentry_promo_code": "spring-26",
	}
	var registered []api.Event
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.BaseURL = "http://127.0.0.1"
		cfg.Auth.TrustedDeviceTTL = deviceTTL
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.origin()}
		cfg.Auth.IdPTrustCheckToken = directoryTrustToken
	}, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.hostClient())
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "user.registered" {
				registered = append(registered, ev)
			}
		})
	})
	_, userID := directorySignIn(t, env, idp, "authentik")
	if n := trustedDeviceRows(t, env, userID); n != 1 {
		t.Fatalf("%d remembered browsers, want 1", n)
	}
	var dirID *int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT directory_account_id FROM identities WHERE user_id = $1::uuid`, userID).Scan(&dirID); err != nil {
		t.Fatal(err)
	}
	if dirID == nil || *dirID != 42 {
		t.Fatalf("directory_account_id = %v, want 42", dirID)
	}
	if len(registered) != 1 || registered[0].Payload["promoCode"] != "SPRING-26" {
		t.Fatalf("user.registered = %+v, want promoCode SPRING-26", registered)
	}
}

// TestAnExtensionsDirectoryKeepsNoCoreStaffMirror: with a mirror group
// configured, an extension's directory leaves the core's mirror off; the
// extension mirrors on staff.changed itself.
func TestAnExtensionsDirectoryKeepsNoCoreStaffMirror(t *testing.T) {
	m := newMirrorFixture(t)
	dir := &fakeDirectory{}
	m.srv.SetDirectory(dir)
	alice := m.person("alice")
	m.join(alice, "alice-"+m.env.sfx+"@"+m.domain)
	m.link(alice, m.dir.account("alice-"+m.env.sfx+"@"+m.domain))
	out, err := m.srv.ReconcileStaffMirror(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out != (api.StaffMirrorOutcome{}) || len(m.dir.members(m.group)) != 0 {
		t.Fatalf("the core's mirror ran beside the extension's directory: %+v, group %v", out, m.dir.members(m.group))
	}
}

// erasingDirectory is an extension's directory that carries out the
// directory half of an erasure itself.
type erasingDirectory struct {
	fakeDirectory
	outcome string
	asked   []api.ErasedAccount
}

func (d *erasingDirectory) EraseErased(_ *http.Request, a api.ErasedAccount) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked = append(d.asked, a)
	return d.outcome
}

var _ api.DirectoryErasure = (*erasingDirectory)(nil)

// TestADirectoryThatErasesItselfAnswersTheErasure: the core hands the
// directory half to the directory once, with the account's identities and
// address, makes no attempt or retry of its own, and reports the
// directory's outcome; an outcome the response does not define is left off.
func TestADirectoryThatErasesItselfAnswersTheErasure(t *testing.T) {
	for _, tc := range []struct{ outcome, header string }{
		{api.DirectoryErasurePending, "pending"},
		{api.DirectoryErasureDeleted, "deleted"},
		{"maybe", ""},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			dir := &erasingDirectory{outcome: tc.outcome}
			env, idp := newOIDCTestEnv(t, nil, func(s *api.Server) { s.SetDirectory(dir) })
			c := env.mintAccount(t, idp, "self-erase")
			uid := env.selfID(c)
			dir.mu.Lock()
			dir.email = c.name + "@example.test"
			dir.mu.Unlock()
			if got := eraseAndReadOutcome(t, env, c); got != tc.header {
				t.Fatalf("X-Agentry-Directory-Erasure = %q, want %q", got, tc.header)
			}
			dir.mu.Lock()
			defer dir.mu.Unlock()
			if len(dir.asked) != 1 || dir.asked[0].UserID != uuid.MustParse(uid) || dir.asked[0].Email != c.name+"@example.test" ||
				len(dir.asked[0].Identities) != 1 || dir.asked[0].Identities[0] != "oidc:sub-"+c.name {
				t.Fatalf("EraseErased was told %+v", dir.asked)
			}
			if len(dir.erased) != 0 {
				t.Fatalf("the core also erased through the port: %+v", dir.erased)
			}
			var audits, jobs int
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT count(*) FROM audit_events WHERE action = 'user.directory_erase' AND target_id = $1::uuid`, uid).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT count(*) FROM river_job WHERE kind = 'gdpr.directory_erase' AND args->>'userId' = $1`, uid).Scan(&jobs); err != nil {
				t.Fatal(err)
			}
			if audits != 0 || jobs != 0 {
				t.Fatalf("the core audited %d attempts and queued %d retries of its own", audits, jobs)
			}
		})
	}
}
