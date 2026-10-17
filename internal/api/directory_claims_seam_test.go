package api_test

// The core reads none of a directory's own claims (its account id, the
// sign-up promo code, the remember-this-browser request) and serves none of
// its checks: an extension that is the directory hears every claim through
// the sign-in hook and does that work itself. A directory that erases on its
// own answers the erasure's response.

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/testidp"
)

// TestTheCoreReadsNoDirectoryClaims: a sign-in whose token carries a
// directory's claims leaves the core untouched (no remembered browser, no
// recorded account id, no promo code on user.registered), and the sign-in
// hook hears every claim and whether the sign-in made the account.
func TestTheCoreReadsNoDirectoryClaims(t *testing.T) {
	for _, id := range []string{config.OIDCProviderID, config.AuthentikProviderID} {
		t.Run(id, func(t *testing.T) {
			var mu sync.Mutex
			var registered []api.Event
			var heard []api.SignIn
			env, idp := newOIDCTestEnv(t, func(cfg *config.Config) {
				cfg.Auth.TrustedDeviceTTL = deviceTTL
				cfg.Auth.OIDC.ID = id
			}, func(s *api.Server) {
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
			h := "claims-" + id + env.sfx
			person := testidp.Person{
				Subject: "sub-" + h, Email: h + "@example.test", EmailVerified: true, Username: h,
				AMR: []string{"pwd", "mfa"}, AuthTime: time.Now(),
				Claims: map[string]any{"agentry_remember_device": true, "agentry_directory_id": 42, "agentry_promo_code": "spring-26"},
			}
			in := env.signInOIDC(t, idp, id, person)
			if in.status != http.StatusOK {
				t.Fatalf("sign-in: %d %s", in.status, in.body)
			}
			requireNoCookie(t, in.cookies, trustedDeviceCookie)
			var devices int
			var dirID *int64
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT count(*) FROM trusted_devices WHERE user_id = $1::uuid`, in.userID).Scan(&devices); err != nil {
				t.Fatal(err)
			}
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT directory_account_id FROM identities WHERE user_id = $1::uuid`, in.userID).Scan(&dirID); err != nil {
				t.Fatal(err)
			}
			if devices != 0 || dirID != nil {
				t.Fatalf("the core minted %d remembered browsers and recorded account id %v from the claims", devices, dirID)
			}
			mu.Lock()
			if len(registered) != 1 {
				mu.Unlock()
				t.Fatalf("heard user.registered %d times, want once", len(registered))
			}
			if code, ok := registered[0].Payload["promoCode"]; ok {
				mu.Unlock()
				t.Fatalf("user.registered carries promoCode %v", code)
			}
			if len(heard) != 1 || !heard[0].NewAccount || heard[0].Claims["agentry_promo_code"] != "spring-26" ||
				heard[0].Claims["agentry_remember_device"] != true {
				mu.Unlock()
				t.Fatalf("the sign-in hook heard %+v", heard)
			}
			mu.Unlock()

			// The same person again: not a new account.
			person.AuthTime = time.Now()
			env.signInOIDC(t, idp, id, person)
			mu.Lock()
			if len(heard) != 2 || heard[1].NewAccount || heard[1].UserID.String() != in.userID {
				mu.Unlock()
				t.Fatalf("the second sign-in was heard as %+v", heard[1:])
			}
			mu.Unlock()

			// The server serves no directory check of its own.
			for _, path := range []string{"/internal/directory/trusted-device", "/internal/directory/email-verification"} {
				res, err := http.Post(env.srv.URL+path, "application/json", nil)
				if err != nil {
					t.Fatal(err)
				}
				_ = res.Body.Close()
				if res.StatusCode != http.StatusNotFound {
					t.Fatalf("%s answered %d, want 404", path, res.StatusCode)
				}
			}
		})
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
	d.asked = append(d.asked, a)
	d.mu.Unlock()
	if d.outcome == "panic" {
		panic("the directory fell over")
	}
	return d.outcome
}

var _ api.DirectoryErasure = (*erasingDirectory)(nil)

// TestADirectoryThatErasesItselfAnswersTheErasure: the core hands the
// directory half to the directory once, with the account's identities and
// address, makes no attempt or retry of its own, and reports the
// directory's outcome; an outcome the response does not define, or a
// directory that panics, is reported as failed.
func TestADirectoryThatErasesItselfAnswersTheErasure(t *testing.T) {
	for _, tc := range []struct{ outcome, header string }{
		{api.DirectoryErasurePending, "pending"},
		{api.DirectoryErasureDeleted, "deleted"},
		{"maybe", "failed"},
		{"", "failed"},
		{"panic", "failed"},
	} {
		t.Run("outcome "+tc.outcome, func(t *testing.T) {
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
