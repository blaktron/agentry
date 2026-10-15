package api_test

// The promo code typed on the directory's sign-up form: the directory's
// agentry scope sends it as agentry_promo_code on every token of the account, and the registry passes
// it to its extensions as promoCode in user.registered only when that
// sign-in makes the account, only from the directory, and only inside the
// code grammar. The core attaches no meaning to it.

import (
	"context"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// promoEnv is a registry trusting the fake IdP as both the directory and
// Google, recording every user.registered it fires.
func promoEnv(t *testing.T, idp *fakeOIDC) (*testEnv, func() []api.Event) {
	t.Helper()
	var mu sync.Mutex
	var seen []api.Event
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.BaseURL = "http://127.0.0.1"
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.origin()}
		cfg.Social.Google = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.origin()}
	}, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.hostClient())
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "user.registered" {
				mu.Lock()
				seen = append(seen, ev)
				mu.Unlock()
			}
		})
	})
	return env, func() []api.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]api.Event(nil), seen...)
	}
}

func jitAuditPromo(t *testing.T, env *testEnv, userID string) (string, bool) {
	t.Helper()
	var code *string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'promoCode' FROM audit_events WHERE action = 'user.social_login' AND target_id = $1::uuid AND detail->>'jit' = 'true'`,
		userID).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if code == nil {
		return "", false
	}
	return *code, true
}

func TestPromoClaimOnlyFromDirectoryOnCreate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider string
		claim    any // nil: absent
		want     string
	}{
		{"the directory sends a code", "authentik", "launch-2026", "LAUNCH-2026"},
		{"the directory sends none", "authentik", nil, ""},
		{"an empty code", "authentik", "", ""},
		{"outside the grammar", "authentik", "a b", ""},
		{"too long", "authentik", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", ""},
		{"not a string", "authentik", 1234, ""},
		{"another provider asserting it", "google", "LAUNCH-2026", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeOIDC(t)
			idp.extra = map[string]any{}
			if tc.claim != nil {
				idp.extra["agentry_promo_code"] = tc.claim
			}
			env, events := promoEnv(t, idp)
			_, userID := directorySignIn(t, env, idp, tc.provider)
			evs := events()
			if len(evs) != 1 || evs[0].UserID.String() != userID {
				t.Fatalf("user.registered: %+v, want one for %s", evs, userID)
			}
			got, present := evs[0].Payload["promoCode"]
			if tc.want == "" {
				if present {
					t.Fatalf("promoCode %v forwarded, want none", got)
				}
			} else if got != tc.want {
				t.Fatalf("promoCode %v, want %q", got, tc.want)
			}
			audited, ok := jitAuditPromo(t, env, userID)
			if (tc.want == "") == ok || audited != tc.want {
				t.Fatalf("the JIT audit's promoCode: %q (present %v), want %q", audited, ok, tc.want)
			}

			// The claim rides every later token of the account: a returning
			// sign-in is not a new account and forwards nothing.
			if _, again := directorySignIn(t, env, idp, tc.provider); again != userID {
				t.Fatalf("second sign-in landed on %s, want %s", again, userID)
			}
			if n := len(events()); n != 1 {
				t.Fatalf("a returning sign-in fired user.registered again (%d events)", n)
			}
		})
	}

	// An account that already exists is linked by its verified address, not
	// made: no user.registered, so no code, whatever the token carries.
	t.Run("a linked account", func(t *testing.T) {
		idp := newFakeOIDC(t)
		env, events := promoEnv(t, idp)
		handle := env.register("promo-linked")
		env.verifyEmail(handle)
		var existing string
		if err := env.st.Pool().QueryRow(context.Background(), `SELECT id::text FROM handles WHERE handle = $1`, handle).Scan(&existing); err != nil {
			t.Fatal(err)
		}
		before := len(events()) // the native register's own event
		idp.email = handle + "@example.test"
		idp.extra = map[string]any{"agentry_promo_code": "LAUNCH-2026"}
		if _, userID := directorySignIn(t, env, idp, "authentik"); userID != existing {
			t.Fatalf("signed in as %s, want the existing %s", userID, existing)
		}
		if after := events(); len(after) != before {
			t.Fatalf("a linked account fired user.registered: %+v", after[before:])
		}
	})
}
