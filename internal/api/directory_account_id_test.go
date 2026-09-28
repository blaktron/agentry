package api_test

// The directory's own id for the account (agentry#727): the directory's
// agentry scope sends it as agentry_directory_id, and the registry records
// it on the identity the token signed in, from the directory alone.

import (
	"context"
	"testing"
)

func directoryAccountIDOf(t *testing.T, env *testEnv, userID string) *int64 {
	t.Helper()
	var id *int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT directory_account_id FROM identities WHERE user_id = $1::uuid`, userID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDirectoryAccountIDIsRecordedAtSignIn(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider string
		claim    any // nil: absent
		want     int64
	}{
		{"the directory sends it", "authentik", 4127, 4127},
		{"the directory sends none", "authentik", nil, 0},
		{"not a whole number", "authentik", 41.5, 0},
		{"not a number", "authentik", "4127", 0},
		{"not positive", "authentik", -3, 0},
		{"another provider asserting it", "google", 4127, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeOIDC(t)
			idp.extra = map[string]any{}
			if tc.claim != nil {
				idp.extra["agentry_directory_id"] = tc.claim
			}
			env := newRememberEnv(t, idp, false)
			_, userID := directorySignIn(t, env, idp, tc.provider)
			got := directoryAccountIDOf(t, env, userID)
			if tc.want == 0 {
				if got != nil {
					t.Fatalf("recorded %d, want nothing", *got)
				}
				return
			}
			if got == nil || *got != tc.want {
				t.Fatalf("recorded %v, want %d", got, tc.want)
			}
		})
	}

	t.Run("a later sign-in moves it", func(t *testing.T) {
		idp := newFakeOIDC(t)
		idp.extra = map[string]any{"agentry_directory_id": 12}
		env := newRememberEnv(t, idp, false)
		_, userID := directorySignIn(t, env, idp, "authentik")
		idp.extra["agentry_directory_id"] = 13
		if _, again := directorySignIn(t, env, idp, "authentik"); again != userID {
			t.Fatalf("second sign-in landed on %s, want %s", again, userID)
		}
		if got := directoryAccountIDOf(t, env, userID); got == nil || *got != 13 {
			t.Fatalf("recorded %v, want 13", got)
		}
		// A sign-in whose token carries no id leaves the last one standing.
		delete(idp.extra, "agentry_directory_id")
		directorySignIn(t, env, idp, "authentik")
		if got := directoryAccountIDOf(t, env, userID); got == nil || *got != 13 {
			t.Fatalf("recorded %v after a token with none, want 13 kept", got)
		}
	})
}
