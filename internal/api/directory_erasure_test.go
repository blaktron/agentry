package api_test

// Erasure deletes the sign-in account in the directory service too:
// exactly the person's account,
// never a superuser or a service account, and the outcome is audited.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// erasureDirectory is authentik 2026.8's users API as erasure uses it:
// search= is case-blind and matches parts of the address,
// one account reads by its id, and a delete removes it. at is the erased
// person's address, which the directory's accounts are built around.
func erasureDirectory(t *testing.T, accounts func(at string) []map[string]any, at *string) (url string, deleted, searches *[]string) {
	t.Helper()
	deleted, searches = &[]string{}, &[]string{}
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer idp-admin-token" {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/users/":
			if r.URL.Query().Has("email") {
				http.Error(w, "email= is exact and case-sensitive on 2026.8", http.StatusBadRequest)
				return
			}
			q := strings.ToLower(r.URL.Query().Get("search"))
			*searches = append(*searches, q)
			results := []map[string]any{}
			for _, u := range accounts(*at) {
				if strings.Contains(strings.ToLower(u["email"].(string)), q) {
					results = append(results, u)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"pagination": map[string]any{"next": 0}, "results": results})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/core/users/"):
			for _, u := range accounts(*at) {
				if r.URL.Path == fmt.Sprintf("/api/v3/core/users/%v/", u["pk"]) {
					_ = json.NewEncoder(w).Encode(u)
					return
				}
			}
			http.Error(w, "not found", http.StatusNotFound)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v3/core/users/"):
			*deleted = append(*deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(idp.Close)
	return idp.URL, deleted, searches
}

func lastDirectoryErasure(t *testing.T, env *testEnv, userID string) (outcome, lookup string) {
	t.Helper()
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'directoryErasure', coalesce(detail->>'directoryLookup', '') FROM audit_events
		 WHERE action = 'user.directory_erase' AND target_id = $1::uuid ORDER BY occurred_at DESC LIMIT 1`, userID).Scan(&outcome, &lookup); err != nil {
		t.Fatal(err)
	}
	return outcome, lookup
}

// TestErasureDeletesDirectoryAccount: erasure deletes exactly the person's
// directory accounts: the one each directory
// sign-in's recorded id names, whatever address it holds; else, for an
// account that never signed in through the directory, the one account at
// its address, case-blind. It never deletes a superuser or a service
// account, and an account it cannot tell apart is left in place and
// reported unresolved, not not-found.
func TestErasureDeletesDirectoryAccount(t *testing.T) {
	// uid is the directory's uid for pk when a directory sign-in linked it.
	uid := func(pk int, at string) string { return fmt.Sprintf("uid-%d-%s", pk, at) }
	for _, tc := range []struct {
		name     string
		accounts func(at string) []map[string]any
		// links are the directory accounts (by pk) directory sign-ins
		// recorded, oldest first; none means the person never signed in
		// through the directory.
		links       []int
		wantDeleted []string
		wantOutcome string
		wantLookup  string
		wantSearch  bool
	}{
		{
			name: "the one account at the address, held with capitals",
			accounts: func(at string) []map[string]any {
				return []map[string]any{
					{"pk": 41, "uid": "uid-41", "email": strings.ToUpper(at), "type": "internal", "is_superuser": false},
					{"pk": 77, "uid": "uid-77", "email": at, "type": "internal_service_account", "is_superuser": false},
					{"pk": 99, "uid": "uid-99", "email": "x" + at, "type": "internal", "is_superuser": false},
				}
			},
			wantDeleted: []string{"/api/v3/core/users/41/"}, wantOutcome: "deleted", wantLookup: "address", wantSearch: true,
		},
		{
			name: "two accounts at the address: neither is deleted",
			accounts: func(at string) []map[string]any {
				return []map[string]any{
					{"pk": 41, "uid": "uid-41", "email": at, "type": "internal", "is_superuser": false},
					{"pk": 1, "uid": "uid-1", "email": at, "type": "internal", "is_superuser": true},
				}
			},
			wantOutcome: "unresolved", wantLookup: "address-shared", wantSearch: true,
		},
		{
			name: "the only account at the address is a superuser",
			accounts: func(at string) []map[string]any {
				return []map[string]any{{"pk": 1, "uid": "uid-1", "email": at, "type": "internal", "is_superuser": true}}
			},
			wantOutcome: "unresolved", wantLookup: "superuser", wantSearch: true,
		},
		{
			name: "no account at the address",
			accounts: func(at string) []map[string]any {
				return []map[string]any{{"pk": 99, "uid": "uid-99", "email": "x" + at, "type": "internal", "is_superuser": false}}
			},
			wantOutcome: "not-found", wantLookup: "address", wantSearch: true,
		},
		{
			name: "the linked account by its id, at another address, beside another at the erased one",
			accounts: func(at string) []map[string]any {
				return []map[string]any{
					{"pk": 41, "uid": uid(41, at), "email": "elsewhere@dev.local", "type": "internal", "is_superuser": false},
					{"pk": 42, "uid": "uid-42", "email": at, "type": "internal", "is_superuser": false},
				}
			},
			links: []int{41}, wantDeleted: []string{"/api/v3/core/users/41/"}, wantOutcome: "deleted", wantLookup: "id",
		},
		{
			name: "every linked account: the oldest gone, the newer one deleted",
			accounts: func(at string) []map[string]any {
				return []map[string]any{
					{"pk": 43, "uid": uid(43, at), "email": at, "type": "internal", "is_superuser": false},
				}
			},
			links: []int{41, 43}, wantDeleted: []string{"/api/v3/core/users/43/"}, wantOutcome: "deleted", wantLookup: "id,id",
		},
		{
			name: "the recorded id now names an account with another uid",
			accounts: func(at string) []map[string]any {
				return []map[string]any{
					{"pk": 41, "uid": "uid-someone-else", "email": at, "type": "internal", "is_superuser": false},
				}
			},
			links: []int{41}, wantOutcome: "unresolved", wantLookup: "id-mismatch",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var at string
			idpURL, deleted, searches := erasureDirectory(t, tc.accounts, &at)
			env := newTestEnvCfg(t, func(c *config.Config) {
				c.Auth.IdPAdminURL = idpURL
				c.Auth.IdPAdminToken = "idp-admin-token"
			})
			user := env.register("dir-erase")
			at = user + "@example.test"
			env.verifyEmail(user)
			var userID string
			if err := env.st.Pool().QueryRow(context.Background(), `SELECT id::text FROM users WHERE email = $1`, at).Scan(&userID); err != nil {
				t.Fatal(err)
			}
			for i, pk := range tc.links {
				if _, err := env.st.Pool().Exec(context.Background(),
					`INSERT INTO identities (id, user_id, provider_kind, subject, directory_account_id, created_at)
					 VALUES (gen_random_uuid(), $1::uuid, 'social', 'authentik:' || $2, $3, now() + make_interval(secs => $4))`,
					userID, uid(pk, at), pk, i); err != nil {
					t.Fatal(err)
				}
			}
			sess := env.login(user)
			res := env.do(sess, http.MethodPost, "/api/v1/user/delete", nil)
			_ = res.Body.Close()
			if res.StatusCode != http.StatusNoContent {
				t.Fatalf("erase: %d, want 204", res.StatusCode)
			}
			if h := res.Header.Get("X-Agentry-Directory-Erasure"); h != tc.wantOutcome {
				t.Fatalf("X-Agentry-Directory-Erasure = %q, want %s", h, tc.wantOutcome)
			}

			if got := len(*searches) > 0; got != tc.wantSearch {
				t.Fatalf("address searches = %v, want some: %v", *searches, tc.wantSearch)
			}
			if strings.Join(*deleted, " ") != strings.Join(tc.wantDeleted, " ") {
				t.Fatalf("directory deletes = %v, want %v", *deleted, tc.wantDeleted)
			}
			if got, lookup := lastDirectoryErasure(t, env, userID); got != tc.wantOutcome || lookup != tc.wantLookup {
				t.Fatalf("audit directoryErasure = %q by %q, want %s by %s", got, lookup, tc.wantOutcome, tc.wantLookup)
			}
		})
	}
}

func TestErasureWithoutDirectoryIsAudited(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("dir-none")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)
	var outcome string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'directoryErasure' FROM audit_events WHERE action = 'user.directory_erase' ORDER BY occurred_at DESC LIMIT 1`).Scan(&outcome); err != nil || outcome != "not-configured" {
		t.Fatalf("audit directoryErasure = %q (%v), want not-configured", outcome, err)
	}
}
