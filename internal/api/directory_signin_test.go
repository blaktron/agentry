package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeSignInDirectory answers the calls SignInFacts makes, in authentik
// 2026.8's shapes: two accounts share one address (authentik does not keep
// addresses unique), told apart by uid; the second has two
// source connections, the older one Google, and carries the blueprint's
// agentry_has_password attribute as given (omitted when attr is nil).
func fakeSignInDirectory(t *testing.T, attr any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/core/users/", func(w http.ResponseWriter, r *http.Request) {
		pat := map[string]any{"pk": 12, "email": "pat@example.test", "uid": "uid-pat", "type": "internal", "is_active": true, "attributes": map[string]any{}}
		if attr != nil {
			pat["attributes"] = map[string]any{"agentry_has_password": attr}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"pagination": map[string]any{"next": 0},
			"results": []map[string]any{
				{"pk": 11, "email": "Pat@Example.test", "uid": "uid-other", "type": "internal", "is_active": true, "attributes": map[string]any{"agentry_has_password": true}},
				pat,
			},
		})
	})
	mux.HandleFunc("GET /api/v3/core/users/{pk}/", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("pk") != "12" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		pat := map[string]any{"pk": 12, "email": "pat@example.test", "uid": "uid-pat", "type": "internal", "is_active": true, "attributes": map[string]any{}}
		if attr != nil {
			pat["attributes"] = map[string]any{"agentry_has_password": attr}
		}
		_ = json.NewEncoder(w).Encode(pat)
	})
	mux.HandleFunc("GET /api/v3/sources/user_connections/oauth/", func(w http.ResponseWriter, r *http.Request) {
		// The API ignores unknown filters and would answer every account's
		// connections; the client must ask by user pk.
		if r.URL.Query().Get("user") != "12" {
			http.Error(w, "filter by user pk", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"pagination": map[string]any{"next": 0},
			"results": []map[string]any{
				{"pk": 3, "user": 12, "created": "2026-09-20T10:00:00.000000Z", "source_obj": map[string]any{"slug": "github", "name": "GitHub"}},
				{"pk": 2, "user": 12, "created": "2026-09-01T10:00:00.000000Z", "source_obj": map[string]any{"slug": "google", "name": "Google"}},
				// Older, and somebody else's: a filter the API stopped honouring.
				{"pk": 9, "user": 99, "created": "2026-07-01T10:00:00.000000Z", "source_obj": map[string]any{"slug": "discord", "name": "Discord"}},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDirectorySignInFacts(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		attr any
		want *bool
	}{
		{"a recorded password", true, ptrTo(true)},
		{"a recorded absence", false, ptrTo(false)},
		{"nothing recorded yet", nil, nil},
		// Someone edited the attribute into another type: unknown, and the
		// lookup (which the staff mirror shares) still answers.
		{"a value that is not a boolean", "yes", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAuthentikEraser(fakeSignInDirectory(t, tc.attr).URL, "tok")
			for _, link := range []DirectoryLink{
				// Signed in before the directory sent its id: the uid at the address.
				{UID: "uid-pat", Email: "pat@example.test"},
				// The directory's id, the registry's address being another
				// (the bootstrap admin).
				{AccountID: 12, UID: "uid-pat", Email: "pat@authentik.social.local"},
			} {
				f, err := a.SignInFacts(ctx, link)
				if err != nil {
					t.Fatal(err)
				}
				if f.FirstSource == nil || f.FirstSource.Slug != "google" || f.FirstSource.Name != "Google" {
					t.Fatalf("%+v: first source = %+v, want google/Google (the linked account's oldest)", link, f.FirstSource)
				}
				if (f.HasPassword == nil) != (tc.want == nil) || (f.HasPassword != nil && *f.HasPassword != *tc.want) {
					t.Fatalf("%+v: hasPassword = %v, want %v", link, f.HasPassword, tc.want)
				}
			}
		})
	}
	t.Run("no account the link names: nothing is reported", func(t *testing.T) {
		a := newAuthentikEraser(fakeSignInDirectory(t, true).URL, "tok")
		for _, link := range []DirectoryLink{
			{Email: "pat@example.test"}, // no directory sign-in: an address alone never picks it
			{UID: "uid-nobody", Email: "pat@example.test"},
			{AccountID: 12, UID: "uid-other", Email: "pat@example.test"}, // the id holds another account now
			{AccountID: 99, UID: "uid-pat", Email: "pat@example.test"},   // the account is gone
		} {
			f, err := a.SignInFacts(ctx, link)
			if err != nil || f.FirstSource != nil || f.HasPassword != nil {
				t.Fatalf("%+v: facts = %+v (err %v), want none", link, f, err)
			}
		}
	})
}

func ptrTo[T any](v T) *T { return &v }
