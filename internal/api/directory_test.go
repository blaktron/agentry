package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeDirectoryUser is one account in fakeAuthentik.
type fakeDirectoryUser struct {
	PK          int    `json:"pk"`
	UID         string `json:"uid"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Type        string `json:"type"`
	IsActive    bool   `json:"is_active"`
	IsSuperuser bool   `json:"is_superuser"`
	// Attributes is the account's attributes object; a PATCH replaces it
	// whole, as authentik's does.
	Attributes map[string]any `json:"attributes,omitempty"`
}

// fakeDirectory is authentik 2026.8's users and authenticators admin API as
// the directory client uses it, with its filter semantics: email= is
// exact and case-sensitive, search= is case-blind and matches parts of
// the username, the name and the address.
type fakeDirectory struct {
	mu       sync.Mutex
	users    []fakeDirectoryUser
	deleted  []string // "user/<pk>" or "<kind>/<id>"
	patched  []string // "user/<pk>"
	byEmail  int      // lookups that used email=
	byID     int      // reads of one account by its id
	searched int      // lookups that used search=
}

func (d *fakeDirectory) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/core/users/", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		q := r.URL.Query()
		results := []fakeDirectoryUser{}
		for _, u := range d.users {
			switch {
			case q.Has("email"):
				if u.Email == q.Get("email") {
					results = append(results, u)
				}
			case q.Has("search"):
				s := strings.ToLower(q.Get("search"))
				if strings.Contains(strings.ToLower(u.Email), s) || strings.Contains(strings.ToLower(u.Username), s) {
					results = append(results, u)
				}
			default:
				results = append(results, u)
			}
		}
		if q.Has("email") {
			d.byEmail++
		}
		if q.Has("search") {
			d.searched++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"pagination": map[string]any{"next": 0}, "results": results})
	})
	mux.HandleFunc("GET /api/v3/core/users/{pk}/", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.byID++
		for _, u := range d.users {
			if strconv.Itoa(u.PK) == r.PathValue("pk") {
				_ = json.NewEncoder(w).Encode(u)
				return
			}
		}
		http.Error(w, `{"detail":"No User matches the given query."}`, http.StatusNotFound)
	})
	mux.HandleFunc("PATCH /api/v3/core/users/{pk}/", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		var body struct {
			Attributes map[string]any `json:"attributes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		for i, u := range d.users {
			if strconv.Itoa(u.PK) == r.PathValue("pk") {
				d.users[i].Attributes = body.Attributes
				d.patched = append(d.patched, "user/"+r.PathValue("pk"))
				_ = json.NewEncoder(w).Encode(d.users[i])
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
	mux.HandleFunc("DELETE /api/v3/core/users/{pk}/", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		for i, u := range d.users {
			if strconv.Itoa(u.PK) == r.PathValue("pk") {
				d.users = append(d.users[:i], d.users[i+1:]...)
				d.deleted = append(d.deleted, "user/"+r.PathValue("pk"))
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
	mux.HandleFunc("GET /api/v3/authenticators/admin/all/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("user") {
		case "7":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"pk": 31, "name": "phone", "type": "authentik_stages_authenticator_totp.TOTPDevice", "verbose_name": "TOTP Device", "created": "2026-09-01T10:00:00.000000Z"},
				{"pk": "44f2", "name": "yubikey", "type": "authentik_stages_authenticator_webauthn.WebAuthnDevice", "verbose_name": "WebAuthn Device", "created": "2026-09-02T10:00:00.000000Z"},
			})
		default:
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		}
	})
	mux.HandleFunc("DELETE /api/v3/authenticators/admin/{kind}/{id}/", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.deleted = append(d.deleted, r.PathValue("kind")+"/"+r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// fakeAuthentik is a directory holding:
//
//	7   alice, held with capitals, with a TOTP and a WebAuthn device
//	8   bob
//	11, 13  two accounts at one address
//	12  pat, whose registry account has another address
//	20  an inactive account
//	1   an operator's superuser account
//	77  a service account at alice's address
func fakeAuthentik(t *testing.T) (*authentikEraser, *fakeDirectory) {
	t.Helper()
	d := &fakeDirectory{users: []fakeDirectoryUser{
		{PK: 7, UID: "uid-alice", Username: "alice", Email: "Alice@Example.test", Type: "internal", IsActive: true},
		{PK: 8, UID: "uid-bob", Username: "bob", Email: "bob@example.test", Type: "internal", IsActive: true},
		{PK: 11, UID: "uid-s1", Username: "s1", Email: "shared@example.test", Type: "internal", IsActive: true},
		{PK: 13, UID: "uid-s2", Username: "s2", Email: "shared@example.test", Type: "internal", IsActive: true},
		{PK: 12, UID: "uid-pat", Username: "pat", Email: "pat@dev.local", Type: "internal", IsActive: true},
		{PK: 20, UID: "uid-gone", Username: "gone", Email: "gone@example.test", Type: "internal", IsActive: false},
		{PK: 1, UID: "uid-root", Username: "akadmin", Email: "root@example.test", Type: "internal", IsActive: true, IsSuperuser: true},
		{PK: 77, UID: "uid-svc", Username: "svc", Email: "alice@example.test", Type: "internal_service_account", IsActive: true},
	}}
	srv := httptest.NewServer(d.handler())
	t.Cleanup(srv.Close)
	return newAuthentikEraser(srv.URL, "tok"), d
}

// TestDirectoryFindAccount is the rule every directory lookup shares: the
// directory's id when the registry has
// learnt it, confirmed by the uid; else the linked uid at the address; else
// the address alone, only when exactly one account holds it.
func TestDirectoryFindAccount(t *testing.T) {
	a, d := fakeAuthentik(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		link DirectoryLink
		pk   int // 0: none
		how  DirectoryLookup
	}{
		{"by id, the registry's address being another", DirectoryLink{AccountID: 12, UID: "uid-pat", Email: "pat@authentik.social.local"}, 12, DirectoryLookupByID},
		{"by id, but another account's uid there now", DirectoryLink{AccountID: 12, UID: "uid-bob", Email: "bob@example.test"}, 0, DirectoryLookupIDMismatch},
		{"by id, the account gone", DirectoryLink{AccountID: 999, UID: "uid-pat"}, 0, DirectoryLookupByID},
		{"by id, a service account", DirectoryLink{AccountID: 77, UID: "uid-svc"}, 0, DirectoryLookupIDMismatch},
		{"by id, an inactive account", DirectoryLink{AccountID: 20, UID: "uid-gone"}, 20, DirectoryLookupByID},
		{"by uid, held with capitals", DirectoryLink{UID: "uid-alice", Email: "alice@example.test"}, 7, DirectoryLookupByUID},
		{"by uid, one of two at the address", DirectoryLink{UID: "uid-s2", Email: "shared@example.test"}, 13, DirectoryLookupByUID},
		{"by uid, not at the address", DirectoryLink{UID: "uid-pat", Email: "pat@authentik.social.local"}, 0, DirectoryLookupByUID},
		{"by address, the only holder (a service account never counts)", DirectoryLink{Email: "alice@example.test"}, 7, DirectoryLookupByAddress},
		{"by address, the registry's copy in capitals", DirectoryLink{Email: "BOB@EXAMPLE.TEST"}, 8, DirectoryLookupByAddress},
		{"by address, an inactive account", DirectoryLink{Email: "gone@example.test"}, 20, DirectoryLookupByAddress},
		{"by address, two holders", DirectoryLink{Email: "shared@example.test"}, 0, DirectoryLookupAddressShared},
		{"by address, a prefix of an address is not it", DirectoryLink{Email: "shared@example"}, 0, DirectoryLookupByAddress},
		{"by address, nobody", DirectoryLink{Email: "nobody@example.test"}, 0, DirectoryLookupByAddress},
		{"nothing to go on", DirectoryLink{}, 0, DirectoryLookupByAddress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, how, err := a.findAccount(ctx, tc.link)
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			if u != nil {
				got = u.PK
			}
			if got != tc.pk || how != tc.how {
				t.Fatalf("found %d by %s, want %d by %s", got, how, tc.pk, tc.how)
			}
		})
	}
	if d.byEmail != 0 {
		t.Fatalf("%d lookups used email=, which is exact and case-sensitive on authentik 2026.8", d.byEmail)
	}

	// An id in hand never falls back to the address.
	d.byID, d.searched = 0, 0
	if _, _, err := a.findAccount(ctx, DirectoryLink{AccountID: 999, UID: "uid-alice", Email: "alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	if d.byID != 1 || d.searched != 0 {
		t.Fatalf("reads by id %d, searches %d: want the id alone", d.byID, d.searched)
	}
}

// TestDirectoryDevicesCarryIDs: the device list keeps the directory's ids
// (numeric or string) so the settings page can name one to remove.
func TestDirectoryDevicesCarryIDs(t *testing.T) {
	c, _ := fakeAuthentik(t)
	devs, err := c.Devices(context.Background(), DirectoryLink{AccountID: 7, UID: "uid-alice", Email: "alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 || devs[0].ID != "31" || devs[0].Kind != "totp" || devs[1].ID != "44f2" || devs[1].Kind != "webauthn" {
		t.Fatalf("devices = %+v", devs)
	}
	if devs[0].CreatedAt == nil {
		t.Error("created timestamp not parsed")
	}
	none, err := c.Devices(context.Background(), DirectoryLink{Email: "shared@example.test"})
	if err != nil || len(none) != 0 {
		t.Fatalf("an address two accounts hold: %+v %v, want no devices", none, err)
	}
}

// TestDirectoryDeleteDeviceOwnOnly: a device is removed only
// when the account's own list reports it — somebody else's id, an unknown
// kind, or a foreign account all answer "not deleted" without touching the
// directory.
func TestDirectoryDeleteDeviceOwnOnly(t *testing.T) {
	c, d := fakeAuthentik(t)
	ctx := context.Background()
	alice := DirectoryLink{AccountID: 7, UID: "uid-alice", Email: "alice@example.test"}
	ok, err := c.DeleteDevice(ctx, alice, "totp", "31")
	if err != nil || !ok {
		t.Fatalf("own device: ok=%v err=%v", ok, err)
	}
	if len(d.deleted) != 1 || d.deleted[0] != "totp/31" {
		t.Fatalf("deleted = %v", d.deleted)
	}
	for _, tc := range []struct {
		link     DirectoryLink
		kind, id string
	}{
		{DirectoryLink{AccountID: 8, UID: "uid-bob", Email: "bob@example.test"}, "totp", "31"},   // alice's device, bob asking
		{DirectoryLink{AccountID: 7, UID: "uid-bob", Email: "alice@example.test"}, "totp", "31"}, // alice's id, bob's uid
		{alice, "webauthn", "31"}, // wrong kind for that id
		{alice, "sms", "9"},       // no such device
		{alice, "bogus", "31"},    // unknown kind
		{DirectoryLink{Email: "nobody@example.test"}, "totp", "31"}, // no directory account
	} {
		ok, err := c.DeleteDevice(ctx, tc.link, tc.kind, tc.id)
		if err != nil || ok {
			t.Errorf("%+v: ok=%v err=%v", tc, ok, err)
		}
	}
	if len(d.deleted) != 1 {
		t.Fatalf("directory touched for a refused request: %v", d.deleted)
	}
}

// TestDirectoryEraseAccount: erasure deletes the one account the link
// names and never a superuser, whichever rule
// found it.
func TestDirectoryEraseAccount(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		link DirectoryLink
		want string // "" when nothing is deleted
	}{
		{"by id, whatever the registry's address", DirectoryLink{AccountID: 12, UID: "uid-pat", Email: "pat@authentik.social.local"}, "user/12"},
		{"by uid, one of two at the address", DirectoryLink{UID: "uid-s1", Email: "shared@example.test"}, "user/11"},
		{"by address, the only holder, held with capitals", DirectoryLink{Email: "alice@example.test"}, "user/7"},
		{"by address, an inactive account", DirectoryLink{Email: "gone@example.test"}, "user/20"},
		{"by address, two holders", DirectoryLink{Email: "shared@example.test"}, ""},
		{"a superuser, by id", DirectoryLink{AccountID: 1, UID: "uid-root", Email: "root@example.test"}, ""},
		{"a superuser, by address", DirectoryLink{Email: "root@example.test"}, ""},
		{"by id, the account gone", DirectoryLink{AccountID: 999, UID: "uid-x", Email: "bob@example.test"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, d := fakeAuthentik(t)
			deleted, _, err := a.EraseAccount(ctx, tc.link)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if deleted || len(d.deleted) != 0 {
					t.Fatalf("deleted=%v %v, want nothing", deleted, d.deleted)
				}
				return
			}
			if !deleted || len(d.deleted) != 1 || d.deleted[0] != tc.want {
				t.Fatalf("deleted=%v %v, want %s only", deleted, d.deleted, tc.want)
			}
		})
	}
}
