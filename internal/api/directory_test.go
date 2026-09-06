package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAuthentik serves the three admin endpoints the directory client
// uses: the user lookup, the account's device list, and device deletion.
func fakeAuthentik(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var deleted []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/core/users/", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		results := []map[string]any{}
		switch email {
		case "alice@example.test":
			results = append(results, map[string]any{"pk": 7, "email": "alice@example.test", "type": "internal"})
		case "bob@example.test":
			results = append(results, map[string]any{"pk": 8, "email": "bob@example.test", "type": "internal"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
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
		deleted = append(deleted, r.PathValue("kind")+"/"+r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &deleted
}

// TestDirectoryDevicesCarryIDs: the device list keeps the directory's ids
// (numeric or string) so the settings page can name one to remove.
func TestDirectoryDevicesCarryIDs(t *testing.T) {
	srv, _ := fakeAuthentik(t)
	c := newAuthentikEraser(srv.URL, "tok")
	devs, err := c.DevicesByEmail(context.Background(), "alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 || devs[0].ID != "31" || devs[0].Kind != "totp" || devs[1].ID != "44f2" || devs[1].Kind != "webauthn" {
		t.Fatalf("devices = %+v", devs)
	}
	if devs[0].CreatedAt == nil {
		t.Error("created timestamp not parsed")
	}
}

// TestDirectoryDeleteDeviceOwnOnly (agentry#164): a device is removed only
// when the account's own list reports it — somebody else's id, an unknown
// kind, or a foreign account all answer "not deleted" without touching the
// directory.
func TestDirectoryDeleteDeviceOwnOnly(t *testing.T) {
	srv, deleted := fakeAuthentik(t)
	c := newAuthentikEraser(srv.URL, "tok")
	ctx := context.Background()
	ok, err := c.DeleteDevice(ctx, "alice@example.test", "totp", "31")
	if err != nil || !ok {
		t.Fatalf("own device: ok=%v err=%v", ok, err)
	}
	if len(*deleted) != 1 || (*deleted)[0] != "totp/31" {
		t.Fatalf("deleted = %v", *deleted)
	}
	for _, tc := range []struct{ email, kind, id string }{
		{"bob@example.test", "totp", "31"},       // alice's device, bob asking
		{"alice@example.test", "webauthn", "31"}, // wrong kind for that id
		{"alice@example.test", "sms", "9"},       // no such device
		{"alice@example.test", "bogus", "31"},    // unknown kind
		{"nobody@example.test", "totp", "31"},    // no directory account
	} {
		ok, err := c.DeleteDevice(ctx, tc.email, tc.kind, tc.id)
		if err != nil || ok {
			t.Errorf("%+v: ok=%v err=%v", tc, ok, err)
		}
	}
	if len(*deleted) != 1 {
		t.Fatalf("directory touched for a refused request: %v", *deleted)
	}
}
