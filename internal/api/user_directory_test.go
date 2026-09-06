package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// GET /user/directory tells the settings page where credentials live when a
// directory service owns them (agentry#113): the directory's flow URLs
// derived from the OIDC issuer, and the caller's enrolled authenticators
// through the same admin access account erasure uses.
func TestUserDirectoryLinksAndDevices(t *testing.T) {
	var deleted atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer idp-admin-token" {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/core/users/":
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
				{"pk": 41, "email": r.URL.Query().Get("email"), "type": "internal"},
			}})
		case "/api/v3/authenticators/admin/all/":
			if r.URL.Query().Get("user") != "41" {
				http.Error(w, "wrong user", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"pk": 7, "name": "Phone", "type": "authentik_stages_authenticator_totp.TOTPDevice", "verbose_name": "TOTP Device", "created": "2026-09-01T10:00:00.000000Z"},
				{"pk": 9, "name": "", "type": "authentik_stages_authenticator_webauthn.WebAuthnDevice", "verbose_name": "WebAuthn Device"},
			})
		case "/api/v3/authenticators/admin/totp/7/":
			if r.Method != http.MethodDelete {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			deleted.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer idp.Close()

	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Auth.ExternalOnly = false // native register/login still allowed for the test's own account
		c.Auth.IdPAdminURL = idp.URL
		c.Auth.IdPAdminToken = "idp-admin-token"
		c.Social.Authentik = config.SocialProvider{ClientID: "agentry", ClientSecret: "s", Issuer: "https://auth.example.test/application/o/agentry/"}
	})
	user := env.register("dir-settings")
	env.verifyEmail(user)
	sess := env.login(user)

	// Not managed: the flag says so and nothing else is claimed.
	var off map[string]any
	env.doJSON(sess, http.MethodGet, "/api/v1/user/directory", nil, &off, http.StatusOK)
	if off["managed"] != false || off["accountUrl"] != nil {
		t.Fatalf("externalOnly=false: %v", off)
	}

	// Managed: the account lives in the directory, so sign in through the
	// (fake) directory IdP; links derive from its issuer, devices from the
	// admin API.
	oidc := newFakeOIDC(t)
	env2 := newTestEnvCfg(t, func(c *config.Config) {
		c.Auth.ExternalOnly = true
		c.Auth.IdPAdminURL = idp.URL
		c.Auth.IdPAdminToken = "idp-admin-token"
		c.Social.Authentik = config.SocialProvider{ClientID: oidc.clientID, ClientSecret: "s", Issuer: oidc.srv.URL}
	}, func(s *api.Server) { s.SetOIDCHTTPClient(oidc.srv.Client()) })
	authURL, state, cookie := env2.socialStart(t, "authentik")
	visit, err := oidc.srv.Client().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	res := env2.socialCallback(t, "authentik", state, cookie)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: %d", res.StatusCode)
	}
	var login struct {
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(res.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	sess2 := caller{name: "dir-oidc", csrf: login.CsrfToken}
	for _, ck := range res.Cookies() {
		if ck.Name == "agentry_session" {
			sess2.session = ck.Value
		}
	}
	if sess2.session == "" {
		t.Fatal("social login issued no session cookie")
	}
	var on struct {
		Managed           bool    `json:"managed"`
		AccountUrl        *string `json:"accountUrl"`
		PasswordChangeUrl string  `json:"passwordChangeUrl"`
		TotpSetupUrl      string  `json:"totpSetupUrl"`
		WebauthnSetupUrl  string  `json:"webauthnSetupUrl"`
		Devices           []struct {
			Id, Kind, Name string
			CreatedAt      *string `json:"createdAt"`
		} `json:"devices"`
	}
	env2.doJSON(sess2, http.MethodGet, "/api/v1/user/directory", nil, &on, http.StatusOK)
	base := oidc.srv.URL
	// DEV-089: the directory stays behind the scenes — no account URL, and the
	// flows are Agentry's own, which return to /settings when they finish.
	if !on.Managed || on.AccountUrl != nil || on.PasswordChangeUrl != base+"/if/flow/agentry-password-change/" || on.TotpSetupUrl != base+"/if/flow/agentry-totp-setup/" || on.WebauthnSetupUrl != base+"/if/flow/agentry-webauthn-setup/" {
		t.Fatalf("links: %+v", on)
	}
	if len(on.Devices) != 2 || on.Devices[0].Id != "7" || on.Devices[0].Kind != "totp" || on.Devices[0].Name != "Phone" || on.Devices[0].CreatedAt == nil || on.Devices[1].Id != "9" || on.Devices[1].Kind != "webauthn" || on.Devices[1].Name != "WebAuthn Device" {
		t.Fatalf("devices: %+v", on.Devices)
	}

	// Removing a device goes through Agentry, which checks the device is the
	// caller's own before asking the directory to delete it.
	env2.doJSON(sess2, http.MethodDelete, "/api/v1/user/directory/devices/totp/7", nil, nil, http.StatusNoContent)
	if deleted.Load() != 1 {
		t.Fatalf("directory delete calls: %d", deleted.Load())
	}
	env2.doJSON(sess2, http.MethodDelete, "/api/v1/user/directory/devices/totp/999", nil, nil, http.StatusNotFound)
	env2.doJSON(sess, http.MethodDelete, "/api/v1/user/directory/devices/totp/7", nil, nil, http.StatusNotFound) // native account: not managed
	if deleted.Load() != 1 {
		t.Fatalf("directory delete calls after misses: %d", deleted.Load())
	}
}
