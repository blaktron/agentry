package api_test

// Platform staff follows directory group membership (agentry#51): the
// `groups` claim of the deployment's own directory (`authentik`) grants
// and revokes users.platform_staff at sign-in; other providers and an
// unconfigured group name never touch it.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

func loginThroughFakeOIDCAs(t *testing.T, env *testEnv, idp *fakeOIDC, provider string) string {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, provider)
	visit, err := idp.srv.Client().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	res := env.socialCallback(t, provider, state, cookie)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Id string `json:"id"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.User.Id
}

func platformStaff(t *testing.T, env *testEnv, userID string) bool {
	t.Helper()
	var staff bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT platform_staff FROM users WHERE id = $1::uuid`, userID).Scan(&staff); err != nil {
		t.Fatal(err)
	}
	return staff
}

func TestDirectoryGroupDrivesPlatformStaff(t *testing.T) {
	idp := newFakeOIDC(t)
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
		cfg.Auth.IdPStaffGroup = "agentry-platform-staff"
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })

	// Member of the group at first sign-in: staff.
	idp.groups = []string{"engineering", "agentry-platform-staff"}
	userID := loginThroughFakeOIDCAs(t, env, idp, "authentik")
	if !platformStaff(t, env, userID) {
		t.Fatal("group member must be platform staff after sign-in")
	}
	var audited int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.staff_sync' AND target_id = $1::uuid AND detail->>'platformStaff' = 'true'`, userID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("staff grant must be audited once, got %d", audited)
	}

	// Removed from the group: revoked at the next sign-in.
	idp.groups = []string{"engineering"}
	if again := loginThroughFakeOIDCAs(t, env, idp, "authentik"); again != userID {
		t.Fatalf("second sign-in must resolve the same account: %s vs %s", again, userID)
	}
	if platformStaff(t, env, userID) {
		t.Fatal("leaving the group must revoke platform staff")
	}

	// Same claim from a non-directory provider: ignored.
	other := newFakeOIDC(t)
	other.groups = []string{"agentry-platform-staff"}
	env2 := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Google = config.SocialProvider{ClientID: other.clientID, ClientSecret: "s", Issuer: other.srv.URL}
		cfg.Auth.IdPStaffGroup = "agentry-platform-staff"
	}, func(s *api.Server) { s.SetOIDCHTTPClient(other.srv.Client()) })
	if platformStaff(t, env2, loginThroughFakeOIDCAs(t, env2, other, "google")) {
		t.Fatal("a non-directory provider's groups claim must not grant staff")
	}
}

func TestDirectoryGroupSyncOffWhenUnconfigured(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.groups = []string{"agentry-platform-staff"}
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
	if platformStaff(t, env, loginThroughFakeOIDCAs(t, env, idp, "authentik")) {
		t.Fatal("no group configured: the flag must stay false")
	}
}
