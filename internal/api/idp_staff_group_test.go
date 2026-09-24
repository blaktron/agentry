package api_test

// Platform staff follows directory group membership (agentry#51): the
// `groups` claim of the deployment's own directory (`authentik`) grants
// and revokes users.platform_staff at sign-in; other providers and an
// unconfigured group name never touch it.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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

// Platform staff also follows an email domain (agentry#525): the directory's
// own ID token, asserting a verified address at exactly the configured
// domain, grants staff at sign-in and revokes it when the next sign-in no
// longer does. A subdomain, a look-alike, an unverified assertion and any
// other provider never grant it; the group rule stands beside it.
func TestDirectoryDomainDrivesPlatformStaff(t *testing.T) {
	idp := newFakeOIDC(t)
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
		cfg.Auth.IdPStaffDomain = "secureagentry.net"
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
	signIn := func(email string, verified bool) string {
		t.Helper()
		idp.email, idp.emailUnverified = email, !verified
		return loginThroughFakeOIDCAs(t, env, idp, "authentik")
	}

	// At the domain, verified, in any case: staff, audited with the rule.
	userID := signIn("Staff-"+randSuffix()+"@SecureAgentry.NET", true)
	if !platformStaff(t, env, userID) {
		t.Fatal("a verified address at the staff domain must be platform staff")
	}
	var rule string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'rule' FROM audit_events WHERE action = 'user.staff_sync' AND target_id = $1::uuid AND detail->>'platformStaff' = 'true'`, userID).Scan(&rule); err != nil {
		t.Fatalf("the grant is not audited: %v", err)
	}
	if rule != "domain" {
		t.Fatalf("the audit says the rule was %q, want domain", rule)
	}

	// The same account's next sign-in asserts another address: revoked.
	if again := signIn("staff-"+randSuffix()+"@elsewhere.test", true); again != userID {
		t.Fatalf("the second sign-in resolved another account: %s vs %s", again, userID)
	}
	if platformStaff(t, env, userID) {
		t.Fatal("an address no longer at the staff domain must revoke platform staff")
	}
	// That is the stored-versus-asserted case too: a sign-in does not
	// rewrite the stored address, so the account still holds the one at the
	// staff domain, and only the token's word counted.
	var stored string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT email FROM users WHERE id = $1::uuid`, userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.ToLower(stored), "@secureagentry.net") {
		t.Fatalf("the stored address moved to %q; this step no longer proves the stored address is ignored", stored)
	}
	var revokedRule string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'rule' FROM audit_events WHERE action = 'user.staff_sync' AND target_id = $1::uuid AND detail->>'platformStaff' = 'false'`, userID).Scan(&revokedRule); err != nil || revokedRule != "none" {
		t.Fatalf("the revocation's audit rule: %q %v", revokedRule, err)
	}

	// Never staff: a subdomain, look-alikes, an unverified assertion.
	for _, c := range []struct {
		email    string
		verified bool
	}{
		{"a-" + randSuffix() + "@ops.secureagentry.net", true},
		{"b-" + randSuffix() + "@secureagentry.net.evil.test", true},
		{"c-" + randSuffix() + "@evilsecureagentry.net", true},
		{"d-" + randSuffix() + "@secureagentry.net", false},
	} {
		idp.sub = "g-" + randSuffix()
		if platformStaff(t, env, signIn(c.email, c.verified)) {
			t.Fatalf("%s (verified %v) must not be platform staff", c.email, c.verified)
		}
	}

	// Another provider's verified address at the domain: ignored.
	other := newFakeOIDC(t)
	other.email = "g-" + randSuffix() + "@secureagentry.net"
	env2 := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Google = config.SocialProvider{ClientID: other.clientID, ClientSecret: "s", Issuer: other.srv.URL}
		cfg.Auth.IdPStaffDomain = "secureagentry.net"
	}, func(s *api.Server) { s.SetOIDCHTTPClient(other.srv.Client()) })
	if platformStaff(t, env2, loginThroughFakeOIDCAs(t, env2, other, "google")) {
		t.Fatal("a non-directory provider's address must not grant staff")
	}
}

// With both rules configured, either one makes staff, and a person who
// meets neither is not.
func TestDirectoryGroupOrDomainMakesStaff(t *testing.T) {
	idp := newFakeOIDC(t)
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
		cfg.Auth.IdPStaffGroup = "agentry-platform-staff"
		cfg.Auth.IdPStaffDomain = "secureagentry.net"
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
	for _, c := range []struct {
		email  string
		groups []string
		want   bool
	}{
		{"g-" + randSuffix() + "@elsewhere.test", []string{"agentry-platform-staff"}, true},
		{"d-" + randSuffix() + "@secureagentry.net", []string{"engineering"}, true},
		{"n-" + randSuffix() + "@elsewhere.test", []string{"engineering"}, false},
	} {
		idp.sub, idp.email, idp.groups = "g-"+randSuffix(), c.email, c.groups
		if got := platformStaff(t, env, loginThroughFakeOIDCAs(t, env, idp, "authentik")); got != c.want {
			t.Fatalf("%s in %v: staff %v, want %v", c.email, c.groups, got, c.want)
		}
	}
}
