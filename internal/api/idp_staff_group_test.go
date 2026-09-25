package api_test

// The directory's word at sign-in no longer makes platform staff
// (agentry#556): the group of DEV-083 and the domain-alone rule of DEV-137
// are retired, and staff is membership of the staff organization. The
// sign-in through the deployment's directory still recomputes the flag.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

func loginThroughFakeOIDCAs(t *testing.T, env *testEnv, idp *fakeOIDC) string {
	const provider = "authentik"
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

func TestRetiredDirectoryRulesGrantNothing(t *testing.T) {
	idp := newFakeOIDC(t)
	tag := randSuffix()
	org, domain := "staff"+tag, "staff"+tag+".test"
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
		cfg.Auth.StaffOrg, cfg.Auth.StaffDomain = org, domain
		// The retired keys still load, and grant nothing.
		cfg.Auth.IdPStaffGroup, cfg.Auth.IdPStaffDomain = "agentry-platform-staff", domain
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })

	founder := env.registerEmail("founder", "founder-"+env.sfx+"@"+domain)
	env.verifyEmail(founder)
	founderSess := env.login(founder)
	env.makePlatformStaff(t, founder) // founding the staff organization is reserved to staff
	env.createOrg(founderSess, org)

	// In the retired group, with a verified address at the domain, through
	// the deployment's own directory: not staff, because not a member.
	idp.sub, idp.email, idp.groups = "d-"+tag, "dir-"+env.sfx+"@"+domain, []string{"agentry-platform-staff"}
	userID := loginThroughFakeOIDCAs(t, env, idp)
	if platformStaff(t, env, userID) {
		t.Fatal("the retired group and domain rules must grant nothing")
	}

	// A member of the staff organization: the next directory sign-in makes
	// staff (the flag here is set by nothing but the sync).
	var handle string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT handle FROM handles WHERE id = $1::uuid`, userID).Scan(&handle); err != nil {
		t.Fatal(err)
	}
	env.seedMembership(org, handle, "member", "active")
	if again := loginThroughFakeOIDCAs(t, env, idp); again != userID {
		t.Fatalf("second sign-in must resolve the same account: %s vs %s", again, userID)
	}
	if !platformStaff(t, env, userID) {
		t.Fatal("a member of the staff organization at its domain must be staff after a directory sign-in")
	}

	// Out of the group again changes nothing; out of the organization does.
	idp.groups = nil
	loginThroughFakeOIDCAs(t, env, idp)
	if !platformStaff(t, env, userID) {
		t.Fatal("the group no longer decides anything")
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`DELETE FROM memberships WHERE user_id = $1::uuid`, userID); err != nil {
		t.Fatal(err)
	}
	loginThroughFakeOIDCAs(t, env, idp)
	if platformStaff(t, env, userID) {
		t.Fatal("no longer a member: the next sign-in must revoke staff")
	}
}
