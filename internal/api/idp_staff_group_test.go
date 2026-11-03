package api_test

// The sign-in provider's word does not make platform staff: neither a group
// claim nor an address domain alone grants it, and staff is membership of
// the staff organization. Every sign-in through the provider recomputes the
// flag.

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

// signInStatusThroughFakeOIDCAs is the callback's status for a sign-in that
// may be refused.
func signInStatusThroughFakeOIDCAs(t *testing.T, env *testEnv, idp *fakeOIDC) int {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, "authentik")
	visit, err := idp.srv.Client().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	res := env.socialCallback(t, "authentik", state, cookie)
	_ = res.Body.Close()
	return res.StatusCode
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

// TestRetiredDirectoryRulesGrantNothing: a groups claim naming a staff group
// and an address at the staff domain grant nothing without membership.
func TestRetiredDirectoryRulesGrantNothing(t *testing.T) {
	idp := newFakeOIDC(t)
	tag := randSuffix()
	org, domain := "staff"+tag, "staff"+tag+".test"
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Auth.OIDC = config.OIDCProvider{ID: config.AuthentikProviderID, ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
		cfg.Auth.StaffOrg, cfg.Auth.StaffDomain = org, domain
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })

	founder := env.registerEmail("founder", "founder-"+env.sfx+"@"+domain)
	env.verifyEmail(founder)
	founderSess := env.login(founder)
	env.makePlatformStaff(t, founder) // founding the staff organization is reserved to staff
	env.createOrg(founderSess, org)

	// In a staff group by the token's groups claim, with a verified address
	// at the domain: not staff, because not a member.
	idp.sub, idp.email, idp.groups = "d-"+tag, "dir-"+env.sfx+"@"+domain, []string{"agentry-platform-staff"}
	userID := loginThroughFakeOIDCAs(t, env, idp)
	if platformStaff(t, env, userID) {
		t.Fatal("a group claim and the domain alone must grant nothing")
	}

	// A member of the staff organization: the next directory sign-in makes
	// staff (the flag here is set by nothing but the sync), and only an
	// active membership counts.
	var handle string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT handle FROM handles WHERE id = $1::uuid`, userID).Scan(&handle); err != nil {
		t.Fatal(err)
	}
	syncs := func() int {
		t.Helper()
		var n int
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events WHERE action = 'user.staff_sync' AND target_id = $1::uuid`, userID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := env.st.Pool().Exec(context.Background(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	env.seedMembership(org, handle, "member", "pending")
	loginThroughFakeOIDCAs(t, env, idp)
	if platformStaff(t, env, userID) || syncs() != 0 {
		t.Fatal("a pending membership must not make staff, and a sign-in that changes nothing writes no sync row")
	}
	env.seedMembership(org, handle, "member", "active")
	if again := loginThroughFakeOIDCAs(t, env, idp); again != userID {
		t.Fatalf("second sign-in must resolve the same account: %s vs %s", again, userID)
	}
	if !platformStaff(t, env, userID) {
		t.Fatal("a member of the staff organization at its domain must be staff after a directory sign-in")
	}
	// The grant is audited by the sign-in's own sync, naming the rule.
	var detail map[string]any
	var actorID string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail, actor_id::text FROM audit_events WHERE action = 'user.staff_sync' AND target_id = $1::uuid`, userID).Scan(&detail, &actorID); err != nil {
		t.Fatal(err)
	}
	if detail["platformStaff"] != true || detail["rule"] != "staff-org" || detail["reason"] != "sign-in" ||
		detail["org"] != org || detail["domain"] != domain || actorID != userID {
		t.Fatalf("the grant is audited as %v by %s, want platformStaff true by rule staff-org at sign-in for %s@%s by the person", detail, actorID, org, domain)
	}

	// Out of the group again changes nothing (and writes nothing); out of the
	// organization does.
	idp.groups = nil
	loginThroughFakeOIDCAs(t, env, idp)
	if !platformStaff(t, env, userID) || syncs() != 1 {
		t.Fatalf("the group no longer decides anything: staff %v after %d sync rows", platformStaff(t, env, userID), syncs())
	}
	exec(`DELETE FROM memberships WHERE user_id = $1::uuid`, userID)
	loginThroughFakeOIDCAs(t, env, idp)
	if platformStaff(t, env, userID) || syncs() != 2 {
		t.Fatalf("no longer a member: the next sign-in must revoke staff (staff %v, %d sync rows)", platformStaff(t, env, userID), syncs())
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail FROM audit_events WHERE action = 'user.staff_sync' AND target_id = $1::uuid ORDER BY occurred_at DESC LIMIT 1`, userID).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if detail["platformStaff"] != false || detail["rule"] != "staff-org" || detail["reason"] != "sign-in" {
		t.Fatalf("the revocation is audited as %v", detail)
	}

	// Staff is recomputed from the account at every sign-in: a member who is
	// suspended, whose address is no longer verified, or whose address is no
	// longer at the domain is not staff however the membership stands.
	for _, tc := range []struct {
		name, sql string
		args      []any
		restore   string
		status    int
	}{
		{"an account that is suspended", `UPDATE users SET state = 'suspended' WHERE id = $1::uuid`, nil,
			`UPDATE users SET state = 'active' WHERE id = $1::uuid`, http.StatusUnauthorized},
		{"an address that is not verified", `UPDATE users SET email_verified_at = NULL WHERE id = $1::uuid`, nil,
			`UPDATE users SET email_verified_at = now() WHERE id = $1::uuid`, http.StatusOK},
		{"an address outside the domain", `UPDATE users SET email = 'outside-' || $2::text || '@elsewhere.test' WHERE id = $1::uuid`, []any{tag},
			`UPDATE users SET email = $2::text WHERE id = $1::uuid`, http.StatusOK},
	} {
		var email string
		if err := env.st.Pool().QueryRow(context.Background(), `SELECT email::text FROM users WHERE id = $1::uuid`, userID).Scan(&email); err != nil {
			t.Fatal(err)
		}
		env.seedMembership(org, handle, "member", "active")
		if again := loginThroughFakeOIDCAs(t, env, idp); again != userID || !platformStaff(t, env, userID) {
			t.Fatalf("%s: a member at the domain must be staff again before the account changes", tc.name)
		}
		exec(tc.sql, append([]any{userID}, tc.args...)...)
		if got := signInStatusThroughFakeOIDCAs(t, env, idp); got != tc.status {
			t.Fatalf("%s: the sign-in answered %d, want %d", tc.name, got, tc.status)
		}
		if platformStaff(t, env, userID) {
			t.Fatalf("%s: a member must not stay staff", tc.name)
		}
		restore := []any{userID}
		if tc.restore != "" && len(tc.args) > 0 {
			restore = append(restore, email)
		}
		exec(tc.restore, restore...)
	}
}
