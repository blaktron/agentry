package api_test

// The rule that billing state never loosens identity: an organization's
// enforced SSO holds whatever its subscription says.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
)

// identityTier is a tier that does or does not include SSO and SCIM.
func identityTier(sso, scim bool) func(*api.Server) {
	return onTier(func(f *entitlements.Features) { f.SSO, f.SCIM = sso, scim })
}

func identityResolverFor(sso, scim bool) entitlements.Resolver {
	return tierResolver{
		Resolver: entitlements.NewConfigResolver(config.Default().Limits),
		apply:    func(f *entitlements.Features) { f.SSO, f.SCIM = sso, scim },
	}
}

func (env *testEnv) ssoRequired(orgID string) bool {
	env.t.Helper()
	var required bool
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT sso_required FROM orgs WHERE id = $1`, orgID).Scan(&required); err != nil {
		env.t.Fatalf("read sso_required: %v", err)
	}
	return required
}

// The rule this test exists to keep: a subscription that stops including
// SSO lets nobody in. `sso_required` is untouched — billing never writes
// it — and enforcement goes on: neither a downgrade nor an entitlement
// outage lets an ordinary session past the organization's own sign-in
// policy.
func TestDowngradeNeverLoosensIdentity(t *testing.T) {
	env := newTestEnvWith(t, identityTier(true, true))
	admin := env.register("dg-admin")
	env.verifyEmail(admin)
	sess := env.login(admin)
	orgH := "dgorg" + env.sfx
	orgID := env.createOrg(sess, orgH)

	// With the tier: enforced SSO.
	env.doJSON(sess, http.MethodPatch, "/api/v1/orgs/"+orgH, map[string]any{"ssoRequired": true}, nil, http.StatusOK)
	if !env.ssoRequired(orgID) {
		t.Fatal("before the downgrade: sso_required is not set")
	}

	// The positive control, without which the assertion after the
	// downgrade would pass for an organization that was never enforcing:
	// while the tier includes SSO, this ordinary session is refused the
	// organization's own settings, because it has not come through the
	// organization's identity provider.
	res := env.do(sess, http.MethodPatch, "/api/v1/orgs/"+orgH,
		map[string]any{"displayName": "Refused While Enforcing"})
	code, slug, _ := problemOf(t, res)
	if code != http.StatusForbidden {
		t.Fatalf("enforced SSO with the tier: %d %s, want 403 — the rest of this test proves nothing otherwise", code, slug)
	}

	// The subscription stops including either.
	env.setEntitlements(identityResolverFor(false, false))

	if !env.ssoRequired(orgID) {
		t.Fatal("the downgrade cleared sso_required")
	}

	// Who the policy admits and who it turns away is what it was with the
	// tier: a sign-in through the organization's identity provider, or a
	// token bound to the organization, gets in; an ordinary session, a
	// sign-in that has lapsed or was for another organization, and a token
	// bound to no organization or to another one do not. A person who holds
	// no credential at all satisfies nothing.
	adminID := env.userID(admin)
	otherOrgID := env.createOrg(env.seedCaller("dg-other"), "dgother"+env.sfx)
	boundTok := caller{name: "bound", pat: env.insertPAT(adminID, orgID, "org:admin")}
	unboundTok := caller{name: "unbound", pat: env.insertPAT(adminID, "", "org:admin")}
	elsewhereTok := caller{name: "elsewhere", pat: env.insertPAT(adminID, otherOrgID, "org:admin")}
	memberH := env.register("dg-member")
	env.verifyEmail(memberH)
	env.seedMembership(orgH, memberH, "member", "active")
	memberID := env.userID(memberH)
	member := env.login(memberH)
	membersPath := "/api/v1/orgs/" + orgH + "/members"
	read := func(c caller) (int, string) {
		t.Helper()
		res := env.do(c, http.MethodGet, membersPath, nil)
		if res.StatusCode == http.StatusOK {
			_ = res.Body.Close()
			return res.StatusCode, ""
		}
		code, slug, _ := problemOf(t, res)
		return code, slug
	}
	untag := func() {
		t.Helper()
		if _, err := env.st.Pool().Exec(context.Background(), `UPDATE sessions SET sso_tags = '{}'::jsonb WHERE user_id = $1`, memberID); err != nil {
			t.Fatal(err)
		}
	}
	p, ok, err := env.srvObj.PrincipalForUser(context.Background(), uuid.MustParse(adminID))
	if err != nil || !ok {
		t.Fatalf("the principal for the admin: %v, %v", ok, err)
	}

	// Enforcement goes on, whatever the tier says and when it cannot be
	// read: the ordinary session is still refused.
	for name, tier := range map[string]entitlements.Resolver{
		"a tier without SSO": identityResolverFor(false, false),
		"an unknown tier":    brokenTierResolver(),
	} {
		env.setEntitlements(tier)
		res = env.do(sess, http.MethodPatch, "/api/v1/orgs/"+orgH,
			map[string]any{"displayName": "Refused After The Downgrade"})
		code, slug, _ = problemOf(t, res)
		if code != http.StatusForbidden || slug != "sso-required" {
			t.Fatalf("enforced SSO under %s: %d %s, want 403 sso-required", name, code, slug)
		}

		untag()
		if code, slug := read(member); code != http.StatusForbidden || slug != "sso-required" {
			t.Fatalf("an ordinary session under %s: %d %s, want 403 sso-required", name, code, slug)
		}
		env.staleSSO(memberID, orgID)
		if code, slug := read(member); code != http.StatusForbidden || slug != "sso-required" {
			t.Fatalf("a lapsed sign-in under %s: %d %s, want 403 sso-required", name, code, slug)
		}
		env.freshenSSO(memberID, otherOrgID)
		if code, slug := read(member); code != http.StatusForbidden || slug != "sso-required" {
			t.Fatalf("a sign-in for another organization under %s: %d %s, want 403 sso-required", name, code, slug)
		}
		if code, slug := read(unboundTok); code != http.StatusForbidden || slug != "sso-required" {
			t.Fatalf("a token bound to no organization under %s: %d %s, want 403 sso-required", name, code, slug)
		}
		if code, _ := read(elsewhereTok); code != http.StatusForbidden {
			t.Fatalf("a token bound to another organization under %s: %d, want 403", name, code)
		}
		if p.SSOSatisfied(uuid.MustParse(orgID), time.Hour) {
			t.Fatalf("a principal with no credential satisfies the policy under %s", name)
		}
		env.freshenSSO(memberID, orgID)
		if code, _ := read(member); code != http.StatusOK {
			t.Fatalf("a fresh sign-in under %s: %d, want 200", name, code)
		}
		if code, _ := read(boundTok); code != http.StatusOK {
			t.Fatalf("a token bound to the organization under %s: %d, want 200", name, code)
		}

		// A token bound to the organization is let in, and still cannot
		// switch the policy off: that is a setting only a session changes.
		res = env.do(boundTok, http.MethodPatch, "/api/v1/orgs/"+orgH, map[string]any{"ssoRequired": false})
		code, slug, detail := problemOf(t, res)
		if code != http.StatusForbidden || !strings.Contains(detail, "ssoRequired") {
			t.Fatalf("a bound token switching enforced SSO off under %s: %d %s %q, want 403 naming ssoRequired", name, code, slug, detail)
		}
		if !env.ssoRequired(orgID) {
			t.Fatalf("a bound token cleared sso_required under %s", name)
		}
		env.doJSON(boundTok, http.MethodPatch, "/api/v1/orgs/"+orgH, map[string]any{"displayName": "Renamed By A Bound Token"}, nil, http.StatusOK)
	}
}
