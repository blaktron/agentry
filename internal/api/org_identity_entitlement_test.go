package api_test

// The rule that billing state never loosens identity: an organization's
// enforced SSO holds whatever its subscription says.

import (
	"context"
	"net/http"
	"testing"

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
	}
}
