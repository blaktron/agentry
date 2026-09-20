package api_test

// SSO and SCIM gated on the tier, and the rule that billing state never
// loosens identity (agentry#365, M13; plan organization-subscriptions.md
// §5.7, D11; DEV-118).

import (
	"context"
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
)

// identityResolver is the core resolver with SSO and SCIM switched the way
// a tier's resolver would answer them; broken fails instead, for the
// fail-closed cases.
type identityResolver struct {
	entitlements.Resolver
	sso    bool
	scim   bool
	broken bool
}

func (c identityResolver) Features(ctx context.Context, s entitlements.Subject) (entitlements.Features, error) {
	if c.broken {
		return entitlements.Features{}, context.DeadlineExceeded
	}
	f, err := c.Resolver.Features(ctx, s)
	if err != nil {
		return f, err
	}
	if s.Kind == entitlements.NamespaceOrg {
		f.SSO, f.SCIM = c.sso, c.scim
	}
	return f, nil
}

func identityTier(sso, scim bool) func(*api.Server) {
	return func(s *api.Server) {
		s.SetEntitlements(identityResolver{
			Resolver: entitlements.NewConfigResolver(config.Default().Limits), sso: sso, scim: scim,
		})
	}
}

func brokenIdentityTier() func(*api.Server) {
	return func(s *api.Server) {
		s.SetEntitlements(identityResolver{
			Resolver: entitlements.NewConfigResolver(config.Default().Limits), broken: true,
		})
	}
}

// setEntitlements swaps the resolver after the fixture is built, which is
// what a subscription changing under a live organization looks like.
func (env *testEnv) setEntitlements(r entitlements.Resolver) {
	env.srvObj.SetEntitlements(r)
}

// identityState is what a downgrade must not touch: the organization's
// enforced-SSO flag and the rows behind its sign-in and provisioning.
type identityState struct {
	required    bool
	connections int
	tokens      int
}

func (env *testEnv) ssoState(orgID string) identityState {
	env.t.Helper()
	var st identityState
	ctx := context.Background()
	if err := env.st.Pool().QueryRow(ctx, `SELECT sso_required FROM orgs WHERE id = $1`, orgID).Scan(&st.required); err != nil {
		env.t.Fatalf("read sso_required: %v", err)
	}
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM sso_connections WHERE org_id = $1`, orgID).Scan(&st.connections); err != nil {
		env.t.Fatalf("count connections: %v", err)
	}
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM scim_tokens WHERE org_id = $1 AND revoked_at IS NULL`, orgID).Scan(&st.tokens); err != nil {
		env.t.Fatalf("count scim tokens: %v", err)
	}
	return st
}

// A tier without SSO or SCIM refuses to create either, and says which
// subscription is the reason rather than pretending the route is absent.
func TestIdentityDoorsAreGatedOnTheTier(t *testing.T) {
	env := newTestEnvWith(t, identityTier(false, false))
	admin := env.register("id-admin")
	env.verifyEmail(admin)
	sess := env.login(admin)
	orgH := "idorg" + env.sfx
	env.createOrg(sess, orgH)

	res := env.do(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
		"enabled": true,
		"config":  map[string]any{"issuer": "https://idp.example", "clientId": "x", "clientSecret": "y"},
	})
	code, slug, _ := problemOf(t, res)
	if code != http.StatusForbidden || slug != "feature-not-included" {
		t.Fatalf("an SSO connection on a tier without SSO: %d %s, want 403 feature-not-included", code, slug)
	}

	res = env.do(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/scim/tokens", map[string]any{})
	code, slug, _ = problemOf(t, res)
	if code != http.StatusForbidden || slug != "feature-not-included" {
		t.Fatalf("a SCIM token on a tier without SCIM: %d %s, want 403 feature-not-included", code, slug)
	}

	// The organization's SSO start is not a door that exists.
	res = env.do(caller{name: "anon"}, http.MethodGet, "/api/v1/orgs/"+orgH+"/sso/oidc/start", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("the SSO start on a tier without SSO: %d, want 404", res.StatusCode)
	}
}

// An entitlement the resolver cannot answer refuses the act, as every
// other entitlement gate does: an outage is not a way to add a sign-in
// door or mint a directory credential.
func TestIdentityDoorsFailClosed(t *testing.T) {
	env := newTestEnvWith(t, brokenIdentityTier())
	admin := env.register("idf-admin")
	env.verifyEmail(admin)
	sess := env.login(admin)
	orgH := "idforg" + env.sfx
	env.createOrg(sess, orgH)

	for _, tc := range []struct {
		name, method, path string
		body               map[string]any
	}{
		{"an SSO connection", http.MethodPut, "/api/v1/orgs/" + orgH + "/sso/connections/oidc",
			map[string]any{"enabled": true, "config": map[string]any{"issuer": "https://idp.example", "clientId": "x", "clientSecret": "y"}}},
		{"a SCIM token", http.MethodPost, "/api/v1/orgs/" + orgH + "/scim/tokens", map[string]any{}},
	} {
		res := env.do(sess, tc.method, tc.path, tc.body)
		code, _, _ := problemOf(t, res)
		if code < 400 {
			t.Fatalf("%s while entitlements are unknown: %d, want a refusal", tc.name, code)
		}
	}
}

// The rule this milestone exists to keep: a subscription that stops
// including SSO takes nothing away and lets nobody in. The connection and
// the SCIM token keep their rows, `sso_required` is untouched — billing
// never writes it — and the only change is that enforcement stops, because
// an organization with no door cannot demand that people come through it.
func TestDowngradeNeverLoosensIdentity(t *testing.T) {
	env := newTestEnvWith(t, identityTier(true, true))
	admin := env.register("dg-admin")
	env.verifyEmail(admin)
	sess := env.login(admin)
	orgH := "dgorg" + env.sfx
	orgID := env.createOrg(sess, orgH)

	// With the tier: a connection, a SCIM token, and enforced SSO.
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
		"enabled": true,
		"config":  map[string]any{"issuer": "https://idp.example", "clientId": "x", "clientSecret": "y"},
	}, nil, http.StatusOK)
	var tok struct {
		Token string `json:"token"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/scim/tokens", map[string]any{}, &tok, http.StatusCreated)
	env.doJSON(sess, http.MethodPatch, "/api/v1/orgs/"+orgH, map[string]any{"ssoRequired": true}, nil, http.StatusOK)

	before := env.ssoState(orgID)
	if !before.required || before.connections != 1 || before.tokens != 1 {
		t.Fatalf("before the downgrade: %+v", before)
	}

	// The subscription stops including either.
	env.setEntitlements(identityResolver{
		Resolver: entitlements.NewConfigResolver(config.Default().Limits), sso: false, scim: false,
	})

	after := env.ssoState(orgID)
	if after != before {
		t.Fatalf("the downgrade changed identity state: before %+v, after %+v", before, after)
	}

	// Nothing is enforced any more, so the admin still reaches the
	// organization's own settings with an ordinary session — the sign-in
	// they would have been asked for no longer exists.
	env.doJSON(sess, http.MethodPatch, "/api/v1/orgs/"+orgH,
		map[string]any{"displayName": "Still Reachable"}, nil, http.StatusOK)

	// And the doors are shut: the token no longer provisions, and the
	// start is gone.
	res := env.do(caller{name: "scim", pat: tok.Token}, http.MethodGet, "/scim/v2/Users", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("SCIM after the downgrade: %d, want 403", res.StatusCode)
	}
	res = env.do(caller{name: "anon"}, http.MethodGet, "/api/v1/orgs/"+orgH+"/sso/oidc/start", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("the SSO start after the downgrade: %d, want 404", res.StatusCode)
	}

	// Back on a tier that includes them, everything works again without
	// anything being re-entered.
	env.setEntitlements(identityResolver{
		Resolver: entitlements.NewConfigResolver(config.Default().Limits), sso: true, scim: true,
	})
	res = env.do(caller{name: "scim", pat: tok.Token}, http.MethodGet, "/scim/v2/Users", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("SCIM after re-subscribing: %d, want 200 — the token should not have had to be re-issued", res.StatusCode)
	}
}
