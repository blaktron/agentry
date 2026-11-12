package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/pkg/extension"
)

// The single sign-on seam: an extension route that acts on an organization
// asks the core whether the caller meets the organization's SSO
// requirement, and gets the answer the core's own organization routes give.
// A probe extension answers 204 where the seam allows, 403 where it does
// not, and 500 on a fault.
func TestOrgSSOSeamAnswersAsTheCoreDoes(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("GET /sso/{id}", func(w http.ResponseWriter, r *http.Request) {
				id, err := uuid.Parse(r.PathValue("id"))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				ok, err := s.OrgSSOAllows(r.Context(), extension.PrincipalFromContext(r.Context()), id)
				switch {
				case err != nil:
					w.WriteHeader(http.StatusInternalServerError)
				case !ok:
					w.WriteHeader(http.StatusForbidden)
				default:
					w.WriteHeader(http.StatusNoContent)
				}
			})
		})
	})
	ctx := context.Background()
	admin := env.seedCaller("osso-admin")
	orgID := env.createOrg(admin, "osso-org"+env.sfx)
	other := env.createOrg(env.seedCaller("osso-member"), "osso-second"+env.sfx)
	userID := env.selfID(admin)
	_, unbound := env.mintPAT(admin, "osso-unbound", "org:admin")
	boundID, bound := env.mintPAT(admin, "osso-bound", "org:admin")
	if _, err := env.st.Pool().Exec(ctx, `UPDATE pats SET org_id = $2 WHERE id = $1`, boundID, orgID); err != nil {
		t.Fatal(err)
	}
	ask := func(c caller, id string) int {
		t.Helper()
		res := env.do(c, http.MethodGet, "/api/v1/x/probe/sso/"+id, nil)
		_ = res.Body.Close()
		return res.StatusCode
	}
	tag := func(org string, at time.Time) {
		t.Helper()
		if _, err := env.st.Pool().Exec(ctx, `UPDATE sessions SET sso_tags = jsonb_build_object($2::text, $3::text) WHERE user_id = $1`,
			userID, org, at.UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	unboundPAT, boundPAT := caller{name: "unbound", pat: unbound}, caller{name: "bound", pat: bound}

	// No requirement: every caller.
	for name, c := range map[string]caller{"a session": admin, "an unbound token": unboundPAT, "a bound token": boundPAT} {
		if got := ask(c, orgID); got != http.StatusNoContent {
			t.Errorf("%s, no requirement: %d", name, got)
		}
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET sso_required = true WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}
	// Required: a session its SSO never asserted, a token not bound to it,
	// and a session tagged for another organization are refused.
	if got := ask(admin, orgID); got != http.StatusForbidden {
		t.Errorf("a session the organization's SSO did not assert: %d", got)
	}
	if got := ask(unboundPAT, orgID); got != http.StatusForbidden {
		t.Errorf("a token not bound to the organization: %d", got)
	}
	if got := ask(boundPAT, orgID); got != http.StatusNoContent {
		t.Errorf("a token bound to the organization: %d", got)
	}
	tag(other, time.Now())
	if got := ask(admin, orgID); got != http.StatusForbidden {
		t.Errorf("a session another organization's SSO asserted: %d", got)
	}
	// A fresh assertion admits the session; one past the window does not.
	tag(orgID, time.Now())
	if got := ask(admin, orgID); got != http.StatusNoContent {
		t.Errorf("a fresh SSO session: %d", got)
	}
	tag(orgID, time.Now().Add(-25*time.Hour))
	if got := ask(admin, orgID); got != http.StatusForbidden {
		t.Errorf("a stale SSO session: %d", got)
	}
	// The other organization requires nothing; an unknown one is answered
	// as absent elsewhere and allows here.
	if got := ask(admin, other); got != http.StatusNoContent {
		t.Errorf("an organization without the requirement: %d", got)
	}
	if got := ask(admin, uuid.NewString()); got != http.StatusNoContent {
		t.Errorf("an unknown organization: %d", got)
	}
}
