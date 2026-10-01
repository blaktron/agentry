package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
)

// The agent-maintain seam (agentry#833): an extension asks the core whether
// a principal may maintain an agent — the hosted revision admits only a
// maintainer (drafter-revisions R3) — and gets the answer the core's own
// routes give: the maintain role over the namespace or a grant, a PAT's
// org:admin, and the organization's gate for a write. Absent, unreadable,
// readable-but-not-maintainable and gated are one answer. A probe
// extension answers 200 when the seam says maintainable and 404 otherwise,
// and each answer is checked against the agent route's own maintain
// decision (the settings it serializes for a maintainer alone).
func TestAgentMaintainSeamAnswersAsTheCoreDoes(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("GET /maintain/{ns}/{name}", func(w http.ResponseWriter, r *http.Request) {
				a, ok, err := s.AgentMaintainable(r.Context(), api.PrincipalFrom(r.Context()), r.PathValue("ns"), r.PathValue("name"))
				switch {
				case err != nil:
					w.WriteHeader(http.StatusInternalServerError)
				case !ok:
					w.WriteHeader(http.StatusNotFound)
				default:
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"namespace": a.Namespace, "kind": a.NamespaceKind, "public": a.Visibility == "public"})
				}
			})
		})
	})
	ctx := context.Background()

	founder := env.register("ms-founder")
	env.verifyEmail(founder)
	member := env.register("ms-member")
	pending := env.register("ms-pending")
	reviewer := env.register("ms-reviewer")
	outsider := env.register("ms-outsider")
	reader := env.register("ms-reader")
	maintainer := env.register("ms-maintainer")
	staff := env.register("ms-staff")
	env.makePlatformStaff(t, staff)
	admin := env.login(founder)
	staffSess := env.login(staff)
	org := "ms-org" + env.sfx
	orgID := env.createOrg(admin, org)
	env.joinOrg(admin, org, member)
	env.seedMembership(org, pending, "member", "pending")
	env.seedMembership(org, reviewer, "security_reviewer", "active")
	for _, a := range []struct{ ns, name, visibility string }{
		{org, "private", "private"}, {org, "public", "public"}, {founder, "own", "private"},
	} {
		env.doJSON(admin, http.MethodPost, "/api/v1/agents", map[string]any{"namespace": a.ns, "name": a.name, "visibility": a.visibility}, nil, http.StatusCreated)
	}
	// Explicit grants on the organization's private agent: one to read, one
	// to maintain.
	env.doJSON(admin, http.MethodPut, "/api/v1/agents/"+org+"/private/grants/user/"+reader, map[string]any{"role": "read"}, nil, http.StatusNoContent)
	env.doJSON(admin, http.MethodPut, "/api/v1/agents/"+org+"/private/grants/user/"+maintainer, map[string]any{"role": "maintain"}, nil, http.StatusNoContent)
	_, founderPATRead := env.mintPAT(admin, "read-only", "run:write", "agent:read")
	_, founderPATAdmin := env.mintPAT(admin, "with-org-admin", "agent:read", "org:admin")

	callers := map[string]caller{
		"anonymous": anonymous, "the founder": admin, "a member": env.login(member), "a pending member": env.login(pending),
		"the security reviewer": env.login(reviewer), "an outsider": env.login(outsider), "a read grantee": env.login(reader),
		"a maintain grantee": env.login(maintainer), "platform staff": staffSess,
		"the founder's PAT without org:admin": {name: "pat-read", pat: founderPATRead},
		"the founder's PAT with org:admin":    {name: "pat-admin", pat: founderPATAdmin},
	}
	// maintains asks the seam and, beside it, the core's agent route,
	// which serializes the maintainer's settings (autoPublishTags) for a
	// maintainer alone: the two must agree, or the seam is not the core's
	// decision. gated skips the route's side, which does not apply the
	// organization's gate for a write.
	maintains := func(c caller, ns, name string, gated bool) int {
		t.Helper()
		res := env.do(c, http.MethodGet, "/api/v1/x/probe/maintain/"+ns+"/"+name, nil)
		_ = res.Body.Close()
		if !gated {
			route := env.do(c, http.MethodGet, "/api/v1/agents/"+ns+"/"+name, nil)
			var body map[string]any
			if route.StatusCode == http.StatusOK {
				decodeInto(t, route, &body)
			} else {
				_ = route.Body.Close()
			}
			_, routeSays := body["autoPublishTags"]
			if (res.StatusCode == http.StatusOK) != routeSays {
				t.Errorf("%s on %s/%s: the seam says %d, the route's maintain is %v", c.name, ns, name, res.StatusCode, routeSays)
			}
		}
		return res.StatusCode
	}
	want := map[string][3]int{ // org/private, org/public, founder/own
		"anonymous":                           {404, 404, 404},
		"the founder":                         {200, 200, 200},
		"a member":                            {200, 200, 404},
		"a pending member":                    {404, 404, 404},
		"the security reviewer":               {404, 404, 404},
		"an outsider":                         {404, 404, 404},
		"a read grantee":                      {404, 404, 404},
		"a maintain grantee":                  {200, 404, 404},
		"platform staff":                      {404, 404, 404},
		"the founder's PAT without org:admin": {404, 404, 404},
		"the founder's PAT with org:admin":    {200, 200, 200},
	}
	targets := [3][2]string{{org, "private"}, {org, "public"}, {founder, "own"}}
	for who, c := range callers {
		for i, tg := range targets {
			if got := maintains(c, tg[0], tg[1], false); got != want[who][i] {
				t.Errorf("%s maintains %s/%s: %d, want %d", who, tg[0], tg[1], got, want[who][i])
			}
		}
	}
	// A maintainable answer carries what the core knows of the agent.
	res := env.do(callers["a maintain grantee"], http.MethodGet, "/api/v1/x/probe/maintain/"+org+"/private", nil)
	var ref struct {
		Namespace, Kind string
		Public          bool
	}
	decodeInto(t, res, &ref)
	if ref.Namespace != org || ref.Kind != "org" || ref.Public {
		t.Fatalf("the ref: %+v", ref)
	}
	// The organization's gate for a write: in its decommission hold its
	// agents read and are maintained by no one; suspended, they are absent.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = 'decommissioning', decommission_at = now() + interval '7 days' WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}
	for who, c := range map[string]caller{"the founder": admin, "a member": callers["a member"], "a maintain grantee": callers["a maintain grantee"]} {
		if got := maintains(c, org, "private", true); got != 404 {
			t.Errorf("%s maintains the private agent of an organization in its hold: %d, want 404", who, got)
		}
	}
	if got := maintains(admin, founder, "own", false); got != 200 {
		t.Errorf("the founder's own agent while their organization is in its hold: %d, want 200", got)
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = 'active', decommission_at = NULL WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}
	env.doJSON(staffSess, http.MethodPost, "/api/v1/orgs/"+org+"/suspend", map[string]any{"reason": "the maintain seam's test"}, nil, http.StatusOK)
	if got := maintains(admin, org, "private", true); got != 404 {
		t.Errorf("the founder maintains the private agent of a suspended organization: %d, want 404", got)
	}
	// Nothing at all: absent, not an error.
	if got := maintains(admin, founder, "nothing", false); got != 404 {
		t.Errorf("a missing agent: %d, want 404", got)
	}
	if got := maintains(admin, "nobody"+env.sfx, "nothing", false); got != 404 {
		t.Errorf("a missing namespace: %d, want 404", got)
	}
}
