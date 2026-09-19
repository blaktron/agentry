package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
)

// The agent-read seam (agentry#381): an extension asks the core whether a
// principal may read an agent and gets the answer the core's own routes
// give — the effective role over the namespace and the grants, the PAT's
// scope, the organization's state — and never distinguishes "absent" from
// "not yours". A probe extension answers 200 with the ref when the seam
// says readable and 404 otherwise, so every caller the runs extension
// meets is enumerated through HTTP.
func TestAgentReadSeamAnswersAsTheCoreDoes(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("GET /read/{ns}/{name}", func(w http.ResponseWriter, r *http.Request) {
				a, ok, err := s.AgentReadable(r.Context(), api.PrincipalFrom(r.Context()), r.PathValue("ns"), r.PathValue("name"))
				switch {
				case err != nil:
					w.WriteHeader(http.StatusInternalServerError)
				case !ok:
					w.WriteHeader(http.StatusNotFound)
				default:
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"namespace": a.Namespace, "kind": a.NamespaceKind, "public": a.Visibility == "public", "id": a.ID})
				}
			})
		})
	})
	ctx := context.Background()

	founder := env.register("rs-founder")
	env.verifyEmail(founder)
	member := env.register("rs-member")
	pending := env.register("rs-pending")
	reviewer := env.register("rs-reviewer")
	outsider := env.register("rs-outsider")
	grantee := env.register("rs-grantee")
	staff := env.register("rs-staff")
	env.makePlatformStaff(t, staff)
	admin := env.login(founder)
	staffSess := env.login(staff)
	org := "rs-org" + env.sfx
	orgID := env.createOrg(admin, org)
	env.joinOrg(admin, org, member)
	env.seedMembership(org, pending, "member", "pending")
	env.seedMembership(org, reviewer, "security_reviewer", "active")
	for _, a := range []struct{ ns, name, visibility string }{
		{org, "private", "private"}, {org, "public", "public"}, {founder, "own", "private"},
	} {
		env.doJSON(admin, http.MethodPost, "/api/v1/agents", map[string]any{"namespace": a.ns, "name": a.name, "visibility": a.visibility}, nil, http.StatusCreated)
	}
	// An explicit read grant on the organization's private agent, through
	// the door.
	env.doJSON(admin, http.MethodPut, "/api/v1/agents/"+org+"/private/grants/user/"+grantee, map[string]any{"role": "read"}, nil, http.StatusNoContent)
	_, memberPATRunOnly := env.mintPAT(env.login(member), "run-only", "run:write")
	_, memberPATRead := env.mintPAT(env.login(member), "with-read", "run:write", "agent:read")

	callers := map[string]caller{
		"anonymous": anonymous, "the founder": admin, "a member": env.login(member), "a pending member": env.login(pending),
		"the security reviewer": env.login(reviewer), "an outsider": env.login(outsider), "a grantee": env.login(grantee),
		"platform staff": staffSess, "a member's PAT without agent:read": {name: "pat-run", pat: memberPATRunOnly},
		"a member's PAT with agent:read": {name: "pat-read", pat: memberPATRead},
	}
	// read asks the seam, and beside it the core's own route: the two must
	// agree cell for cell, or the seam is not the core's read.
	read := func(c caller, ns, name string) int {
		t.Helper()
		res := env.do(c, http.MethodGet, "/api/v1/x/probe/read/"+ns+"/"+name, nil)
		_ = res.Body.Close()
		route := env.do(c, http.MethodGet, "/api/v1/agents/"+ns+"/"+name, nil)
		_ = route.Body.Close()
		if (res.StatusCode == 200) != (route.StatusCode == 200) {
			t.Errorf("%s on %s/%s: the seam says %d, the route says %d", c.name, ns, name, res.StatusCode, route.StatusCode)
		}
		return res.StatusCode
	}
	// Who reads what while the organization is active.
	want := map[string][3]int{ // org/private, org/public, founder/own
		"anonymous":                         {404, 200, 404},
		"the founder":                       {200, 200, 200},
		"a member":                          {200, 200, 404},
		"a pending member":                  {404, 200, 404},
		"the security reviewer":             {404, 200, 404},
		"an outsider":                       {404, 200, 404},
		"a grantee":                         {200, 200, 404},
		"platform staff":                    {404, 200, 404},
		"a member's PAT without agent:read": {404, 200, 404},
		"a member's PAT with agent:read":    {200, 200, 404},
	}
	targets := [3][2]string{{org, "private"}, {org, "public"}, {founder, "own"}}
	for who, c := range callers {
		for i, tg := range targets {
			if got := read(c, tg[0], tg[1]); got != want[who][i] {
				t.Errorf("%s reads %s/%s: %d, want %d", who, tg[0], tg[1], got, want[who][i])
			}
		}
	}
	// A readable answer carries what the core knows of the agent.
	res := env.do(callers["a member"], http.MethodGet, "/api/v1/x/probe/read/"+org+"/private", nil)
	var ref struct {
		Namespace, Kind string
		Public          bool
	}
	decodeInto(t, res, &ref)
	if ref.Namespace != org || ref.Kind != "org" || ref.Public {
		t.Fatalf("the ref: %+v", ref)
	}
	// The organization's state: suspended by staff, each of its agents is
	// absent to everyone, the founder included; in the decommission hold
	// they read.
	env.doJSON(staffSess, http.MethodPost, "/api/v1/orgs/"+org+"/suspend", map[string]any{"reason": "the read seam's test"}, nil, http.StatusOK)
	for who, c := range map[string]caller{"the founder": admin, "an outsider": callers["an outsider"], "platform staff": staffSess} {
		for _, name := range []string{"private", "public"} {
			if got := read(c, org, name); got != 404 {
				t.Errorf("%s reads %s/%s of a suspended organization: %d, want 404", who, org, name, got)
			}
		}
	}
	if got := read(admin, founder, "own"); got != 200 {
		t.Errorf("the founder's own agent while their organization is suspended: %d, want 200", got)
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = 'decommissioning', decommission_at = now() + interval '7 days' WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}
	if got := read(callers["a member"], org, "private"); got != 200 {
		t.Errorf("a member reads the private agent of an organization in its hold: %d, want 200", got)
	}
	if got := read(callers["an outsider"], org, "public"); got != 200 {
		t.Errorf("an outsider reads the public agent of an organization in its hold: %d, want 200", got)
	}
	// Nothing at all: absent, not an error.
	if got := read(admin, org, "nothing"); got != 404 {
		t.Errorf("a missing agent: %d, want 404", got)
	}
	if got := read(admin, "nobody"+env.sfx, "nothing"); got != 404 {
		t.Errorf("a missing namespace: %d, want 404", got)
	}
}
