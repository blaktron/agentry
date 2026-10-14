package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
)

// The agent-publish seam and the agent route's canPublish (agentry#875):
// whether a principal may add a version to an agent, as the core's own
// routes decide it — the publish role over the namespace or a grant, a
// PAT's agent:publish, and the organization's gate for a write. The
// desktop's sign-in token carries agent:publish and never org:admin, so it
// never reads the maintainer's settings: this is what it offers Edit on
// (drafter-revisions R7), and what the hosted revision admits it by (R8).
// A probe extension answers 200 when the seam says publishable and 404
// otherwise, and each answer is checked against the route's canPublish.
func TestAgentPublishSeamAnswersAsTheCoreDoes(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("GET /publish/{ns}/{name}", func(w http.ResponseWriter, r *http.Request) {
				a, ok, err := s.AgentPublishable(r.Context(), api.PrincipalFrom(r.Context()), r.PathValue("ns"), r.PathValue("name"))
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

	admin := env.seedCaller("ps-founder")
	founder := admin.name
	member := env.register("ps-member")
	reviewer := env.seedCaller("ps-reviewer")
	outsider := env.seedCaller("ps-outsider")
	reader := env.seedCaller("ps-reader")
	maintainer := env.seedCaller("ps-maintainer")
	publisher := env.seedCaller("ps-publisher")
	org := "ps-org" + env.sfx
	orgID := env.createOrg(admin, org)
	env.joinOrg(admin, org, member)
	env.seedMembership(org, reviewer.name, "security_reviewer", "active")
	for _, a := range []struct{ ns, name, visibility string }{
		{org, "private", "private"}, {org, "public", "public"}, {founder, "own", "private"},
	} {
		env.doJSON(admin, http.MethodPost, "/api/v1/agents", map[string]any{"namespace": a.ns, "name": a.name, "visibility": a.visibility}, nil, http.StatusCreated)
	}
	// Grants on the organization's private agent: maintain ranks below
	// publish, so a maintain grantee may not add a version.
	env.doJSON(admin, http.MethodPut, "/api/v1/agents/"+org+"/private/grants/user/"+reader.name, map[string]any{"role": "read"}, nil, http.StatusNoContent)
	env.doJSON(admin, http.MethodPut, "/api/v1/agents/"+org+"/private/grants/user/"+maintainer.name, map[string]any{"role": "maintain"}, nil, http.StatusNoContent)
	env.doJSON(admin, http.MethodPut, "/api/v1/agents/"+org+"/private/grants/user/"+publisher.name, map[string]any{"role": "publish"}, nil, http.StatusNoContent)
	// The sign-in grant's own publishing scopes, and a token that may
	// administer the organization but not publish.
	_, signInLike := env.mintPAT(admin, "sign-in-like", "agent:read", "agent:publish", "repo:read", "repo:write", "user:profile", "run:read", "run:write")
	_, orgAdminOnly := env.mintPAT(admin, "org-admin-only", "agent:read", "org:admin")

	callers := map[string]caller{
		"anonymous": anonymous, "the founder": admin, "a member": env.login(member),
		"the security reviewer": reviewer, "an outsider": outsider, "a read grantee": reader,
		"a maintain grantee": maintainer, "a publish grantee": publisher,
		"the founder's sign-in-like token":    {name: "pat-signin", pat: signInLike},
		"the founder's token without publish": {name: "pat-orgadmin", pat: orgAdminOnly},
	}
	publishes := func(c caller, ns, name string, gated bool) int {
		t.Helper()
		res := env.do(c, http.MethodGet, "/api/v1/x/probe/publish/"+ns+"/"+name, nil)
		_ = res.Body.Close()
		if !gated {
			route := env.do(c, http.MethodGet, "/api/v1/agents/"+ns+"/"+name, nil)
			var body map[string]any
			if route.StatusCode == http.StatusOK {
				decodeInto(t, route, &body)
			} else {
				_ = route.Body.Close()
			}
			v, routeSays := body["canPublish"]
			if routeSays && v != true {
				t.Errorf("%s on %s/%s: canPublish is %v; it is true or absent", c.name, ns, name, v)
			}
			if (res.StatusCode == http.StatusOK) != routeSays {
				t.Errorf("%s on %s/%s: the seam says %d, the route's canPublish is %v", c.name, ns, name, res.StatusCode, routeSays)
			}
		}
		return res.StatusCode
	}
	want := map[string][3]int{ // org/private, org/public, founder/own
		"anonymous":                           {404, 404, 404},
		"the founder":                         {200, 200, 200},
		"a member":                            {200, 200, 404},
		"the security reviewer":               {404, 404, 404},
		"an outsider":                         {404, 404, 404},
		"a read grantee":                      {404, 404, 404},
		"a maintain grantee":                  {404, 404, 404},
		"a publish grantee":                   {200, 404, 404},
		"the founder's sign-in-like token":    {200, 200, 200},
		"the founder's token without publish": {404, 404, 404},
	}
	targets := [3][2]string{{org, "private"}, {org, "public"}, {founder, "own"}}
	for who, c := range callers {
		for i, tg := range targets {
			if got := publishes(c, tg[0], tg[1], false); got != want[who][i] {
				t.Errorf("%s publishes %s/%s: %d, want %d", who, tg[0], tg[1], got, want[who][i])
			}
		}
	}
	// The sign-in-like token publishes and does not maintain: the route
	// gives it canPublish and never the maintainer's settings.
	res := env.do(callers["the founder's sign-in-like token"], http.MethodGet, "/api/v1/agents/"+founder+"/own", nil)
	var own map[string]any
	decodeInto(t, res, &own)
	if _, ok := own["autoPublishTags"]; ok || own["canPublish"] != true {
		t.Fatalf("the sign-in-like token's view of its own agent: autoPublishTags present %v, canPublish %v", ok, own["canPublish"])
	}
	// A publishable answer carries what the core knows of the agent.
	res = env.do(callers["a publish grantee"], http.MethodGet, "/api/v1/x/probe/publish/"+org+"/private", nil)
	var ref struct {
		Namespace, Kind string
		Public          bool
	}
	decodeInto(t, res, &ref)
	if ref.Namespace != org || ref.Kind != "org" || ref.Public {
		t.Fatalf("the ref: %+v", ref)
	}
	// The organization's gate for a write: in its decommission hold its
	// agents read and are published to by no one.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = 'decommissioning', decommission_at = now() + interval '7 days' WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}
	for who, c := range map[string]caller{"the founder": admin, "a member": callers["a member"], "a publish grantee": callers["a publish grantee"]} {
		if got := publishes(c, org, "private", true); got != 404 {
			t.Errorf("%s publishes to the private agent of an organization in its hold: %d, want 404", who, got)
		}
	}
	if got := publishes(admin, founder, "own", false); got != 200 {
		t.Errorf("the founder's own agent while their organization is in its hold: %d, want 200", got)
	}
	// Nothing at all: absent, not an error.
	if got := publishes(admin, founder, "nothing", false); got != 404 {
		t.Errorf("a missing agent: %d, want 404", got)
	}
}
