package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
)

// The principal seam (agentry#838): an extension that holds a user by id —
// a hosted revision's owner, when the sandbox host fetches the release long
// after the create — asks the core for the principal it would hold for that
// user now, and puts it to the agent seams. The answer must be the core's:
// for every user and agent it is what the user's own session is answered,
// and a role taken away after the first answer is gone from the next. A
// probe extension answers 200 when the seam says the action is allowed, 404
// when it is not, and 410 when the core has no principal for the user.
func TestPrincipalForUserAnswersTheRoleAsItIsNow(t *testing.T) {
	var srv *api.Server
	act := func(s *api.Server, r *http.Request, p *auth.Principal) (bool, error) {
		var err error
		var ok bool
		switch r.PathValue("action") {
		case "read":
			_, ok, err = s.AgentReadable(r.Context(), p, r.PathValue("ns"), r.PathValue("name"))
		case "maintain":
			_, ok, err = s.AgentMaintainable(r.Context(), p, r.PathValue("ns"), r.PathValue("name"))
		case "publish":
			_, ok, err = s.AgentPublishable(r.Context(), p, r.PathValue("ns"), r.PathValue("name"))
		}
		return ok, err
	}
	answer := func(w http.ResponseWriter, ok bool, err error) {
		switch {
		case err != nil:
			w.WriteHeader(http.StatusInternalServerError)
		case !ok:
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}
	env := newTestEnvWith(t, func(s *api.Server) {
		srv = s
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			// As the caller: the live principal of the request.
			mux.HandleFunc("GET /self/{action}/{ns}/{name}", func(w http.ResponseWriter, r *http.Request) {
				ok, err := act(s, r, api.PrincipalFrom(r.Context()))
				answer(w, ok, err)
			})
			// As a user held by id, whoever calls.
			mux.HandleFunc("GET /user/{id}/{action}/{ns}/{name}", func(w http.ResponseWriter, r *http.Request) {
				id, err := uuid.Parse(r.PathValue("id"))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				p, found, err := s.PrincipalForUser(r.Context(), id)
				switch {
				case err != nil:
					w.WriteHeader(http.StatusInternalServerError)
					return
				case !found:
					w.WriteHeader(http.StatusGone)
					return
				}
				ok, err := act(s, r, p)
				answer(w, ok, err)
			})
		})
	})
	ctx := context.Background()

	founder := env.register("ps-founder")
	env.verifyEmail(founder)
	member := env.register("ps-member")
	pending := env.register("ps-pending")
	reader := env.register("ps-reader")
	maintainer := env.register("ps-maintainer")
	publisher := env.register("ps-publisher")
	outsider := env.register("ps-outsider")
	admin := env.login(founder)
	org := "ps-org" + env.sfx
	orgID := env.createOrg(admin, org)
	env.joinOrg(admin, org, member)
	env.seedMembership(org, pending, "member", "pending")
	for _, a := range []struct{ ns, name, visibility string }{
		{org, "private", "private"}, {org, "public", "public"}, {founder, "own", "private"},
	} {
		env.doJSON(admin, http.MethodPost, "/api/v1/agents", map[string]any{"namespace": a.ns, "name": a.name, "visibility": a.visibility}, nil, http.StatusCreated)
	}
	for handle, role := range map[string]string{reader: "read", maintainer: "maintain", publisher: "publish"} {
		env.doJSON(admin, http.MethodPut, "/api/v1/agents/"+org+"/private/grants/user/"+handle, map[string]any{"role": role}, nil, http.StatusNoContent)
	}
	users := []string{founder, member, pending, reader, maintainer, publisher, outsider}
	sessions := map[string]caller{founder: admin}
	for _, h := range users[1:] {
		sessions[h] = env.login(h)
	}
	targets := [][2]string{{org, "private"}, {org, "public"}, {founder, "own"}}
	actions := []string{"read", "maintain", "publish"}

	asUser := func(handle, action, ns, name string) int {
		t.Helper()
		res := env.do(anonymous, http.MethodGet, "/api/v1/x/probe/user/"+env.userID(handle)+"/"+action+"/"+ns+"/"+name, nil)
		_ = res.Body.Close()
		return res.StatusCode
	}
	asSelf := func(c caller, action, ns, name string) int {
		t.Helper()
		res := env.do(c, http.MethodGet, "/api/v1/x/probe/self/"+action+"/"+ns+"/"+name, nil)
		_ = res.Body.Close()
		return res.StatusCode
	}

	// The principal for a user is answered as the user's own session is,
	// for every action on every agent.
	allowed := 0
	for _, h := range users {
		for _, tg := range targets {
			for _, a := range actions {
				byID, bySession := asUser(h, a, tg[0], tg[1]), asSelf(sessions[h], a, tg[0], tg[1])
				if byID != bySession {
					t.Errorf("%s %s %s/%s: by id %d, by their session %d", h, a, tg[0], tg[1], byID, bySession)
				}
				if byID == http.StatusOK {
					allowed++
				}
			}
		}
	}
	// The comparison means something only if both answers occur.
	if allowed == 0 || allowed == len(users)*len(targets)*len(actions) {
		t.Fatalf("%d of %d answers allowed: the matrix does not discriminate", allowed, len(users)*len(targets)*len(actions))
	}
	for _, c := range []struct {
		who, action string
		want        int
	}{
		{member, "maintain", 200}, {maintainer, "maintain", 200}, {publisher, "publish", 200},
		{publisher, "maintain", 200}, {maintainer, "publish", 404}, {reader, "maintain", 404},
		{pending, "read", 404}, {outsider, "read", 404},
	} {
		if got := asUser(c.who, c.action, org, "private"); got != c.want {
			t.Errorf("%s %s the private agent by id: %d, want %d", c.who, c.action, got, c.want)
		}
	}

	// A role taken away after that answer is gone from the next: the
	// member leaves the organization, the grants are revoked.
	env.doJSON(admin, http.MethodDelete, "/api/v1/orgs/"+org+"/members/"+member, nil, nil, http.StatusNoContent)
	env.doJSON(admin, http.MethodDelete, "/api/v1/agents/"+org+"/private/grants/user/"+maintainer, nil, nil, http.StatusNoContent)
	env.doJSON(admin, http.MethodDelete, "/api/v1/agents/"+org+"/private/grants/user/"+publisher, nil, nil, http.StatusNoContent)
	for _, c := range []struct{ who, action string }{
		{member, "maintain"}, {member, "publish"}, {member, "read"},
		{maintainer, "maintain"}, {maintainer, "read"},
		{publisher, "publish"}, {publisher, "maintain"},
	} {
		if got := asUser(c.who, c.action, org, "private"); got != http.StatusNotFound {
			t.Errorf("%s %s the private agent by id after the role was taken away: %d, want 404", c.who, c.action, got)
		}
	}
	// The founder, untouched, still maintains and publishes.
	for _, a := range []string{"maintain", "publish"} {
		if got := asUser(founder, a, org, "private"); got != http.StatusOK {
			t.Errorf("the founder %s the private agent by id: %d, want 200", a, got)
		}
	}

	// The organization's gate for a write holds for a principal by id as
	// for a session: in its decommission hold, no one maintains.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = 'decommissioning', decommission_at = now() + interval '7 days' WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}
	if got := asUser(founder, "maintain", org, "private"); got != http.StatusNotFound {
		t.Errorf("the founder maintains by id in the organization's hold: %d, want 404", got)
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = 'active', decommission_at = NULL WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}

	// An account that is not active, and one that does not exist, have no
	// principal.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE users SET state = 'suspended' WHERE id = $1`, env.userID(outsider)); err != nil {
		t.Fatal(err)
	}
	if got := asUser(outsider, "read", org, "public"); got != http.StatusGone {
		t.Errorf("a suspended account's principal: %d, want 410", got)
	}
	res := env.do(anonymous, http.MethodGet, "/api/v1/x/probe/user/"+uuid.NewString()+"/read/"+org+"/public", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusGone {
		t.Errorf("an account that does not exist: %d, want 410", res.StatusCode)
	}

	// What it is: the account, Via "user", no scopes, no session, no SSO.
	p, ok, err := srv.PrincipalForUser(ctx, uuid.MustParse(env.userID(founder)))
	if err != nil || !ok {
		t.Fatalf("the founder's principal: %v, %v", ok, err)
	}
	if p.Via != "user" || p.Anonymous || p.Handle != founder || p.Scopes != nil ||
		p.SessionID != uuid.Nil || p.PATID != uuid.Nil || !p.EmailVerified {
		t.Errorf("the founder's principal: %+v", p)
	}
	if p.Role(uuid.MustParse(orgID)) != auth.RoleAdmin {
		t.Errorf("the founder's role in the organization: %q, want admin", p.Role(uuid.MustParse(orgID)))
	}
	if p.SSOSatisfied(uuid.MustParse(orgID), time.Hour) {
		t.Error("a principal by id satisfies enforced SSO")
	}
}

// The schedule credential (agentry#1002, plan quickagent-scheduling.md
// §6): what a schedule's fire starts its owner's run with. It is the
// owner's account as it is now, narrowed to auth.ScheduleScopes — so an
// organization admin's schedule reads the organization's private agent and
// cannot maintain or publish it — with no platform-staff standing, no
// session, no token and no SSO; a suspended owner's schedule has none.
func TestPrincipalForScheduleIsTheOwnersNarrowCredential(t *testing.T) {
	var srv *api.Server
	env := newTestEnvWith(t, func(s *api.Server) { srv = s })
	ctx := context.Background()

	founder := env.register("sc-founder")
	env.verifyEmail(founder)
	env.makePlatformStaff(t, founder)
	admin := env.login(founder)
	org := "sc-org" + env.sfx
	orgID := uuid.MustParse(env.createOrg(admin, org))
	env.doJSON(admin, http.MethodPost, "/api/v1/agents", map[string]any{"namespace": org, "name": "private", "visibility": "private"}, nil, http.StatusCreated)
	owner := uuid.MustParse(env.userID(founder))
	schedule := uuid.New()

	p, ok, err := srv.PrincipalForSchedule(ctx, owner, schedule)
	if err != nil || !ok {
		t.Fatalf("the founder's schedule credential: %v, %v", ok, err)
	}
	if p.Via != "schedule" || p.ScheduleID != schedule || p.UserID != owner || p.Handle != founder || p.Anonymous ||
		p.SessionID != uuid.Nil || p.PATID != uuid.Nil || p.PlatformStaff || !p.EmailVerified {
		t.Errorf("the founder's schedule credential: %+v", p)
	}
	if strings.Join(p.Scopes, ",") != strings.Join(auth.ScheduleScopes(), ",") {
		t.Errorf("its scopes: %v, want %v", p.Scopes, auth.ScheduleScopes())
	}
	if p.Role(orgID) != auth.RoleAdmin {
		t.Errorf("its role in the organization: %q, want the owner's, admin", p.Role(orgID))
	}
	if p.SSOSatisfied(orgID, time.Hour) {
		t.Error("a schedule credential satisfies enforced SSO")
	}

	// The agent seams answer it as a token with those scopes: read on the
	// role, nothing the scopes do not carry.
	if _, ok, err := srv.AgentReadable(ctx, p, org, "private"); err != nil || !ok {
		t.Errorf("the schedule reads its owner's organization's private agent: %v, %v", ok, err)
	}
	if _, ok, err := srv.AgentMaintainable(ctx, p, org, "private"); err != nil || ok {
		t.Errorf("the schedule maintains the agent: %v, %v; a schedule only starts runs", ok, err)
	}
	if _, ok, err := srv.AgentPublishable(ctx, p, org, "private"); err != nil || ok {
		t.Errorf("the schedule publishes to the agent: %v, %v; a schedule only starts runs", ok, err)
	}
	// The owner's principal by id is untouched by the narrowing.
	if u, ok, err := srv.PrincipalForUser(ctx, owner); err != nil || !ok || u.Via != "user" || u.Scopes != nil || !u.PlatformStaff {
		t.Errorf("the owner's principal by id after a schedule credential: %+v %v %v", u, ok, err)
	}

	// A credential that names no schedule is refused; an account that does
	// not exist, or is not active, has none.
	if _, _, err := srv.PrincipalForSchedule(ctx, owner, uuid.Nil); err == nil {
		t.Error("a schedule credential with no schedule id was minted")
	}
	if _, ok, err := srv.PrincipalForSchedule(ctx, uuid.New(), schedule); err != nil || ok {
		t.Errorf("an account that does not exist: %v, %v, want none", ok, err)
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE users SET state = 'suspended' WHERE id = $1`, owner); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := srv.PrincipalForSchedule(ctx, owner, schedule); err != nil || ok {
		t.Errorf("a suspended owner's schedule credential: %v, %v, want none", ok, err)
	}
}
