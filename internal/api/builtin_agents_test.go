package api_test

// Built-in agents (agentry#737): the packages the Agentry CLI embeds are
// published under the platform's own organization for reading
// (agentry-cli#470, DR-50), and the directory labels them Built-in in
// place of their run modes. The label is the platform's to say: only
// platform staff set or clear it, never the namespace's own
// administrators, and it marks an agent only in a first-party namespace.
// Every place the registry describes an agent serves it.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestOnlyStaffMarkABuiltInAgentInTheFirstPartyNamespace(t *testing.T) {
	env := newTestEnv(t)
	staffH := env.register("bt-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)

	// The first-party organization: a reserved handle only staff may take,
	// shared by every test in the package, so made once.
	if res := env.do(staff, http.MethodGet, "/api/v1/orgs/agentry", nil); res.StatusCode == http.StatusNotFound {
		env.createOrg(staff, "agentry")
	} else if res.StatusCode != http.StatusOK {
		t.Fatalf("reading the first-party organization: %d", res.StatusCode)
	}
	env.seedMembership("agentry", staffH, "admin", "active")

	// An administrator of the first-party organization who is not staff.
	adminH := env.register("bt-admin")
	env.verifyEmail(adminH)
	env.seedMembership("agentry", adminH, "admin", "active")
	admin := env.login(adminH)

	name := "bt-drafter-" + env.sfx
	summary := "Drafts things " + env.sfx
	env.publishSearchable(t, staff, "agentry", name, summary, "The built-in "+env.sfx)

	patch := func(c caller, ns, n string, body map[string]any) (int, string) {
		code, slug, _ := problemOf(t, env.do(c, http.MethodPatch, "/api/v1/agents/"+ns+"/"+n, body))
		return code, slug
	}
	var got struct {
		ID      string `json:"id"`
		Builtin *bool  `json:"builtin"`
	}
	// The audit's record of the last change to builtin on this agent, if
	// any.
	lastBuiltinAudit := func() (bool, bool) {
		t.Helper()
		var v *bool
		err := env.st.Pool().QueryRow(context.Background(),
			`SELECT (detail->>'builtin')::boolean FROM audit_events
			 WHERE action = 'agent.update' AND target_id = $1 AND detail ? 'builtin'
			 ORDER BY occurred_at DESC, id DESC LIMIT 1`, got.ID).Scan(&v)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return v != nil && *v, true
	}

	// Unmarked by default, and said so to every reader.
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/agentry/"+name, nil, &got, http.StatusOK)
	if got.Builtin == nil || *got.Builtin {
		t.Fatalf("a new agent's builtin = %v, want present and false", got.Builtin)
	}

	// The namespace's own administrator may not mark it, with a session
	// or with a token that carries every scope maintain needs.
	if code, _ := patch(admin, "agentry", name, map[string]any{"builtin": true}); code != http.StatusForbidden {
		t.Fatalf("a non-staff administrator marking it: %d, want 403", code)
	}
	_, adminTok := env.mintPAT(admin, "bt-admin-"+env.sfx, "agent:read", "agent:publish", "org:admin")
	if code, _ := patch(caller{name: "admin-pat", pat: adminTok}, "agentry", name, map[string]any{"builtin": true}); code != http.StatusForbidden {
		t.Fatalf("a non-staff administrator's token marking it: %d, want 403", code)
	}

	// Outside a first-party namespace, not even staff: another staff
	// member's own organization (a person belongs to one at a time).
	otherH := env.register("bt-staff2")
	env.verifyEmail(otherH)
	env.makePlatformStaff(t, otherH)
	other := env.login(otherH)
	orgH := "btorg" + env.sfx
	env.createOrg(other, orgH)
	env.doJSON(other, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "lookalike", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	if code, s := patch(other, orgH, "lookalike", map[string]any{"builtin": true}); code != http.StatusConflict || s != "builtin-first-party" {
		t.Fatalf("staff marking an agent outside the first-party namespace: %d %s, want 409 builtin-first-party", code, s)
	}

	// Staff mark it, with a token as the CLI's release does
	// (agentry-cli#474); the change is audited, and the agent, the
	// namespace listing and search all say so.
	_, staffTok := env.mintPAT(staff, "bt-staff-"+env.sfx, "agent:read", "agent:publish", "org:admin")
	env.doJSON(caller{name: "staff-pat", pat: staffTok}, http.MethodPatch, "/api/v1/agents/agentry/"+name, map[string]any{"builtin": true}, &got, http.StatusOK)
	if got.Builtin == nil || !*got.Builtin {
		t.Fatalf("marked, the agent says %v", got.Builtin)
	}
	if v, ok := lastBuiltinAudit(); !ok || !v {
		t.Fatalf("marking it is not audited: %v %v", v, ok)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/agentry/"+name, nil, &got, http.StatusOK)
	if got.Builtin == nil || !*got.Builtin {
		t.Fatalf("marked, an anonymous read says %v", got.Builtin)
	}
	var listing []struct {
		Name    string `json:"name"`
		Builtin *bool  `json:"builtin"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents?namespace=agentry", nil, &listing, http.StatusOK)
	found := false
	for _, a := range listing {
		if a.Name == name {
			found = true
			if a.Builtin == nil || !*a.Builtin {
				t.Fatalf("the namespace listing says builtin %v", a.Builtin)
			}
		}
	}
	if !found {
		t.Fatalf("%s is not in the namespace listing", name)
	}
	var hits struct {
		Results []struct {
			Name    string `json:"name"`
			Builtin *bool  `json:"builtin"`
		} `json:"results"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+env.sfx, nil, &hits, http.StatusOK)
	found = false
	for _, h := range hits.Results {
		if h.Name == name {
			found = true
			if h.Builtin == nil || !*h.Builtin {
				t.Fatalf("the search hit says builtin %v", h.Builtin)
			}
		}
	}
	if !found {
		t.Fatalf("%s is not among the search hits: %+v", name, hits.Results)
	}

	// Clearing it is staff's too.
	if code, _ := patch(admin, "agentry", name, map[string]any{"builtin": false}); code != http.StatusForbidden {
		t.Fatalf("a non-staff administrator clearing it: %d, want 403", code)
	}
	env.doJSON(staff, http.MethodPatch, "/api/v1/agents/agentry/"+name, map[string]any{"builtin": false}, &got, http.StatusOK)
	if got.Builtin == nil || *got.Builtin {
		t.Fatalf("cleared, the agent says %v", got.Builtin)
	}

	if v, ok := lastBuiltinAudit(); !ok || v {
		t.Fatalf("clearing it is not audited: %v %v", v, ok)
	}

	// A non-staff request that names the value the agent already has is
	// not refused, so the settings an administrator may change pass beside
	// it; but its value is never written, so it could not undo a staff
	// change that lands between the handler's read and its write. The
	// audit says what was written: nothing about builtin.
	env.doJSON(staff, http.MethodPatch, "/api/v1/agents/agentry/"+name, map[string]any{"builtin": true}, &got, http.StatusOK)
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/agentry/"+name, map[string]any{"builtin": true, "summary": summary}, &got, http.StatusOK)
	if got.Builtin == nil || !*got.Builtin {
		t.Fatalf("after an administrator's no-op, the agent says %v", got.Builtin)
	}
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'agent.update' AND target_id = $1
		 AND detail ? 'summary' AND detail ? 'builtin'`, got.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("an administrator's builtin value was written (%d audited changes carry it)", n)
	}
}
