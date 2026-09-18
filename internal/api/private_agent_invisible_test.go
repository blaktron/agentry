package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// TestPrivateAgentInvisibleToNonReaders pins the rule of agentry#313 (the
// operator, 2026-09-13): nobody but the private agent's readers can learn
// that a registry hosts it. Every by-name route answers a caller who cannot
// read the agent exactly as it answers a name that does not exist — 404,
// never the 401 that would say "sign in and this exists" — anonymous or
// signed in as a stranger, for reads and for writes; the advisories
// `?affecting=` path is the same gate; the owner still sees everything.
func TestPrivateAgentInvisibleToNonReaders(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("priv-owner")
	env.verifyEmail(owner)
	ownerSess := env.login(owner)
	stranger := env.register("priv-stranger")
	env.verifyEmail(stranger)
	strangerSess := env.login(stranger)
	env.doJSON(ownerSess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": owner, "name": "secret", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)

	// The problem document, less the instance path that names the request.
	get := func(c caller, path string) (int, map[string]any) {
		res := env.do(c, http.MethodGet, path, nil)
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		var doc map[string]any
		_ = json.Unmarshal(b, &doc)
		delete(doc, "instance")
		return res.StatusCode, doc
	}
	missingStatus, missingBody := get(anonymous, "/api/v1/agents/"+owner+"/no-such-agent")
	if missingStatus != http.StatusNotFound {
		t.Fatalf("missing agent: got %d", missingStatus)
	}

	for _, c := range []struct {
		name string
		c    caller
	}{{"anonymous", anonymous}, {"stranger", strangerSess}} {
		for _, path := range []string{
			"/api/v1/agents/" + owner + "/secret",
			"/api/v1/agents/" + owner + "/secret/versions",
			"/api/v1/advisories?affecting=" + owner + "/secret",
		} {
			st, body := get(c.c, path)
			if st != http.StatusNotFound {
				t.Fatalf("%s GET %s: got %d, want the missing agent's 404", c.name, path, st)
			}
			if !reflect.DeepEqual(body, missingBody) {
				t.Fatalf("%s GET %s: the 404 differs from a missing agent's:\n%v\nvs\n%v", c.name, path, body, missingBody)
			}
		}
		// A write on a private agent by a non-reader is a 404 too, not a
		// 401 or 403 that would confirm the name.
		res := env.do(c.c, http.MethodPatch, "/api/v1/agents/"+owner+"/secret", map[string]any{"summary": "x"})
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s PATCH private agent: got %d, want 404", c.name, res.StatusCode)
		}
	}

	// The namespace listing agrees with the by-name route: the stranger
	// and the anonymous caller see no private name in it, the owner does.
	list := func(c caller) []string {
		var rows []struct {
			Name string `json:"name"`
		}
		env.doJSON(c, http.MethodGet, "/api/v1/agents?namespace="+owner, nil, &rows, http.StatusOK)
		names := make([]string, 0, len(rows))
		for _, r := range rows {
			names = append(names, r.Name)
		}
		return names
	}
	for _, c := range []caller{anonymous, strangerSess} {
		for _, n := range list(c) {
			if n == "secret" {
				t.Fatalf("%s: the namespace listing names the private agent", c.name)
			}
		}
	}
	if names := list(ownerSess); len(names) == 0 || names[0] != "secret" {
		t.Fatalf("owner listing: %v", names)
	}

	// The owner reads it, and its (empty) advisory list.
	if st, _ := get(ownerSess, "/api/v1/agents/"+owner+"/secret"); st != http.StatusOK {
		t.Fatalf("owner GET: got %d", st)
	}
	if st, _ := get(ownerSess, "/api/v1/advisories?affecting="+owner+"/secret"); st != http.StatusOK {
		t.Fatalf("owner advisories: got %d", st)
	}

	// A public agent keeps the conventional answers: anonymous reads it,
	// and an anonymous write is a 401 (the name is no secret).
	env.doJSON(ownerSess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": owner, "name": "open", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	if st, _ := get(anonymous, "/api/v1/agents/"+owner+"/open"); st != http.StatusOK {
		t.Fatalf("anonymous GET public: got %d", st)
	}
	res := env.do(anonymous, http.MethodPatch, "/api/v1/agents/"+owner+"/open", map[string]any{"summary": "x"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous PATCH public: got %d, want 401", res.StatusCode)
	}
}

// TestPrivateOrgAgentReaderSetIsEveryActiveMember: DEV-101's reader set,
// widened by agentry#362. An organization's private agent is readable by
// its active members — that is what a seat buys — and by nobody else: a
// pending member, whom no admin has approved, gets the same 404 an
// outsider does, and the same one a name that does not exist gets.
func TestPrivateOrgAgentReaderSetIsEveryActiveMember(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("pv-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "pvorg" + env.sfx
	env.createOrg(admin, orgH)
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "hidden", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)

	memberH := env.register("pv-member")
	env.joinOrg(admin, orgH, memberH)
	member := env.login(memberH)

	pendingH := env.register("pv-pending")
	env.verifyEmail(pendingH)
	env.seedMembership(orgH, pendingH, "member", "pending")
	pending := env.login(pendingH)

	outsiderH := env.register("pv-outsider")
	env.verifyEmail(outsiderH)
	outsider := env.login(outsiderH)

	get := func(c caller, path string) (int, map[string]any) {
		res := env.do(c, http.MethodGet, path, nil)
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		var doc map[string]any
		_ = json.Unmarshal(b, &doc)
		delete(doc, "instance")
		return res.StatusCode, doc
	}
	_, missingBody := get(anonymous, "/api/v1/agents/"+orgH+"/no-such-agent")

	// The member reads it and may release it: a seat buys a share of the
	// organization's agents (D6, D19).
	if st, _ := get(member, "/api/v1/agents/"+orgH+"/hidden"); st != http.StatusOK {
		t.Fatalf("an active member reading the org's private agent: got %d, want 200", st)
	}

	// The pending member and the outsider get a missing name's 404, byte
	// for byte — the agent's existence is not something either can learn.
	for _, c := range []struct {
		name string
		c    caller
	}{{"a pending member", pending}, {"an outsider", outsider}, {"anonymous", anonymous}} {
		st, body := get(c.c, "/api/v1/agents/"+orgH+"/hidden")
		if st != http.StatusNotFound {
			t.Fatalf("%s reading the org's private agent: got %d, want 404", c.name, st)
		}
		if !reflect.DeepEqual(body, missingBody) {
			t.Fatalf("%s: the 404 differs from a missing agent's:\n%v\nvs\n%v", c.name, body, missingBody)
		}
	}
}

// TestMembershipConfersPublishButNotTheAgentItself: what a member may do
// with the organization's agents, and where the line is (D19). A member
// creates and releases; only an admin changes visibility, deletes, or
// hands out a grant — handing someone access to a private agent is a
// disclosure, so it sits with the acts that decide what the agent is.
func TestMembershipConfersPublishButNotTheAgentItself(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("mc-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "mcorg" + env.sfx
	env.createOrg(admin, orgH)
	memberH := env.register("mc-member")
	env.joinOrg(admin, orgH, memberH)
	member := env.login(memberH)

	// A member creates an agent in the organization's namespace.
	env.doJSON(member, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "shared", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)

	// And may change its settings — that is what maintain is for.
	env.doJSON(member, http.MethodPatch, "/api/v1/agents/"+orgH+"/shared",
		map[string]any{"summary": "a shared thing"}, nil, http.StatusOK)

	// But not what the agent is. Each of these is the admins'.
	res := env.do(member, http.MethodPatch, "/api/v1/agents/"+orgH+"/shared", map[string]any{"visibility": "public"})
	if code, _, detail := problemOf(t, res); code != http.StatusForbidden || !strings.Contains(detail, "administrators") {
		t.Fatalf("a member making the agent public: %d %q, want 403 naming the administrators", code, detail)
	}
	res = env.do(member, http.MethodDelete, "/api/v1/agents/"+orgH+"/shared", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a member deleting the org's agent: %d, want 403", res.StatusCode)
	}
	res = env.do(member, http.MethodPut, "/api/v1/agents/"+orgH+"/shared/grants/user/"+adminH, map[string]any{"role": "read"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a member granting access to the org's private agent: %d, want 403", res.StatusCode)
	}
	res = env.do(member, http.MethodGet, "/api/v1/agents/"+orgH+"/shared/grants", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a member reading the org's grants: %d, want 403", res.StatusCode)
	}

	// The admin does each of them.
	env.doJSON(admin, http.MethodPut, "/api/v1/agents/"+orgH+"/shared/grants/user/"+memberH,
		map[string]any{"role": "read"}, nil, http.StatusNoContent)
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/shared",
		map[string]any{"visibility": "public"}, nil, http.StatusOK)
	env.doJSON(admin, http.MethodDelete, "/api/v1/agents/"+orgH+"/shared", nil, nil, http.StatusNoContent)

	// Creating a PUBLIC agent is the same exposure decision as making one
	// public, so it is the admins' too — otherwise "create it public"
	// would be the way round the rule above.
	res = env.do(member, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "open-one", "modes": []string{"autonomous"}, "visibility": "public"})
	if code, _, detail := problemOf(t, res); code != http.StatusUnprocessableEntity || !strings.Contains(detail, "administrators") {
		t.Fatalf("a member creating a public agent in the org: %d %q, want a refusal naming the administrators", code, detail)
	}

	// Allowing force pushes rewrites history the rest of the organization
	// is working from: also the admins'.
	env.doJSON(member, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "history", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	res = env.do(member, http.MethodPatch, "/api/v1/agents/"+orgH+"/history", map[string]any{"allowForcePush": true})
	if code, _, _ := problemOf(t, res); code != http.StatusForbidden {
		t.Fatalf("a member allowing force pushes: %d, want 403", code)
	}
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/history",
		map[string]any{"allowForcePush": true}, nil, http.StatusOK)

	// A pending member creates nothing here.
	pendingH := env.register("mc-pending")
	env.verifyEmail(pendingH)
	env.seedMembership(orgH, pendingH, "member", "pending")
	res = env.do(env.login(pendingH), http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "nope", "modes": []string{"autonomous"}})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a pending member creating an agent in the org: %d, want 403", res.StatusCode)
	}
}
