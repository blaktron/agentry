package api_test

// The owner actions under the sign-in grant's agent:manage (agentry#993;
// plan forks-and-publisher.md M6): a token with the grant's scopes makes
// its namespace's QuickAgent private and public, retires, restores and
// deletes it, at the administrators' rung only, and reaches none of the
// agent's other settings.

import (
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/auth"
)

func TestSignInGrantTakesTheOwnerActions(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("mng-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	_, tok := env.mintPAT(sess, "sign-in", auth.SignInGrantScopes()...)
	grant := caller{name: "sign-in", pat: tok}
	_ = env.publishedAgent(sess, owner, "managed")
	path := "/api/v1/agents/" + owner + "/managed"

	var a lifecycleAgent
	env.doJSON(grant, http.MethodPatch, path, map[string]any{"visibility": "private"}, &a, http.StatusOK)
	if a.Visibility != "private" {
		t.Fatalf("make private: visibility %q", a.Visibility)
	}
	env.doJSON(grant, http.MethodPatch, path, map[string]any{"visibility": "public"}, &a, http.StatusOK)
	if a.Visibility != "public" {
		t.Fatalf("make public: visibility %q", a.Visibility)
	}
	env.doJSON(grant, http.MethodPost, path+"/retire", nil, &a, http.StatusOK)
	if a.RetiredAt == nil {
		t.Fatal("retire: retiredAt unset")
	}
	var restored lifecycleAgent
	env.doJSON(grant, http.MethodPost, path+"/restore", nil, &restored, http.StatusOK)
	if restored.RetiredAt != nil || restored.Visibility != "public" {
		t.Fatalf("restore: %+v", restored)
	}

	// The settings stay org:admin's: a field beside visibility, or alone,
	// is refused, and nothing changes.
	for _, body := range []map[string]any{
		{"summary": "changed"},
		{"visibility": "private", "summary": "changed"},
		{"autoPublishTags": true},
		{"visibility": "private", "autoPublishTags": false},
		{"visibility": "private", "allowForcePush": true},
	} {
		if code := statusOf(t, env.do(grant, http.MethodPatch, path, body)); code != http.StatusForbidden {
			t.Fatalf("PATCH %v with the sign-in grant: got %d want 403", body, code)
		}
	}
	var after lifecycleAgent
	env.doJSON(anonymous, http.MethodGet, path, nil, &after, http.StatusOK)
	if after.Visibility != "public" {
		t.Fatalf("a refused PATCH changed visibility to %q", after.Visibility)
	}
	// So do the grants on it.
	if code := statusOf(t, env.do(grant, http.MethodGet, path+"/grants", nil)); code != http.StatusForbidden {
		t.Fatalf("grants with the sign-in grant: got %d want 403", code)
	}

	// Delete with history asks for the name, then leaves the tombstone.
	if code, slug, _ := problemOf(t, env.do(grant, http.MethodDelete, path, nil)); code != http.StatusUnprocessableEntity || slug != "confirm-name" {
		t.Fatalf("delete without the name: %d %s, want 422 confirm-name", code, slug)
	}
	if code := statusOf(t, env.do(grant, http.MethodDelete, path+"?confirm=managed", nil)); code != http.StatusNoContent {
		t.Fatalf("delete with the sign-in grant: got %d want 204", code)
	}
	if code := statusOf(t, env.do(sess, http.MethodGet, path, nil)); code != http.StatusNotFound {
		t.Fatalf("a deleted agent read by its owner: got %d want 404", code)
	}
}

// TestAgentManageKeepsTheAdministratorsRung: an organization's member holds
// publish, so the sign-in grant takes no owner action on the
// organization's QuickAgents, and an outsider's grant none on anyone's;
// the organization's admin takes them with the same grant.
func TestAgentManageKeepsTheAdministratorsRung(t *testing.T) {
	env := newTestEnv(t)
	admin := env.register("mng-adm")
	env.verifyEmail(admin)
	adminSess := env.login(admin)
	org := "mng-org-" + env.sfxDigits()
	env.doJSON(adminSess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "Manage Org"}, nil, http.StatusCreated)
	member := env.register("mng-mem")
	env.joinOrg(adminSess, org, member)
	outsider := env.register("mng-out")
	env.verifyEmail(outsider)
	env.doJSON(adminSess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": org, "name": "kept", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	path := "/api/v1/agents/" + org + "/kept"

	grantOf := func(h string) caller {
		_, tok := env.mintPAT(env.login(h), "sign-in-"+h, auth.SignInGrantScopes()...)
		return caller{name: h, pat: tok}
	}
	for _, c := range []caller{grantOf(member), grantOf(outsider)} {
		for _, req := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPost, path + "/retire", nil},
			{http.MethodPost, path + "/restore", nil},
			{http.MethodPatch, path, map[string]any{"visibility": "private"}},
			{http.MethodDelete, path + "?confirm=kept", nil},
		} {
			if code := statusOf(t, env.do(c, req.method, req.path, req.body)); code != http.StatusForbidden {
				t.Fatalf("%s %s as %s with the sign-in grant: got %d want 403", req.method, req.path, c.name, code)
			}
		}
	}
	adminGrant := grantOf(admin)
	env.doJSON(adminGrant, http.MethodPatch, path, map[string]any{"visibility": "private"}, nil, http.StatusOK)
	env.doJSON(adminGrant, http.MethodPost, path+"/retire", nil, nil, http.StatusOK)
	env.doJSON(adminGrant, http.MethodPost, path+"/restore", nil, nil, http.StatusOK)
	// No version row: deleted outright.
	if code := statusOf(t, env.do(adminGrant, http.MethodDelete, path, nil)); code != http.StatusNoContent {
		t.Fatalf("the admin's delete with the sign-in grant: got %d want 204", code)
	}
}
