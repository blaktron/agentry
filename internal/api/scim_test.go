package api_test

import (
	"net/http"
	"testing"
)

// TestSCIMProvisionAndDeactivate covers §12.5: create a user, filter by
// userName, then PATCH active=false and assert the deactivation revokes the
// user's org-bound PATs and kills their sessions within the request.
func TestSCIMProvisionAndDeactivate(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("scim-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "scimorg" + env.sfx
	orgID := env.createOrg(sess, orgH)

	// Owner mints a SCIM token.
	var tok struct {
		Token string `json:"token"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/scim/tokens",
		map[string]any{}, &tok, http.StatusCreated)
	scim := caller{name: "scim", pat: tok.Token}

	// Create a user via SCIM.
	email := "alice-" + env.sfx + "@acme.example"
	var created struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}
	env.doJSON(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"active":   true,
	}, &created, http.StatusCreated)
	if created.ID == "" || !created.Active {
		t.Fatalf("unexpected create result: %+v", created)
	}
	userID := created.ID

	// Filter userName eq.
	var list struct {
		TotalResults int `json:"totalResults"`
		Resources    []struct {
			ID       string `json:"id"`
			UserName string `json:"userName"`
		} `json:"Resources"`
	}
	env.doJSON(scim, http.MethodGet, `/scim/v2/Users?filter=userName+eq+%22`+email+`%22`, nil, &list, http.StatusOK)
	if list.TotalResults != 1 || len(list.Resources) != 1 || list.Resources[0].ID != userID {
		t.Fatalf("userName filter mismatch: %+v", list)
	}

	// Give the user an org-bound PAT and a session, and confirm both work.
	boundPAT := env.insertPAT(userID, orgID, "user:profile")
	userSess := env.insertSession(userID)

	res := env.do(caller{name: "u-pat", pat: boundPAT}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("org-bound PAT before deactivate: got %d want 200", res.StatusCode)
	}
	res = env.do(caller{name: "u-sess", session: userSess}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session before deactivate: got %d want 200", res.StatusCode)
	}

	// Deactivate via SCIM PATCH active=false.
	env.doJSON(scim, http.MethodPatch, "/scim/v2/Users/"+userID, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	}, nil, http.StatusOK)

	// Org-bound PAT revoked.
	res = env.do(caller{name: "u-pat", pat: boundPAT}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("org-bound PAT after deactivate: got %d want 401", res.StatusCode)
	}
	// Session killed.
	res = env.do(caller{name: "u-sess", session: userSess}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after deactivate: got %d want 401", res.StatusCode)
	}
	// Membership removed (user no longer resolvable in the org's SCIM scope).
	res = env.do(scim, http.MethodGet, "/scim/v2/Users/"+userID, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("deactivated user still a member: got %d want 404", res.StatusCode)
	}
}

// TestSCIMDeleteDeactivates covers DELETE ⇒ same as deactivate (§12.5).
func TestSCIMDeleteDeactivates(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("scimd-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "scimdorg" + env.sfx
	env.createOrg(sess, orgH)
	var tok struct {
		Token string `json:"token"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/scim/tokens", map[string]any{}, &tok, http.StatusCreated)
	scim := caller{name: "scim", pat: tok.Token}

	email := "bob-" + env.sfx + "@acme.example"
	var created struct {
		ID string `json:"id"`
	}
	env.doJSON(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
		"userName": email, "emails": []map[string]any{{"value": email, "primary": true}}, "active": true,
	}, &created, http.StatusCreated)

	res := env.do(scim, http.MethodDelete, "/scim/v2/Users/"+created.ID, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("SCIM delete: got %d want 204", res.StatusCode)
	}
	res = env.do(scim, http.MethodGet, "/scim/v2/Users/"+created.ID, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted user still present: got %d want 404", res.StatusCode)
	}
}

// TestSCIMUnauthorized: no/invalid SCIM token is rejected.
func TestSCIMUnauthorized(t *testing.T) {
	env := newTestEnv(t)
	res := env.do(caller{name: "bad", pat: "agyscim_notarealtoken"}, http.MethodGet, "/scim/v2/Users", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid SCIM token: got %d want 401", res.StatusCode)
	}
}
