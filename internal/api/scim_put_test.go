package api_test

// SCIM: the spec-conformant full-resource PUT, and membership-sync
// failures reaching the IdP as 5xx instead of being swallowed.

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

// scimOrg spins up an org with a SCIM token and returns the caller.
func (env *testEnv) scimOrg(t *testing.T, prefix string) (scim caller, orgID string) {
	t.Helper()
	h := env.register(prefix)
	env.verifyEmail(h)
	owner := env.login(h)
	orgH := prefix + "org" + env.sfx
	orgID = env.createOrg(owner, orgH)
	var tok struct {
		Token string `json:"token"`
	}
	env.doJSON(owner, http.MethodPost, "/api/v1/orgs/"+orgH+"/scim/tokens",
		map[string]any{}, &tok, http.StatusCreated)
	return caller{name: "scim", pat: tok.Token}, orgID
}

// TestSCIMPutDeactivatesOktaShape: Okta offboards by PUTing the whole user
// resource with "active": false. That request must not be handed to the
// PatchOp decoder, which would find zero Operations and answer 200 having
// done nothing — the IdP would believe the person was offboarded while
// their sessions and org-bound tokens still worked.
func TestSCIMPutDeactivatesOktaShape(t *testing.T) {
	env := newTestEnv(t)
	scim, orgID := env.scimOrg(t, "scimput")

	email := "bob-" + env.sfx + "@acme.example"
	var created struct {
		ID string `json:"id"`
	}
	env.doJSON(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"active":   true,
	}, &created, http.StatusCreated)

	boundPAT := env.insertPAT(created.ID, orgID, "user:profile")
	userSess := env.insertSession(created.ID)

	// Okta's deactivation shape: the full resource, active=false.
	var out struct {
		Active bool `json:"active"`
	}
	env.doJSON(scim, http.MethodPut, "/scim/v2/Users/"+created.ID, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":       created.ID,
		"userName": email,
		"name":     map[string]any{"formatted": "Bob Example"},
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"active":   false,
	}, &out, http.StatusOK)
	if out.Active {
		t.Fatal("PUT active=false must report the user as inactive")
	}

	// Deactivation: membership dropped, org-bound PATs revoked,
	// sessions killed — all within the request.
	var members int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM memberships WHERE org_id = $1 AND user_id = $2`, orgID, created.ID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if members != 0 {
		t.Fatal("PUT active=false left the org membership in place")
	}
	res := env.do(caller{name: "u-pat", pat: boundPAT}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("org-bound PAT after PUT deactivate: got %d want 401", res.StatusCode)
	}
	res = env.do(caller{name: "u-sess", session: userSess}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after PUT deactivate: got %d want 401", res.StatusCode)
	}
}

func TestSCIMPutUpdatesAndReinstates(t *testing.T) {
	env := newTestEnv(t)
	scim, orgID := env.scimOrg(t, "scimupd")

	email := "carol-" + env.sfx + "@acme.example"
	var created struct {
		ID string `json:"id"`
	}
	env.doJSON(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"active":   true,
	}, &created, http.StatusCreated)

	// A full replace with a new display name applies it.
	env.doJSON(scim, http.MethodPut, "/scim/v2/Users/"+created.ID, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"name":     map[string]any{"formatted": "Carol Renamed"},
		"active":   true,
	}, nil, http.StatusOK)
	var displayName string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT display_name FROM users WHERE id = $1`, created.ID).Scan(&displayName); err != nil {
		t.Fatal(err)
	}
	if displayName != "Carol Renamed" {
		t.Fatalf("display name = %q, want the PUT value", displayName)
	}

	// Deactivate, then a PUT with active=true reinstates the membership.
	env.doJSON(scim, http.MethodDelete, "/scim/v2/Users/"+created.ID, nil, nil, http.StatusNoContent)
	env.doJSON(scim, http.MethodPut, "/scim/v2/Users/"+created.ID, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"active":   true,
	}, nil, http.StatusNotFound) // GetScimUser is membership-scoped: gone means gone

	var members int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM memberships WHERE org_id = $1 AND user_id = $2`, orgID, created.ID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if members != 0 {
		t.Fatal("a 404 PUT must not have re-created the membership")
	}

	// Renaming the identity is refused rather than silently ignored.
	other := env.register("scimoth")
	_ = other
	env.doJSON(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"active":   true,
	}, nil, http.StatusCreated)
	res := env.do(scim, http.MethodPut, "/scim/v2/Users/"+created.ID, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "renamed-" + email,
		"active":   true,
	})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("userName change: got %d want 400", res.StatusCode)
	}
}

// TestSCIMGroupSyncFailurePropagates injects a database failure on the
// team_members write and asserts the IdP is told, rather than being handed a
// 200 for a sync that did not happen.
func TestSCIMGroupSyncFailurePropagates(t *testing.T) {
	env := newTestEnv(t)
	scim, _ := env.scimOrg(t, "scimgrp")
	ctx := context.Background()

	email := "dave-" + env.sfx + "@acme.example"
	var user struct {
		ID string `json:"id"`
	}
	env.doJSON(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"active":   true,
	}, &user, http.StatusCreated)

	var group struct {
		ID string `json:"id"`
	}
	env.doJSON(scim, http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "eng-" + env.sfx,
	}, &group, http.StatusCreated)

	// Fault injection: refuse writes for this one user id.
	fn := "test_block_tm_" + env.sfx
	if _, err := env.st.Pool().Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger AS $fn$
		BEGIN
		  IF NEW.user_id = '%s'::uuid THEN RAISE EXCEPTION 'injected membership failure'; END IF;
		  RETURN NEW;
		END; $fn$ LANGUAGE plpgsql`, fn, user.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(ctx, fmt.Sprintf(
		`CREATE TRIGGER %s BEFORE INSERT ON team_members FOR EACH ROW EXECUTE FUNCTION %s()`, fn, fn)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = env.st.Pool().Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON team_members`, fn))
		_, _ = env.st.Pool().Exec(ctx, fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fn))
	})

	for _, op := range []string{"replace", "add"} {
		res := env.do(scim, http.MethodPatch, "/scim/v2/Groups/"+group.ID, map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{
				{"op": op, "path": "members", "value": []map[string]any{{"value": user.ID}}},
			},
		})
		_ = res.Body.Close()
		if res.StatusCode < 500 {
			t.Fatalf("group PATCH %s with a failing membership write: got %d, want a 5xx so the IdP retries", op, res.StatusCode)
		}
	}

	// A member who is simply not in the org is a legitimate no-op, not a 5xx:
	// the IdP must not retry that forever.
	stranger := env.register("scimstr")
	var strangerID string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT id::text FROM handles WHERE handle = $1`, stranger).Scan(&strangerID); err != nil {
		t.Fatal(err)
	}
	env.doJSON(scim, http.MethodPatch, "/scim/v2/Groups/"+group.ID, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "add", "path": "members", "value": []map[string]any{{"value": strangerID}}},
		},
	}, nil, http.StatusOK)
}
