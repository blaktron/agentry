package api_test

import (
	"context"
	"net/http"
	"testing"
)

// Through the real query: a handle nobody holds is 404 on both public
// lookups, an existing one 200 — so the site's namespace rule can take 404
// as absence (the 500 path is TestLookupFailedDistinguishes…).
func TestPublicLookupsAnswer404OnlyForAbsence(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("look")
	env.verifyEmail(h)
	sess := env.login(h)
	orgH := "lookorg" + env.sfx
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": orgH, "displayName": "L"}, nil, http.StatusCreated)
	for _, c := range []struct {
		path string
		want int
	}{
		{"/api/v1/users/" + h, http.StatusOK},
		{"/api/v1/users/nobody-" + env.sfx, http.StatusNotFound},
		{"/api/v1/orgs/" + orgH, http.StatusOK},
		{"/api/v1/orgs/noorg-" + env.sfx, http.StatusNotFound},
	} {
		res := env.do(anonymous, http.MethodGet, c.path, nil)
		_ = res.Body.Close()
		if res.StatusCode != c.want {
			t.Errorf("GET %s = %d, want %d", c.path, res.StatusCode, c.want)
		}
	}

	// A handle whose holder is no longer active is absent too: an account
	// that is suspended or deleted, an organization that is suspended or
	// decommissioned. An organization in its decommission hold is still read.
	ctx := context.Background()
	for _, state := range []string{"suspended", "deleted"} {
		gone := env.register("look" + state)
		if _, err := env.st.Pool().Exec(ctx,
			`UPDATE users SET state = $2 WHERE id = (SELECT id FROM handles WHERE handle = $1)`, gone, state); err != nil {
			t.Fatal(err)
		}
		res := env.do(anonymous, http.MethodGet, "/api/v1/users/"+gone, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("GET /users/%s of a %s account = %d, want 404", gone, state, res.StatusCode)
		}
	}
	for _, c := range []struct {
		state string
		want  int
	}{{"decommissioning", http.StatusOK}, {"suspended", http.StatusNotFound}, {"decommissioned", http.StatusNotFound}} {
		if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = $2 WHERE id = (SELECT id FROM handles WHERE handle = $1)`, orgH, c.state); err != nil {
			t.Fatal(err)
		}
		res := env.do(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH, nil)
		_ = res.Body.Close()
		if res.StatusCode != c.want {
			t.Errorf("GET /orgs/%s in state %s = %d, want %d", orgH, c.state, res.StatusCode, c.want)
		}
	}
}
