package api_test

import (
	"net/http"
	"testing"
)

// Through the real query: a handle nobody holds is 404 on both public
// lookups, an existing one 200 — so the site's namespace rule can take 404
// as absence (agentry#261; the 500 path is TestLookupFailedDistinguishes…).
func TestPublicLookupsAnswer404OnlyForAbsence(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("look")
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
}
