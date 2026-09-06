package api_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Root paths of the server and the site are not handles (DEV-091): `ui` is
// the server's own surface, and a person named `settings` would shadow a
// page.
func TestReservedHandlesAreRefused(t *testing.T) {
	env := newTestEnv(t)
	for _, h := range []string{"ui", "settings", "api"} {
		res := env.do(anonymous, http.MethodPost, "/api/v1/auth/register", map[string]any{"handle": h, "email": h + env.sfx + "@example.test", "password": "hunter2hunter2"})
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode < 400 || res.StatusCode >= 500 || !strings.Contains(string(b), "reserved") {
			t.Fatalf("register %q: %d %s", h, res.StatusCode, b)
		}
	}
	owner := env.register("resv")
	env.verifyEmail(owner)
	sess := env.login(owner)
	res := env.do(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "ui", "displayName": "UI"})
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode < 400 || res.StatusCode >= 500 || !strings.Contains(string(b), "reserved") {
		t.Fatalf("createOrg ui: %d %s", res.StatusCode, b)
	}
}
