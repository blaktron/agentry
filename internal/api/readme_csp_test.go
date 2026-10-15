package api_test

import (
	"net/http"
	"testing"
)

// TestReadmeRouteCarriesACSP: the README route serves
// sanitised HTML as text/html on the API origin, where a session cookie
// lives. It carries the same policy the image proxy does — nothing loads,
// nothing runs, sandboxed — so a hole in the sanitiser would have nowhere
// to go if a browser ever rendered the response directly. The site
// embeds this HTML server-side and never sees the header.
func TestReadmeRouteCarriesACSP(t *testing.T) {
	env := newTestEnv(t)
	userH := env.register("csp-user")
	env.verifyEmail(userH)
	sess := env.login(userH)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": userH, "name": "plain", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)

	res := env.do(sess, http.MethodGet, "/api/v1/agents/"+userH+"/plain/readme", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("readme: %d", res.StatusCode)
	}
	if got := res.Header.Get("Content-Security-Policy"); got != "default-src 'none'; sandbox" {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, "default-src 'none'; sandbox")
	}
	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
}
