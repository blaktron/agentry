package api_test

import (
	"io"
	"net/http"
	"strings"
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
	if got := res.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}

	// The same headers ride a README that has content: the fragment is
	// the sanitised rendering, and what the sanitiser removes is not there,
	// but the response is inert even if a browser opens it directly. A public
	// agent's fragment is cacheable for five minutes; a private agent's never.
	const readme = "# Heading\n\nBody text <script>alert(1)</script>\n"
	env.publishSearchable(t, sess, userH, "documented", "documented summary", readme)
	// A second copy of the same published agent, switched to private.
	env.publishSearchable(t, sess, userH, "hidden", "hidden summary", readme)
	env.doJSON(sess, http.MethodPatch, "/api/v1/agents/"+userH+"/hidden", map[string]any{"visibility": "private"}, nil, http.StatusOK)
	for name, cache := range map[string]string{"documented": "public, max-age=300", "hidden": "no-store"} {
		res := env.do(sess, http.MethodGet, "/api/v1/agents/"+userH+"/"+name+"/readme", nil)
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK || !strings.Contains(string(body), "<h2") || !strings.Contains(string(body), "Body text") ||
			strings.Contains(string(body), "<script") {
			t.Fatalf("%s readme: %d %s", name, res.StatusCode, body)
		}
		for k, want := range map[string]string{
			"Content-Security-Policy": "default-src 'none'; sandbox",
			"X-Content-Type-Options":  "nosniff",
			"Content-Type":            "text/html; charset=utf-8",
			"Cache-Control":           cache,
		} {
			if got := res.Header.Get(k); got != want {
				t.Errorf("%s readme %s = %q, want %q", name, k, got, want)
			}
		}
	}
}
