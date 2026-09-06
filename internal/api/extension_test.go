package api_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/api"
)

// The extension seam (DEV-091, pkg/extension): routes under /api/v1/x/<name>/
// go through the principal middleware, /meta lists the extension, and the
// hooks hear what the core commits.
func TestExtensionRoutesMetaAndHooks(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("GET /whoami", func(w http.ResponseWriter, r *http.Request) {
				p := api.PrincipalFrom(r.Context())
				w.Header().Set("Content-Type", "application/json")
				if p.Anonymous {
					_, _ = io.WriteString(w, `{"who":"anonymous"}`)
					return
				}
				_, _ = io.WriteString(w, `{"who":"`+p.Handle+`"}`)
			})
			mux.HandleFunc("POST /mark", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		})
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			mu.Lock()
			seen = append(seen, ev.Kind)
			mu.Unlock()
		})
	})

	var meta struct {
		Extensions []string `json:"extensions"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
	if len(meta.Extensions) != 1 || meta.Extensions[0] != "probe" {
		t.Fatalf("meta.extensions = %v", meta.Extensions)
	}

	var who struct {
		Who string `json:"who"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/x/probe/whoami", nil, &who, http.StatusOK)
	if who.Who != "anonymous" {
		t.Fatalf("anonymous whoami = %q", who.Who)
	}
	handle := env.register("ext")
	sess := env.login(handle)
	env.doJSON(sess, http.MethodGet, "/api/v1/x/probe/whoami", nil, &who, http.StatusOK)
	if who.Who != handle {
		t.Fatalf("session whoami = %q", who.Who)
	}
	// A session mutation without the CSRF header is refused by the same
	// middleware the generated routes use.
	res := env.do(caller{name: "nocsrf", session: sess.session}, http.MethodPost, "/api/v1/x/probe/mark", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation without CSRF: %d", res.StatusCode)
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/x/probe/mark", nil, nil, http.StatusNoContent)

	// Hooks: the registration above and an org creation.
	org := "ext-co" + env.sfx
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "Ext"}, nil, http.StatusCreated)
	mu.Lock()
	kinds := strings.Join(seen, ",")
	mu.Unlock()
	for _, want := range []string{"user.registered", "org.created"} {
		if !strings.Contains(kinds, want) {
			t.Fatalf("hooks saw %q, want %s", kinds, want)
		}
	}
}
