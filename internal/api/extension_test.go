package api_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
)

// The extension seam (pkg/extension): routes under /api/v1/x/<name>/
// go through the principal middleware, /meta lists the extension, and the
// hooks hear what the core commits.
func TestExtensionRoutesMetaAndHooks(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var created []api.Event
	env, idp := newOIDCTestEnv(t, nil, func(s *api.Server) {
		// A hook that panics must not stop the hooks after it or the request
		// that fired it.
		s.AddEventHook(func(context.Context, api.Event) { panic("a hook that fails") })
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
			if ev.Kind == "org.created" {
				created = append(created, ev)
			}
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
	sess := env.mintAccount(t, idp, "ext") // a verified address: creating an organization needs it
	handle := sess.name
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

	// Hooks: the sign-up above and an org creation.
	org := "ext-co" + env.sfx
	var made struct {
		Id uuid.UUID `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "Ext"}, &made, http.StatusCreated)
	mu.Lock()
	kinds := strings.Join(seen, ",")
	mu.Unlock()
	for _, want := range []string{"user.registered", "org.created"} {
		if !strings.Contains(kinds, want) {
			t.Fatalf("hooks saw %q, want %s", kinds, want)
		}
	}
	// The organization's creation names the organization, the person who made
	// it and the handles, which the extension that opens its billing needs.
	mu.Lock()
	defer mu.Unlock()
	if len(created) != 1 {
		t.Fatalf("org.created events: %d, want 1", len(created))
	}
	ev := created[0]
	if ev.OrgID != made.Id || ev.UserID.String() != env.selfID(sess) || ev.Payload["org"] != org || ev.Payload["creator"] != handle {
		t.Fatalf("org.created = org %s user %s %v, want org %s, creator %s (%s) and the handle %s", ev.OrgID, ev.UserID, ev.Payload, made.Id, env.selfID(sess), handle, org)
	}
}
