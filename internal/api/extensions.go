package api

import (
	"context"
	"net/http"
	"regexp"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
)

// The extension seam (DEV-091, pkg/extension): a closed build mounts routes
// under /api/v1/x/<name>/ behind the same principal middleware, hears the
// events the core commits, and shows up in GET /meta. Nothing here runs in
// the core build unless something registers.

// Event is one committed event the core fans out to extensions: the org
// webhook kinds (version.published, agent.quarantined, org.member_added,
// org.policy_updated, …) carrying the owning org, plus user.registered and
// org.created. Payload is the same map the webhook carries.
type Event struct {
	Kind    string
	OrgID   uuid.UUID // uuid.Nil for a personal namespace or a user event
	AgentID uuid.UUID // set for agent transitions
	UserID  uuid.UUID // set for user.registered
	Payload map[string]any
}

var reExtensionName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type extensionMount struct {
	name   string
	routes func(*http.ServeMux)
}

// RegisterExtension mounts routes under /api/v1/x/<name>/ when the handler
// is built (NewHandler); the mux the callback receives is rooted there, so
// its patterns are relative ("GET /status"). Every request through it has
// passed principalMiddleware: PAT or session resolved, CSRF enforced on
// mutations, the per-class rate limits applied.
func (s *Server) RegisterExtension(name string, routes func(*http.ServeMux)) {
	if !reExtensionName.MatchString(name) {
		panic("api: extension name must match " + reExtensionName.String() + ": " + name)
	}
	for _, m := range s.extensions {
		if m.name == name {
			panic("api: extension registered twice: " + name)
		}
	}
	s.extensions = append(s.extensions, extensionMount{name: name, routes: routes})
}

// AddEventHook registers a listener for every Event the core commits.
// Hooks run synchronously after the commit and after the webhook fan-out;
// a slow hook slows the request, so hooks should hand real work to a job.
func (s *Server) AddEventHook(h func(ctx context.Context, ev Event)) {
	s.eventHooks = append(s.eventHooks, h)
}

// ExtensionNames lists the mounted extensions in registration order.
func (s *Server) ExtensionNames() []string {
	out := make([]string, 0, len(s.extensions))
	for _, m := range s.extensions {
		out = append(out, m.name)
	}
	return out
}

// PrincipalFrom is principalFrom for extension routes.
func PrincipalFrom(ctx context.Context) *auth.Principal { return principalFrom(ctx) }

func (s *Server) fireEvent(ctx context.Context, ev Event) {
	for _, h := range s.eventHooks {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					s.log.Error("extension hook panicked", "event", ev.Kind, "panic", rec)
				}
			}()
			h(ctx, ev)
		}()
	}
}

// emitOrgEvent is the one place an org-level event leaves the server: the
// org's webhooks, then the extension hooks. Errors never reach the caller.
func (s *Server) emitOrgEvent(ctx context.Context, orgID uuid.UUID, kind string, payload map[string]any) {
	if s.webhooks != nil {
		if err := s.webhooks.Emit(ctx, orgID, kind, payload); err != nil {
			s.log.Error("webhook emit", "event", kind, "err", err)
		}
	}
	s.fireEvent(ctx, Event{Kind: kind, OrgID: orgID, Payload: payload})
}

func (s *Server) mountExtensions(mux *http.ServeMux) {
	for _, m := range s.extensions {
		sub := http.NewServeMux()
		m.routes(sub)
		prefix := "/api/v1/x/" + m.name
		mux.Handle(prefix+"/", s.principalMiddleware(http.StripPrefix(prefix, sub)))
	}
}
