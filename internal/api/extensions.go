package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
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
	name        string
	routes      func(*http.ServeMux)
	unthrottled map[string]bool
}

var reUnthrottledRoute = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE) /[A-Za-z0-9_./-]*$`)

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

// SetExtensionUnthrottled names the routes of a mounted extension the
// anonymous rate class does not apply to: "METHOD /path", relative to the
// mount, exact (no wildcards — the seam is narrow on purpose). Only an
// extension's own receiver of signed callbacks belongs here (plan
// subscription-tiers §5.5); the route still passes the principal middleware
// and declares its own authorization. Panics on a malformed pattern or an
// unknown extension, at start-up, where it is found.
func (s *Server) SetExtensionUnthrottled(name string, routes []string) {
	for i := range s.extensions {
		if s.extensions[i].name != name {
			continue
		}
		m := make(map[string]bool, len(routes))
		for _, rt := range routes {
			if !reUnthrottledRoute.MatchString(rt) {
				panic("api: extension " + name + ": unthrottled route must be \"METHOD /path\", got " + rt)
			}
			m[rt] = true
		}
		s.extensions[i].unthrottled = m
		return
	}
	panic("api: extension not registered: " + name)
}

// ExtensionUnthrottled lists the unthrottled routes of every extension, as
// "METHOD /api/v1/x/<name>/…" keys, so an extension's own route-table test
// can assert exactly which of its routes escape the anonymous class.
func (s *Server) ExtensionUnthrottled() map[string]bool {
	out := map[string]bool{}
	for _, m := range s.extensions {
		for rt := range m.unthrottled {
			method, path, _ := strings.Cut(rt, " ")
			out[method+" /api/v1/x/"+m.name+path] = true
		}
	}
	return out
}

// ExtensionDeps is what an extension gets to work with (pkg/extension.Deps,
// agentry#324): the pool the core uses, the logger, and an audit writer
// that lands an event in its own transaction. nil pool when the server
// runs without a database (limited dev mode).
func (s *Server) ExtensionDeps() (*pgxpool.Pool, *slog.Logger, func(context.Context, audit.Event) error, func(context.Context, pgx.Tx, audit.Event) error) {
	var pool *pgxpool.Pool
	if s.st != nil {
		pool = s.st.Pool()
	}
	write := func(ctx context.Context, e audit.Event) error {
		if s.st == nil {
			return errors.New("api: no database for the audit event")
		}
		return s.st.WithTx(ctx, func(q *storegen.Queries) error { return s.auditW.Write(ctx, q, e) })
	}
	writeIn := func(ctx context.Context, tx pgx.Tx, e audit.Event) error {
		return s.auditW.Write(ctx, storegen.New(tx), e)
	}
	return pool, s.log, write, writeIn
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
					s.log.ErrorContext(ctx, "extension hook panicked", "event", ev.Kind, "panic", rec)
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
			s.log.ErrorContext(ctx, "webhook emit", "event", kind, "err", err)
		}
	}
	s.fireEvent(ctx, Event{Kind: kind, OrgID: orgID, Payload: payload})
}

func (s *Server) mountExtensions(mux *http.ServeMux) {
	for _, m := range s.extensions {
		sub := http.NewServeMux()
		m.routes(sub)
		prefix := "/api/v1/x/" + m.name
		// The middleware sees the full path (its scope families key on it),
		// so the extension's relative keys are prefixed here.
		unthrottled := make(map[string]bool, len(m.unthrottled))
		for rt := range m.unthrottled {
			method, path, _ := strings.Cut(rt, " ")
			unthrottled[method+" "+prefix+path] = true
		}
		mux.Handle(prefix+"/", s.principalMiddlewareOpts(http.StripPrefix(prefix, sub), principalOpts{unthrottled: unthrottled}))
	}
}
