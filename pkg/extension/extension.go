// Package extension is the seam a closed build uses to add to the open
// server without forking it (DEV-091, plan core-web-split §6): routes under
// /api/v1/x/<name>/, migrations in the extension's own schema, an
// entitlements resolver, hooks on the events the core commits, and worker
// jobs. cmd/agentryd is Main with no extensions; a closed build's main is
// Main with its own.
//
// The types an extension speaks are aliases of the core's, so a module
// outside this one can implement the interface without importing internal
// packages.
package extension

import (
	"context"
	"io/fs"
	"net/http"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
)

// Extension is what a closed build adds. Every method may return the zero
// value: an extension that only has routes returns nil migrations, a nil
// resolver, empty hooks and no jobs.
type Extension interface {
	// Name is the extension's short id (lower-case letters, digits, dashes):
	// its routes live under /api/v1/x/<name>/, its migrations in the schema
	// ent_<name>, and GET /meta lists it under `extensions`.
	Name() string
	// Routes registers the extension's handlers on a mux rooted at
	// /api/v1/x/<name>/ (patterns are relative: "GET /status"). The server
	// has already resolved the caller — PAT or session, CSRF on mutations,
	// the per-class rate limits — so a handler reads it with Principal.
	Routes(mux *http.ServeMux)
	// Migrations are goose SQL migrations applied after the core's, under
	// the extension's own version table (ent_<name>_goose_version). The SQL
	// owns its schema (CREATE SCHEMA IF NOT EXISTS ent_<name>); nil = none.
	Migrations() fs.FS
	// Entitlements replaces the core's config-based resolver; nil keeps it.
	Entitlements() Resolver
	// Hooks receive the events the core commits (see Event); zero = none.
	Hooks() Hooks
	// Jobs are async handlers the worker registers on its queue.
	Jobs() []Job
}

// Resolver, Subject, Limits, Features, Allowance and Feature are the
// core's entitlements types. A resolver an extension supplies usually wraps
// the core's (entitlements.NewConfigResolver) and answers Features by tier.
type (
	Resolver  = entitlements.Resolver
	Subject   = entitlements.Subject
	Limits    = entitlements.Limits
	Features  = entitlements.Features
	Allowance = entitlements.Allowance
	Feature   = entitlements.Feature
)

// The admission seam (plan subscription-tiers §5.1): an extension that
// implements Admits is asked once per submission, after every core gate and
// before anything is stored, and may refuse it. Optional — an extension
// without it admits everything, and the core build has none.
type Admits interface {
	Admitter() Admitter
}

// Admitter, Admission, Ticket and Refusal are the core's admission types.
type (
	Admitter  = registry.Admitter
	Admission = registry.Admission
	Ticket    = registry.Ticket
	Refusal   = registry.Refusal
)

// Unthrottles is the optional interface for an extension whose receiver of
// signed callbacks must never be refused by the anonymous rate class (a
// payment provider's webhook, plan subscription-tiers §5.5). The routes are
// "METHOD /path" relative to the mount, exact; each still passes the
// principal middleware and authorizes on its own signature.
type Unthrottles interface {
	UnthrottledRoutes() []string
}

// Principal is the resolved caller; Principal(ctx) reads it in a route.
type Principal = auth.Principal

// Principal returns the caller the server resolved for this request:
// Anonymous when none.
func PrincipalFromContext(ctx context.Context) *Principal { return api.PrincipalFrom(ctx) }

// Event is one committed event the core fans out (api.Event): the webhook
// kinds (version.published, agent.quarantined, org.member_added, …) with
// the owning org, plus user.registered and org.created.
type Event = api.Event

// Hooks are called after the core has committed the change; they are
// best-effort and must not block — an extension that needs durability
// enqueues a Job from the hook.
type Hooks struct {
	Event func(ctx context.Context, ev Event)
}

// Job is a queue handler the worker registers under Kind. Queue names the
// queue it is claimed from ("core" unless the work is untrusted content).
type Job struct {
	Kind    string
	Queue   string
	Handler queue.Handler
}

// QueueJob is the job envelope a Handler receives.
type QueueJob = queue.Job
