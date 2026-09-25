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
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/webhook"
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

// Resolver, Subject, Limits, Features and Cap are the core's entitlements
// types. A resolver an extension supplies usually wraps the core's
// (entitlements.NewConfigResolver) and answers Features by tier.
type (
	Resolver      = entitlements.Resolver
	Subject       = entitlements.Subject
	NamespaceKind = entitlements.NamespaceKind
	Limits        = entitlements.Limits
	Features      = entitlements.Features
	Cap           = entitlements.Cap
)

// Allowance is the old name of Cap (agentry#360): kept so an extension
// built against it still compiles until it adopts Cap.
//
// Deprecated: use Cap. agentry-enterprise#29 has adopted Cap and nothing in
// the estate uses this name; it goes with the next breaking change to this
// package.
type Allowance = entitlements.Cap

// The two namespace kinds a Subject carries.
const (
	NamespaceUser = entitlements.NamespaceUser
	NamespaceOrg  = entitlements.NamespaceOrg
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

// WrapsKeys is the optional interface for an extension that wraps the data
// keys of knowledge packs itself (plan knowledge.md §4.3, §4.4; agentry#593):
// SecureAgentry's wrapper seals each key to its owner's own certificate. The
// core's wrapper, the deployment's knowledge sealing key, is replaced and
// nothing else changes: the store, the routes, the scan and the erasure
// stay the core's. A nil KeyWrapper leaves the core's in place.
type WrapsKeys interface {
	KeyWrapper() KeyWrapper
}

// KeyWrapper, KeyOwner and WrappedKey are the knowledge store's key types.
type (
	KeyWrapper = knowledge.KeyWrapper
	KeyOwner   = knowledge.Owner
	WrappedKey = knowledge.WrappedKey
)

// The owners a knowledge pack can have.
const (
	KeyOwnerUser = knowledge.OwnerUser
	KeyOwnerOrg  = knowledge.OwnerOrg
)

// ErrKeyNotOwner is what a KeyWrapper's Unwrap answers for a wrapped key
// that does not open for the owner presenting it; the routes answer it as
// a key that is not there.
var ErrKeyNotOwner = knowledge.ErrNotOwner

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

// Scope is a PAT scope as the core spells it; the two an extension may
// require are the hosted-run scopes (agentry#348). A session carries no
// scopes and the account's full authority; a PAT carries what it was
// minted with, flat — no scope implies another.
type Scope = auth.Scope

// The scopes an extension route may require.
const (
	ScopeRunRead  = auth.ScopeRunRead
	ScopeRunWrite = auth.ScopeRunWrite
)

// ScopeAllows is how the core reads a scope for a route: an anonymous
// caller never passes; a session passes, having the account's full
// authority (the route still checks who the account is); a PAT passes
// only when it was minted with the scope. An extension route calls this
// with the principal and the scope it requires and refuses on false.
func ScopeAllows(p *Principal, s Scope) bool {
	switch {
	case p == nil || p.Anonymous:
		return false
	case p.Via == "pat":
		return auth.HasScope(p.Scopes, s)
	default:
		return true
	}
}

// Principal returns the caller the server resolved for this request:
// Anonymous when none.
func PrincipalFromContext(ctx context.Context) *Principal { return api.PrincipalFrom(ctx) }

// Event is one committed event the core fans out (api.Event): the webhook
// kinds (version.published, agent.quarantined, org.member_added, …) with
// the owning org, plus user.registered, user.data_cleared (agentry#498:
// clear what the extension holds for that user) and org.created.
type Event = api.Event

// Hooks are called after the core has committed the change; they are
// best-effort and must not block — an extension that needs durability
// enqueues a Job from the hook.
type Hooks struct {
	Event func(ctx context.Context, ev Event)
}

// Job is a queue handler the worker registers under Kind. Queue names the
// queue it is claimed from ("core" unless the work is untrusted content).
// A positive Every makes the worker enqueue Kind on that period, and once
// at start-up, the way the core's own watchdog and sweep run (agentry#324).
// Every worker replica enqueues on its own clock and the queue's claim
// runs each row once, so the handler must be idempotent — a cycle closer
// that finds nothing to close does nothing.
type Job struct {
	Kind    string
	Queue   string
	Handler queue.Handler
	Every   time.Duration
}

// Deps is what the core hands an extension at start-up (agentry#324), once
// per process, before its routes mount and its jobs register. DB is the
// pool the core uses, under the core's own database role: the convention
// — not yet enforced by a role or a grant — is that an extension writes
// only its own schema (ent_<name>) and reads core tables, never alters
// them; the seam test of the closed build is where that is proven. Log is
// tagged with the extension's name. Audit writes the extension's events
// through the core's writer (the month partition, the archive stream, the
// refusal of an unregistered action); the event's actor kind, IP and user
// agent are the extension's to fill, since no request built it. DB is nil
// when the server runs without a database (limited dev mode).
type Deps struct {
	DB    *pgxpool.Pool
	Log   *slog.Logger
	Audit AuditWriter
	// Blobs is the deployment's object storage — the archive store the
	// core runs on (a local directory or S3) — for an extension to keep
	// its own objects under its own key prefix (agentry#348: a hosted
	// run's inputs, outputs and receipts). nil when the server runs
	// without a database, as DB is.
	Blobs BlobStore
	// Entitlements is the resolver the server uses with no extension —
	// the deployment's configured limits — for an extension's own resolver
	// to embed and answer Features over (agentry#326).
	Entitlements Resolver
	// Orgs is the core's organization store as an extension may act on it
	// (agentry#360). nil when the server runs without a database.
	Orgs Orgs
	// Agents is the core's read of an agent as an extension may ask it
	// (agentry#381). nil when the server runs without a database.
	Agents Agents
	// Notifier carries a message an extension composed to a person, under
	// the core's rules and through the core's transport (agentry#366).
	// nil when the server runs without a database, as DB is.
	Notifier Notifier
	// Webhooks delivers an event to one of an organization's webhook
	// endpoints through the core's transport (agentry#430). nil when the
	// server runs without a database, as DB is.
	Webhooks Webhooks
}

// Notifier lets an extension tell a person something by mail without
// owning a transport, an address book or the rule about who may be
// written to. The core keeps all three (plan organization-subscriptions
// §5.8, D17): the address must be verified — nothing is ever sent to an
// unverified one, DEV-099's rule — and the person's preference for the
// message's kind must be on. An extension composes the words; the core
// decides whether they go and frames them with the registry's name and
// the settings link. The closed product's copy therefore stays out of the
// open repository, and the open repository's rule about addresses cannot
// be bypassed by an extension that holds one.
type Notifier interface {
	// Send delivers subject and text to the person, if the core's rules
	// allow it. It reports whether the message went: false with no error
	// is a suppression — an unverified address, or the kind switched off
	// — which is not the extension's failure and not a state it must
	// react to. An error is a delivery failure the extension may retry.
	// A kind the core does not know is refused: an extension may not
	// send as a class it was not given.
	Send(ctx context.Context, userID uuid.UUID, kind NotifyKind, subject, text string) (bool, error)
	// OrgAdmins names the active administrators of an organization, so
	// a message about the organization's subscription reaches the people
	// who manage it. Pending administrators are not among them: they hold
	// nothing of the organization yet.
	OrgAdmins(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error)
}

// NotifyKind names the class a message is sent as, which is the switch a
// person turns off. Only the kinds the core lists here may be used: a
// message about billing is what the person's billing switch governs, and
// a dependency alert routed to them is what their dependency-alert
// switch governs, wherever it came from.
type NotifyKind string

const (
	// NotifyBilling is the closed build's billing mail (plan §5.8): a
	// checkout confirmed, a payment failed, an organization restricted,
	// seats reached, "your organization covers you".
	NotifyBilling NotifyKind = "billing"
	// NotifyDependencyAlert is a dependency alert an extension routes to
	// the person an organization chose for it (plan
	// organization-subscriptions §6 "Alert routing", agentry#430): the
	// same news the core mails the author, under the same switch.
	NotifyDependencyAlert NotifyKind = "dependency_alert"
)

// Webhooks lets an extension deliver an event to one of an organization's
// webhook endpoints — a destination the organization named for the
// extension's purpose, not one chosen by its subscriptions — through the
// core's transport: the delivery ledger the endpoint's log reads, the
// signed request, the retries, the SSRF guard. The endpoint's secret and
// the transport stay the core's; an extension holds an endpoint by id.
type Webhooks interface {
	// Endpoints lists the organization's endpoints as an extension may
	// name one, active or not. An organization that does not exist has
	// none, not an error.
	Endpoints(ctx context.Context, orgID uuid.UUID) ([]WebhookEndpointRef, error)
	// Deliver records one delivery of event with data to the endpoint
	// and queues it, the way the core's own emit does for a subscribed
	// endpoint. It reports whether a delivery was recorded: false with
	// no error means the endpoint is not the organization's or is
	// switched off — a destination gone stale, which the extension may
	// report but cannot repair. An event outside the core's catalog is
	// refused: what a consumer is told to expect is the core's promise.
	Deliver(ctx context.Context, orgID, endpointID uuid.UUID, event string, data any) (bool, error)
}

// WebhookEndpointRef is an endpoint as the seam describes it: its id,
// its URL, the events it subscribes to and whether it is active. No
// secret.
type WebhookEndpointRef = api.WebhookEndpointRef

// EventAgentDependencyAlert is the catalog event a dependency alert is
// fanned out as (DEV-090): what the hook hears as Event.Kind, and what an
// extension routing the alert delivers it as, so the destination it
// names reads the same event a subscription would have given it.
const EventAgentDependencyAlert = webhook.EventAgentDependencyAlert

// Agents answers whether a principal may read an agent the way the core's
// own routes decide it — the effective role over the namespace and the
// grants, a personal access token's agent:read, the owning organization's
// state — so an extension that names a release (a hosted run of it, say)
// admits exactly whom the core would and mirrors none of the rule in SQL.
type Agents interface {
	// Readable reports whether p may read the agent at namespace/name,
	// and what the core knows of it when they may. An agent that does not
	// exist and one p may not read are the same false with no error: the
	// seam gives no way to tell a private agent's existence that the
	// core's routes would not give.
	Readable(ctx context.Context, p *Principal, namespace, name string) (AgentRef, bool, error)
}

// AgentRef is what the core says of an agent a principal may read: its
// id, the owning namespace's id and kind (NamespaceUser or NamespaceOrg —
// an organization's, for an organization's agent), and whether it is
// public. Readable says nothing of what else the caller may do with it:
// an agent of an organization in its decommission hold reads and is not
// written.
type AgentRef struct {
	ID            uuid.UUID
	NamespaceID   uuid.UUID
	NamespaceKind NamespaceKind
	Public        bool
}

// Orgs holds the acts on an organization the core owns and an extension
// triggers. Where an admission extension runs, an organization is created
// awaiting activation and its creator may not create another until it is
// activated; the extension that owns the org's standing activates it when
// the subscription starts (plan organization-subscriptions §4, D5).
type Orgs interface {
	// Activate marks the organization activated. Idempotent: it reports
	// whether this call did it, and an unknown org is false with no error.
	Activate(ctx context.Context, orgID uuid.UUID) (bool, error)
	// Decommission starts the organization's decommission hold the way an
	// admin's request does (agentry#363): read-only for the configured
	// hold, then erased, its handle and domain released; the core fires
	// org.decommissioning now and org.decommissioned after the erasure.
	// The hosted product's pending-payment sweep calls it for an
	// organization nobody paid for. Idempotent: it reports whether this
	// call did it; an organization that is not active, or unknown, is
	// false with no error.
	Decommission(ctx context.Context, orgID uuid.UUID, reason string) (bool, error)
}

// BlobStore is the core's object store: put (write-once per key, so an
// extension keys its objects uniquely), get, exists, delete.
type BlobStore = registry.BlobStore

// AuditWriter writes one audit event; see Deps. Write lands it in a
// transaction of its own; WriteIn joins the caller's, so a mutation and its
// audit row commit or roll back together, as the core's own do.
type AuditWriter interface {
	Write(ctx context.Context, e AuditEvent) error
	WriteIn(ctx context.Context, tx pgx.Tx, e AuditEvent) error
}

// AuditEvent, AuditAction and ActorKind are the core's audit types.
type (
	AuditEvent  = audit.Event
	AuditAction = audit.Action
	ActorKind   = audit.ActorKind
)

// The actor kinds an extension's events carry.
const (
	ActorUser   = audit.ActorUser
	ActorPAT    = audit.ActorPAT
	ActorSystem = audit.ActorSystem
)

// Binds is the optional interface for an extension that needs Deps.
type Binds interface {
	Bind(Deps)
}

// Audits is the optional interface for an extension that writes audit
// events of its own: the actions it names are added to the catalog at
// start-up under the extension's own name, "<name>.<verb>", so a Deps.Audit
// write of any of them is accepted.
type Audits interface {
	AuditActions() []AuditAction
}

// registerAuditAction adds an extension's action to the audit catalog. The
// action must be "<extension name>.<verb>" with a valid extension name, and
// must not already be in the catalog, so an extension can neither shadow
// a core action nor register one under another name; a violation panics
// at start-up, where it is found.
func registerAuditAction(extensionName string, a AuditAction) {
	if !reExtensionName.MatchString(extensionName) {
		panic("extension: audit action " + string(a) + ": invalid extension name " + extensionName)
	}
	if !strings.HasPrefix(string(a), extensionName+".") || len(a) <= len(extensionName)+1 {
		panic("extension: audit action " + string(a) + " must be prefixed " + extensionName + ".")
	}
	if !audit.Register(a) {
		panic("extension: audit action " + string(a) + " is already in the catalog")
	}
}

var reExtensionName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// QueueJob is the job envelope a Handler receives.
type QueueJob = queue.Job
