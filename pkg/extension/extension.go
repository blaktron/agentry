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
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/internal/voice"
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

// ErasesAccounts is the optional interface for an extension that keeps
// rows about a person which must go with the person's account
// (agentry#638): the core calls EraseAccount inside the transaction of
// POST /user/delete (kind AccountErased) and of POST /user/clear-data
// (kind AccountDataCleared), after its own steps and before its audit
// event, so the extension's delete commits or rolls back with the core's.
// tx carries statements only: the core ends the transaction. The extension
// writes only its own schema through it, and is quick: the request waits
// on it. The count it returns is recorded in the user.delete or
// user.data_clear event's detail under the extension's name. An error
// fails the erasure or the clear — the account is not erased, the caller
// gets a 500 — so the extension's rows never outlive an erased account
// through a failed delete of its own.
//
// Hooks.Event hears user.data_cleared after the commit, best-effort; this
// is for what may not wait or fail on its own.
type ErasesAccounts interface {
	EraseAccount(ctx context.Context, tx ErasureTx, userID uuid.UUID, kind AccountErasureKind) (int64, error)
}

// ErasureTx is the core's erasure transaction as an eraser may use it:
// Exec, Query and QueryRow, never Commit or Rollback.
type ErasureTx = api.ErasureTx

// AccountErasureKind says which account clear an EraseAccount call is part
// of; its values are the audit actions that record them.
type AccountErasureKind = api.AccountErasureKind

// The two account clears.
const (
	AccountErased      = api.AccountErased
	AccountDataCleared = api.AccountDataCleared
)

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

// PoolsKnowledge is the knowledge store's allocation seam (agentry#612):
// an extension's resolver that also implements it names the KnowledgePool
// an owner's packs draw on — the lock every upload into it is reserved
// under, the owners it counts, and its cap — as a paid organization pools
// its seats across its members. Every owner a pool lists must be answered
// with that same pool.
type (
	PoolsKnowledge = knowledge.Pools
	KnowledgePool  = knowledge.Pool
)

// ErrKeyNotOwner is what a KeyWrapper's Unwrap answers for a wrapped key
// that does not open for the owner presenting it; the routes answer it as
// a key that is not there.
var ErrKeyNotOwner = knowledge.ErrNotOwner

// Knowledge is the core's knowledge store as an extension may act on it
// (agentry#624; plan knowledge.md §4.5, M6): SecureAgentry's hosted build
// of the built-in Creator makes a pack, stages its tree for the sandbox
// host, and puts back the tree the build made. The data key stays in the
// core: an extension hands over plaintext files and reads metadata, and a
// tree it puts back is sealed under the pack's own key and stored through
// the same path as an upload through the routes — opened and checked,
// counted against its pool under the pool's lock, the tree it replaces
// deleted, its scan queued. Every call answers ErrKnowledgeUnconfigured
// while the store is off. Deps.Knowledge is nil without a database.
type Knowledge interface {
	// Create makes an empty pack named name for owner, under a data key
	// the core makes and wraps for owner. ErrKnowledgeName for a name
	// that is not a pack's, ErrKnowledgeNameTaken for one owner already
	// uses.
	Create(ctx context.Context, owner KeyOwner, name string) (KnowledgePack, error)
	// Pack reads one of owner's packs; ErrKnowledgeNotFound for another
	// owner's and for none, one answer.
	Pack(ctx context.Context, owner KeyOwner, id uuid.UUID) (KnowledgePack, error)
	// Tree is one of owner's packs' tree decrypted, as the canonical tar
	// whose SHA-256 is the pack's digest: ErrKnowledgeScanning while it
	// is scanned, ErrKnowledgeNotFound for an empty pack. It is plaintext
	// in memory; the caller keeps it no longer than it must.
	Tree(ctx context.Context, owner KeyOwner, id uuid.UUID) (KnowledgePack, []byte, error)
	// Replace makes files the tree of one of owner's packs if the pack
	// still holds the tree whose digest is from ("" for an empty pack),
	// else ErrKnowledgeChanged with nothing stored. A tree past the
	// pool's cap is a *KnowledgeAllocationError, one that is not a pack's
	// ErrKnowledgeTree or ErrKnowledgeTooLarge. A tree the pack already
	// holds is not stored again, changed false, whatever from is, so a
	// replace retried after it landed is not a conflict.
	Replace(ctx context.Context, owner KeyOwner, id uuid.UUID, from string, files []KnowledgeFile) (pack KnowledgePack, changed bool, err error)
	// Usage is owner's meter: what counts against its allocation and the
	// cap (0 is none).
	Usage(ctx context.Context, owner KeyOwner) (KnowledgeUsage, error)
}

// KnowledgePack, KnowledgeFile, KnowledgeUsage and KnowledgeAllocationError
// are the knowledge store's types as the seam speaks them.
type (
	KnowledgePack            = knowledge.Info
	KnowledgeFile            = scan.PackFile
	KnowledgeUsage           = knowledge.Usage
	KnowledgeAllocationError = knowledge.AllocationError
	KnowledgeState           = knowledge.State
)

// The states a knowledge pack is in.
const (
	KnowledgeEmpty    = knowledge.StateEmpty
	KnowledgeScanning = knowledge.StateScanning
	KnowledgeReady    = knowledge.StateReady
	KnowledgeFailed   = knowledge.StateFailed
)

// The knowledge seam's refusals.
var (
	ErrKnowledgeUnconfigured = knowledge.ErrUnconfigured
	ErrKnowledgeNotFound     = knowledge.ErrNotFound
	ErrKnowledgeScanning     = knowledge.ErrScanning
	ErrKnowledgeChanged      = knowledge.ErrChanged
	ErrKnowledgeName         = knowledge.ErrName
	ErrKnowledgeNameTaken    = knowledge.ErrNameTaken
	ErrKnowledgeTree         = knowledge.ErrTree
	ErrKnowledgeTooLarge     = knowledge.ErrTooLarge
)

// ProvesDrafts is the optional interface for an extension that records
// hosted drafts and can answer whether a version is one of them (plan
// drafter-revisions.md §6, R5; agentry#794). An upload may claim the draft
// it was published from; the scan computes the proof of the submitted files
// (pkg/draftproof) and asks DraftProvenance whether the submitter ran that
// draft against the agent's S9 baseline and recorded that proof. A yes
// makes the version a drafter-revision, which S9 reads with the benefit of
// the doubt; the client is never believed. Without it no version is one.
type ProvesDrafts interface {
	DraftProvenance() DraftProvenance
}

// DraftProvenance and DraftClaim are the seam's types: the question
// carries the run, the account, the agent, the baseline and the proof, and
// never a tier or a balance.
type (
	DraftProvenance = scan.DraftProvenance
	DraftClaim      = scan.DraftClaim
)

// AdmitsModelInput is the optional interface for an extension that admits
// hosted jobs to the model-input routes (agentry#608; plan builder-rework.md
// D20, D21): AI Review of text a model is about to read, and web search
// brokered by the registry. A sandbox host presents the credential the
// extension minted for one job in X-Agentry-Job-Token; the core asks
// AdmitModelInput which job it names, and whether the call fits the job
// (a draft past its searches is refused), then records what the call spent
// with RecordModelInput. The use is a count for the record, never a price:
// AI Review is 1 credit an operation, however many scans it makes
// (DEV-150). Without it only platform staff reach the routes.
type AdmitsModelInput interface {
	ModelInputCallers() ModelInputCallers
}

// ModelInputCallers, ModelInputCall, ModelInputUse and ModelInputOp are the
// model-input routes' admission types.
type (
	ModelInputCallers = api.ModelInputCallers
	ModelInputCall    = api.ModelInputCall
	ModelInputUse     = api.ModelInputUse
	ModelInputOp      = api.ModelInputOp
)

// The model-input operations a call can be: a scan, a search, and since
// agentry#708 the check of a finished draft.
const (
	ModelInputOpScan   = api.ModelInputOpScan
	ModelInputOpSearch = api.ModelInputOpSearch
	ModelInputOpCheck  = api.ModelInputOpCheck
)

// AdmitsVoice is the optional interface for an extension that admits, and
// may charge for, the review of a Writing Voice a route asks for (plan
// writing-voice.md D8, agentry#809): an edit saved on the web, a client's
// upload, a Restore of a version reviewed under another question set. AI
// Review is 1 credit an operation (DEV-150); the core charges nothing. A
// refusal is answered in its own status and words before anything is
// stored, and a ticket is voided when nothing was. A Voice Writer run In
// Agentry puts its output through Voice.Propose, whose review is inside
// the build's price and is not admitted here.
type AdmitsVoice interface {
	VoiceAdmitter() VoiceAdmitter
}

// VoiceAdmitter and VoiceAdmission are the voice routes' admission types.
type (
	VoiceAdmitter  = api.VoiceAdmitter
	VoiceAdmission = api.VoiceAdmission
)

// Voice is the core's store of Writing Voices as an extension may act on
// it (agentry#809; plan writing-voice.md §4, §6): SecureAgentry's hosted
// Voice Writer reads the live voice it improves or edits and puts back
// the voice it wrote, and a hosted run reads the live voice it attaches.
// The data key stays in the core: an extension reads and hands over text.
// Every call answers ErrVoiceUnconfigured while the store is off.
// Deps.Voice is nil without a database.
type Voice interface {
	// Live is a person's live version, the one a run attaches, its text
	// opened; ErrVoiceNotFound when they have none. A pending or flagged
	// version is never answered here (plan §3, invariant 4).
	Live(ctx context.Context, user uuid.UUID) (*VoiceVersion, error)
	// State is a person's voice: the always-attach flag and every
	// version, texts opened, a pending or flagged one included, for a
	// Voice Writer run to improve or edit; ErrVoiceNotFound when they
	// have none. A run attaches what Live answers, never this.
	State(ctx context.Context, user uuid.UUID) (VoiceState, error)
	// Propose makes text a person's pending version from a Voice Writer
	// run In Agentry (source VoiceSourceBuild or VoiceSourceAIEdit) and
	// queues its review; it is live only once the review passes it. Text
	// that is not a voice is a *VoiceInvalidError or ErrVoiceTooLarge.
	Propose(ctx context.Context, user uuid.UUID, text []byte, source VoiceSource) (VoiceState, error)
}

// VoiceVersion, VoiceState and VoiceSource are the voice store's types as
// the seam speaks them; VoiceInvalidError is Propose's answer for text that
// is not a voice, with the reason.
type (
	VoiceVersion      = voice.Version
	VoiceState        = voice.State
	VoiceSource       = voice.Source
	VoiceInvalidError = voice.InvalidError
)

// The sources a Voice Writer run In Agentry proposes with.
const (
	VoiceSourceBuild  = voice.SourceBuild
	VoiceSourceAIEdit = voice.SourceAIEdit
)

// The voice seam's refusals.
var (
	ErrVoiceUnconfigured = voice.ErrUnconfigured
	ErrVoiceNotFound     = voice.ErrNotFound
	ErrVoiceTooLarge     = voice.ErrTooLarge
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

// Scope is a PAT scope as the core spells it; those an extension may
// require are the hosted-run scopes (agentry#348), the knowledge scopes,
// for a route that writes into a person's knowledge through the Knowledge
// seam (agentry#624), and the vault's secret:write (agentry#676). A
// session carries no scopes and the account's full authority; a PAT
// carries what it was minted with, flat — no scope implies another.
type Scope = auth.Scope

// The scopes an extension route may require.
const (
	ScopeRunRead        = auth.ScopeRunRead
	ScopeRunWrite       = auth.ScopeRunWrite
	ScopeKnowledgeRead  = auth.ScopeKnowledgeRead
	ScopeKnowledgeWrite = auth.ScopeKnowledgeWrite
	// ScopeSecretWrite lets a token set and delete the caller's hosted-run
	// secrets (agentry#676); the vault extension requires it.
	ScopeSecretWrite = auth.ScopeSecretWrite
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
	// Knowledge is the core's knowledge store (agentry#624). nil when the
	// server runs without a database, as DB is; while the store is off
	// (no key wrapper yet) its calls answer ErrKnowledgeUnconfigured.
	Knowledge Knowledge
	// Voice is the core's store of Writing Voices (agentry#809). nil when
	// the server runs without a database; while the store is off its
	// calls answer ErrVoiceUnconfigured.
	Voice Voice
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
	// Maintainable reports whether p may maintain the agent at
	// namespace/name as the core's own routes decide it: the maintain
	// role over the namespace or a grant, a personal access token's
	// org:admin, and the owning organization's gate for a write (an
	// organization in its decommission hold reads and is not maintained).
	// An agent that does not exist, one p may not read, one p reads and
	// may not maintain, and one the gate holds are the same false with no
	// error (agentry#833).
	Maintainable(ctx context.Context, p *Principal, namespace, name string) (AgentRef, bool, error)
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
