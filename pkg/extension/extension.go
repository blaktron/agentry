// Package extension is the seam an extended build uses to add to the
// server without forking it: routes under /api/v1/x/<name>/, migrations
// in the extension's own schema, an entitlements resolver, hooks on the
// events the core commits, and worker jobs. cmd/agentryd is Main with
// no extensions; an extended build's main is Main with its own.
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
	"go.opentelemetry.io/otel/metric"

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

// Extension is what an extended build adds. Every method may return the
// zero value: an extension that only has routes returns nil migrations,
// a nil resolver, empty hooks and no jobs.
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

// Allowance is the old name of Cap: kept so an extension built against
// it still compiles until it adopts Cap.
//
// Deprecated: use Cap. It goes with the next breaking change to this
// package.
type Allowance = entitlements.Cap

// The two namespace kinds a Subject carries.
const (
	NamespaceUser = entitlements.NamespaceUser
	NamespaceOrg  = entitlements.NamespaceOrg
)

// The admission seam: an extension that implements Admits is asked once
// per submission, after every core gate and before anything is stored,
// and may refuse it. Optional: an extension without it admits
// everything, and the core build has none.
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

// WrapsKeys is the optional interface for an extension that wraps the
// data keys of knowledge packs itself: the hosted build's wrapper seals
// each key to its owner's own certificate. The core's wrapper, the
// deployment's knowledge sealing key, is replaced and nothing else
// changes: the store, the routes, the scan and the erasure stay the
// core's. A nil KeyWrapper leaves the core's in place.
type WrapsKeys interface {
	KeyWrapper() KeyWrapper
}

// ErasesAccounts is the optional interface for an extension that keeps
// rows about a person which must go with the person's account: the core
// calls EraseAccount inside the transaction of POST /user/delete (kind
// AccountErased) and of POST /user/clear-data (kind
// AccountDataCleared), after its own steps and before its audit event,
// so the extension's delete commits or rolls back with the core's. tx
// carries statements only: the core ends the transaction. The extension
// writes only its own schema through it, and is quick: the request
// waits on it. The count it returns is recorded in the user.delete or
// user.data_clear event's detail under the extension's name. An error
// fails the erasure or the clear — the account is not erased, the
// caller gets a 500 — so the extension's rows never outlive an erased
// account through a failed delete of its own.
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

// PoolsKnowledge is the knowledge store's allocation seam: an
// extension's resolver that also implements it names the KnowledgePool
// an owner's packs draw on — the lock every upload into it is reserved
// under, the owners it counts, and its cap — as a paid organization
// pools its seats across its members. Every owner a pool lists must be
// answered with that same pool.
type (
	PoolsKnowledge = knowledge.Pools
	KnowledgePool  = knowledge.Pool
)

// ErrKeyNotOwner is what a KeyWrapper's Unwrap answers for a wrapped key
// that does not open for the owner presenting it; the routes answer it as
// a key that is not there.
var ErrKeyNotOwner = knowledge.ErrNotOwner

// Knowledge is the core's knowledge store as an extension may act on
// it: the hosted build of the built-in Creator makes a pack, stages its
// tree for the sandbox host, and puts back the tree the build made. The
// data key stays in the core: an extension hands over plaintext files
// and reads metadata, and a tree it puts back is sealed under the
// pack's own key and stored through the same path as an upload through
// the routes: opened and checked, counted against its pool under the
// pool's lock, the tree it replaces deleted, its scan queued. Every
// call answers ErrKnowledgeUnconfigured while the store is off.
// Deps.Knowledge is nil without a database.
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
// hosted drafts and can answer whether a version is one of them. An
// upload may claim the draft it was published from; the scan computes
// the proof of the submitted files (pkg/draftproof) and asks
// DraftProvenance whether the submitter ran that draft against the
// agent's S9 baseline and recorded that proof. A yes makes the version
// a drafter-revision, which S9 reads with the benefit of the doubt; the
// client is never believed. Without it no version is one.
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

// AdmitsModelInput is the optional interface for an extension that
// admits hosted jobs to the model-input routes: AI Review of text a
// model is about to read, and web search brokered by the registry. A
// sandbox host presents the credential the extension minted for one job
// in X-Agentry-Job-Token; the core asks AdmitModelInput which job it
// names, and whether the call fits the job (a draft past its searches
// is refused), then records what the call spent with RecordModelInput.
// The use is a count for the record, never a price: AI Review is 1
// credit an operation, however many scans it makes. Without it only
// platform staff reach the routes.
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

// The model-input operations a call can be: a scan, a search, and the
// check of a finished draft.
const (
	ModelInputOpScan   = api.ModelInputOpScan
	ModelInputOpSearch = api.ModelInputOpSearch
	ModelInputOpCheck  = api.ModelInputOpCheck
)

// AdmitsVoice is the optional interface for an extension that admits,
// and may charge for, the review of a Writing Voice a route asks for:
// an edit saved on the web, a client's upload, a Restore of a version
// reviewed under another question set. AI Review is 1 credit an
// operation; the core charges nothing. A refusal is answered in its own
// status and words before anything is stored, and a ticket is voided
// when nothing was. A ticket whose version the core stored is recorded in
// the core's admitted_stores table (kind "voice") in the transaction that
// stores it, so a ticket with no row stored nothing even where its void
// failed or never ran. A Voice Writer run In Agentry puts its output
// through Voice.Propose, whose review is inside the build's price and
// is not admitted here.
type AdmitsVoice interface {
	VoiceAdmitter() VoiceAdmitter
}

// VoiceAdmitter and VoiceAdmission are the voice routes' admission types.
type (
	VoiceAdmitter  = api.VoiceAdmitter
	VoiceAdmission = api.VoiceAdmission
)

// AdmitsKnowledge is the optional interface for an extension that admits,
// and may charge for, the scan an upload of a knowledge pack's tree queues
// (PUT …/knowledge/packs/{id}/tree, an account's or an organization's).
// AI Review is 1 credit an operation; the core charges nothing. It is
// asked after the core has read the tree and checked it against the
// owner's allocation, and before anything is stored; a
// refusal is answered in its own status and words, and a ticket is voided
// when the core then stores nothing. A ticket whose tree the core stored is
// recorded in the core's admitted_stores table (kind "knowledge") in the
// transaction that stores it, so a ticket with no row stored nothing even
// where its void failed or never ran. An upload of the tree the pack
// already holds queues no scan and is never asked about, nor is a pack an
// extension builds and stores through Knowledge.
type AdmitsKnowledge interface {
	KnowledgeAdmitter() KnowledgeAdmitter
}

// KnowledgeAdmitter and KnowledgeAdmission are the knowledge upload's
// admission types.
type (
	KnowledgeAdmitter  = api.KnowledgeAdmitter
	KnowledgeAdmission = api.KnowledgeAdmission
)

// Voice is the core's store of Writing Voices as an extension may act
// on it: the hosted Voice Writer reads the live voice it improves or
// edits and puts back the voice it wrote, and a hosted run reads the
// live voice it attaches. The data key stays in the core: an extension
// reads and hands over text. Every call answers ErrVoiceUnconfigured
// while the store is off. Deps.Voice is nil without a database.
type Voice interface {
	// Live is a person's live version, the one a run attaches, its text
	// opened; ErrVoiceNotFound when they have none. A pending or
	// flagged version is never answered here.
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

// ReportSettings is the core's store of a person's report settings as
// an extension may read them: the hosted runs read the account's report
// design and hand it to the sandbox host, whose CLI lays the run's PDFs
// out in it. Read-only: the person sets it on the Report design page.
// Deps.ReportSettings is nil without a database.
type ReportSettings interface {
	// Design is the person's report design, the canonical theme
	// document version 2 that pkg/reportdesign validated (Parse it to
	// read it), or nil when they never chose one, which is not Plain:
	// the reader decides what nothing means.
	Design(ctx context.Context, user uuid.UUID) ([]byte, error)
	// DesignWithLogo is Design with the person's logo in it, when they
	// have one: its "logo" key holds the PNG the core encoded from
	// their upload. Design leaves it out, because a reader whose
	// pkg/reportdesign predates logos refuses the key and with it the
	// whole design; hand this one only to a reader that draws logos.
	DesignWithLogo(ctx context.Context, user uuid.UUID) ([]byte, error)
	// Theme is the id of the built-in theme the person's design started
	// from (its basedOn), or "" when they never chose one.
	// Transitional: the hosted job carries a theme's name rather than
	// the design itself, and this field goes once the job carries the
	// design.
	Theme(ctx context.Context, user uuid.UUID) (string, error)
}

// Unthrottles is the optional interface for an extension whose receiver
// of signed callbacks must never be refused by the anonymous rate class
// (a payment provider's webhook). The routes are "METHOD /path"
// relative to the mount, exact; each still passes the principal
// middleware and authorizes on its own signature.
type Unthrottles interface {
	UnthrottledRoutes() []string
}

// TakesOwnTokens is an extension that mints bearer tokens of its own for
// its own routes: a credential narrower than a token of the account's,
// for a caller that can present nothing but `Authorization: Bearer`, such
// as a model client inside a run's container. The core accepts such a
// token under /api/v1/x/<name>/ alone and asks Resolve whose it is; the
// principal it becomes has Via "extension", the user's id, no scopes and
// no roles, so no route of the core's would admit it even if it reached
// one. On every other path, the core's routes and other extensions'
// mounts included, the token is "not recognized" (401).
type TakesOwnTokens interface {
	OwnTokens() OwnTokens
}

// OwnTokens is an extension's bearer token kind.
type OwnTokens struct {
	// Prefix starts every such token: "agy", one to four lowercase letters
	// and an underscore, none of the core's own (agy_, agys_, agyi_, agyv_,
	// agyd_) and none another extension claims. A wrong one panics at
	// start-up.
	Prefix string
	// Resolve says whose a token is, or false for one the extension does
	// not know (never issued, expired, ended). An error answers 500.
	Resolve func(ctx context.Context, token string) (userID uuid.UUID, ok bool, err error)
}

// Principal is the resolved caller; Principal(ctx) reads it in a route.
type Principal = auth.Principal

// Scope is a PAT scope as the core spells it; those an extension may
// require are the hosted-run scopes, the knowledge scopes, for a route
// that writes into a person's knowledge through the Knowledge seam, and
// the vault's secret:write. A session carries no scopes and the
// account's full authority; a PAT carries what it was minted with,
// flat: no scope implies another.
type Scope = auth.Scope

// The scopes an extension route may require.
const (
	ScopeRunRead        = auth.ScopeRunRead
	ScopeRunWrite       = auth.ScopeRunWrite
	ScopeKnowledgeRead  = auth.ScopeKnowledgeRead
	ScopeKnowledgeWrite = auth.ScopeKnowledgeWrite
	// ScopeSecretWrite lets a token set and delete the caller's
	// hosted-run secrets; the vault extension requires it.
	ScopeSecretWrite = auth.ScopeSecretWrite
)

// ScopeAllows is how the core reads a scope for a route: an anonymous
// caller never passes; a session passes, having the account's full
// authority (the route still checks who the account is); a PAT passes
// only when it was minted with the scope, and a schedule's credential
// (ScheduleCredentials.ForSchedule) only when the scope is one of
// auth.ScheduleScopes; a principal from Principals.ForUser, which is no
// caller, never passes. An extension route calls this with the principal
// and the scope it requires and refuses on false.
func ScopeAllows(p *Principal, s Scope) bool {
	switch {
	case p == nil || p.Anonymous || p.Via == "user":
		return false
	case p.ScopeBound():
		return auth.HasScope(p.Scopes, s)
	default:
		return true
	}
}

// Principal returns the caller the server resolved for this request:
// Anonymous when none.
func PrincipalFromContext(ctx context.Context) *Principal { return api.PrincipalFrom(ctx) }

// Event is one committed event the core fans out (api.Event): the
// webhook kinds (version.published, agent.quarantined,
// org.member_added, …) with the owning org, plus user.registered,
// user.email_verified (the account's address was confirmed, once, by
// its activation link or an invitation at an organization's domain; an
// account created verified hears only user.registered, with
// emailVerified true), user.data_cleared (clear what the extension
// holds for that user), account.erased, staff.changed and org.created.
type Event = api.Event

// The identity events.
const (
	// EventAccountErased is heard once an account's erasure has committed,
	// with UserID, the Identities it signed in with and the Email it held:
	// what an extension that keeps a copy of the person elsewhere (a
	// directory's account) needs to erase it there. It is best-effort like
	// every hook, so an extension that must not miss one enqueues a Job
	// from it and retries there.
	EventAccountErased = api.EventAccountErased
	// EventStaffChanged is heard a few seconds after the registry changed
	// someone's platform staff standing. It names nobody: read the whole
	// set (Deps.Staff), which also catches up on a change missed.
	EventStaffChanged = api.EventStaffChanged
)

// Hooks are called after the core has committed the change; they are
// best-effort and must not block — an extension that needs durability
// enqueues a Job from the hook.
type Hooks struct {
	Event func(ctx context.Context, ev Event)
}

// Job is a queue handler registered under Kind. Queue names the queue
// it is claimed from: "core" unless the work is untrusted content
// ("sandbox") or must run in the api role (QueueAPI). A positive Every
// makes the role that drains the queue enqueue Kind on that period, and
// once at start-up, the way the core's own watchdog and sweep run.
// Every replica enqueues on its own clock and the queue's claim runs
// each row once, so the handler must be idempotent — a cycle closer
// that finds nothing to close does nothing.
type Job struct {
	Kind    string
	Queue   string
	Handler queue.Handler
	Every   time.Duration
}

// QueueAPI is the queue the api role drains, for a Job that must reach
// a service only the api may reach: an admin API behind a network
// policy that admits the api alone, kept from the worker because the
// worker opens untrusted archives. The worker neither registers nor
// enqueues such a job; the single-process `all` role drains this queue
// beside its worker's. A job here runs beside the api's requests, so it
// should be light.
const QueueAPI = "api"

// Deps is what the core hands an extension at start-up, once per
// process, before its routes mount and its jobs register. DB is the
// pool the core uses, under the core's own database role: the
// convention — not yet enforced by a role or a grant — is that an
// extension writes only its own schema (ent_<name>) and reads core
// tables, never alters them; the extension's own seam test is where
// that is proven. Log is tagged with the extension's name. Audit writes
// the extension's events through the core's writer (the month
// partition, the archive stream, the refusal of an unregistered
// action); the event's actor kind, IP and user agent are the
// extension's to fill, since no request built it. DB is nil when the
// server runs without a database (limited dev mode).
type Deps struct {
	DB    *pgxpool.Pool
	Log   *slog.Logger
	Audit AuditWriter
	// Blobs is the deployment's object storage — the archive store the
	// core runs on (a local directory or S3) — for an extension to keep
	// its own objects under its own key prefix (a hosted run's inputs,
	// outputs and receipts). nil when the server runs without a
	// database, as DB is.
	Blobs BlobStore
	// Entitlements is the resolver the server uses with no extension —
	// the deployment's configured limits — for an extension's own
	// resolver to embed and answer Features over.
	Entitlements Resolver
	// Orgs is the core's organization store as an extension may act on
	// it. nil when the server runs without a database.
	Orgs Orgs
	// OrgGate is the core's organization-state gate as an extension may
	// ask it: whether an organization is there to be read or acted on.
	// A route that names an organization asks it before it answers, so a
	// suspended or erased organization is absent to an extension as it is
	// to the core's own routes. Principal.OrgRoles is a person's
	// memberships and says nothing of the organization's state. nil when
	// the server runs without a database.
	OrgGate OrgGate
	// Agents is the core's read of an agent as an extension may ask it.
	// nil when the server runs without a database.
	Agents Agents
	// Principals loads the principal the core would hold for a user,
	// for asking Agents about someone the extension holds by id rather
	// than by a live request. nil when the server runs without a
	// database.
	Principals Principals
	// ScheduleCredentials mints the credential a schedule's fire starts
	// a run with, its owner's narrow token in all but name. nil when
	// the server runs without a database.
	ScheduleCredentials ScheduleCredentials
	// Notifier carries a message an extension composed to a person,
	// under the core's rules and through the core's transport. nil when
	// the server runs without a database, as DB is.
	Notifier Notifier
	// Webhooks delivers an event to one of an organization's webhook
	// endpoints through the core's transport. nil when the server runs
	// without a database, as DB is.
	Webhooks Webhooks
	// Knowledge is the core's knowledge store. nil when the server runs
	// without a database, as DB is; while the store is off (no key
	// wrapper yet) its calls answer ErrKnowledgeUnconfigured.
	Knowledge Knowledge
	// Voice is the core's store of Writing Voices. nil when the server
	// runs without a database; while the store is off its calls answer
	// ErrVoiceUnconfigured.
	Voice Voice
	// ReportSettings is the core's store of report settings. nil when
	// the server runs without a database.
	ReportSettings ReportSettings
	// Meter is the server's meter under the extension's own scope: an
	// instrument created on it is scraped from /metrics beside the
	// core's, with the same resource labels, and leaves through OTLP
	// when that is configured. Never nil: a no-op meter when the server
	// runs without metrics or without a database.
	//
	// Name an instrument the way the core does (a CloudWatch-style
	// PascalCase name such as RunsHostedTokens, not a dotted one), and
	// begin it with the extension's own name so it cannot take one of the
	// core's: a series whose name the core already uses is dropped from
	// the scrape, and the core's is kept, but the OTLP export carries both
	// under their scopes, and a backend that ignores the scope (CloudWatch
	// EMF) would merge them. An attribute named like a resource label
	// (service.name, agentry.role, deployment.environment) is dropped from
	// the scrape. Label values must be bounded —
	// a run kind, a tier, an outcome — never a run id, a handle, a user or
	// anything a caller chooses, because every distinct value is a series
	// kept for the life of the process.
	Meter metric.Meter
	// Staff reads platform staff. nil when the server runs without a
	// database.
	Staff Staff
	// Members is the core's membership door for an extension that
	// provisions people on a directory's word. nil when the server runs
	// without a database.
	Members Members
	// RememberedBrowsers mints and checks remembered browsers under the
	// core's rules, audited under the extension's name. nil when the
	// server runs without a database.
	RememberedBrowsers RememberedBrowsers
	// Sealer seals and opens small values under a key derived from the
	// server's sealing key (auth.sealingKey) for this extension alone
	// (authenticated encryption), for an extension that must keep a
	// personal value at rest in a row, as a queued erasure keeps the
	// address it erases. It opens none of the server's own sealed values
	// and none of another extension's. Never nil.
	Sealer Sealer
	// BaseURL is the deployment's public origin, the address the core's
	// own links are built on (config baseURL, or AGENTRY_BASE_URL over
	// it), without a trailing slash: for an extension that must name an
	// address of its own to a third party, such as an OAuth callback.
	// Empty when the deployment names none.
	BaseURL string
}

// Notifier lets an extension tell a person something by mail without
// owning a transport, an address book or the rule about who may be
// written to. The core keeps all three: the address must be verified
// (nothing is ever sent to an unverified one) and the person's
// preference for the message's kind must be on. An extension composes
// the words; the core decides whether they go and frames them with the
// registry's name and the settings link. An extension's own copy
// therefore stays outside this repository, and this repository's rule
// about addresses cannot be bypassed by an extension that holds one.
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
// switch governs, wherever it came from; a notice about one of their
// schedules is what their schedules switch governs; and a notice that a
// bug report they filed is fixed is what their bug-report switch governs.
type NotifyKind string

const (
	// NotifyBilling is the hosted build's billing mail: a checkout
	// confirmed, a payment failed, an organization restricted, seats
	// reached, "your organization covers you".
	NotifyBilling NotifyKind = "billing"
	// NotifyDependencyAlert is a dependency alert an extension routes
	// to the person an organization chose for it: the same news the
	// core mails the author, under the same switch.
	NotifyDependencyAlert NotifyKind = "dependency_alert"
	// NotifySchedule is the hosted build's schedule mail: a scheduled
	// run in Agentry failed, or the schedule paused (three refusals in
	// a row, an entitlement that lapsed). Never a success.
	NotifySchedule NotifyKind = "schedule"
	// NotifyBugReport is the hosted build's bug-report mail: platform
	// staff marked a bug report the person filed complete, "Reported
	// bug fixed", quoting the report and any note staff added. Never
	// sent for a report closed without a fix.
	NotifyBugReport NotifyKind = "bug_report"
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
// fanned out as. It is what the hook hears as Event.Kind, and what an
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
	// organization in its decommission hold reads and is not
	// maintained). An agent that does not exist, one p may not read,
	// one p reads and may not maintain, and one the gate holds are the
	// same false with no error.
	Maintainable(ctx context.Context, p *Principal, namespace, name string) (AgentRef, bool, error)
	// Publishable reports whether p may add a version to the agent at
	// namespace/name as the core's own routes decide it: the publish
	// role over the namespace or a grant, a personal access token's
	// agent:publish, and the owning organization's gate for a write.
	// The publish role ranks above maintain, so a session caller who
	// may publish also maintains; a token may publish without
	// org:admin, as the desktop's and the CLI's sign-in grant does.
	// Absent, unreadable, not publishable and held by the gate are one
	// false with no error, as Maintainable's are.
	Publishable(ctx context.Context, p *Principal, namespace, name string) (AgentRef, bool, error)
}

// Principals answers who a user is now, as the core would resolve them,
// for an extension that must re-ask a role later than the request that
// gave it one: a hosted revision's release fetch asks again whether the
// run's owner may still maintain or publish to the QuickAgent. The
// extension rebuilds none of the rule (memberships, roles, the
// account's standing): the core loads them.
type Principals interface {
	// ForUser is the principal for userID with no credential: the
	// account's standing and its organization roles as they are now, as
	// a session would carry them, with Via "user", no scopes and no
	// session. Put it to Agents: Readable, Maintainable and Publishable
	// answer it on the role alone, which never exceeds what the person's
	// own session would be answered, so a role kept since an earlier check
	// is answered as before and a role taken away is gone. An account that
	// does not exist, or is not active (suspended, deleted), is false with
	// no error. It is not a credential: auth.Check and ScopeAllows refuse
	// it, as does every route that needs a session, and an extension must
	// never act for the user with it beyond asking. It satisfies no
	// organization's enforced SSO, but the agent seams do not ask for SSO
	// (only git does), so this is no SSO gate. Its answer is the role
	// alone, without the scopes of the credential an earlier request
	// carried: ask it only to re-check what that request already checked.
	ForUser(ctx context.Context, userID uuid.UUID) (*Principal, bool, error)
}

// ScheduleCredentials mints the credential of a run a schedule starts
// on its owner's behalf, with no live request to carry one. Every
// hosted run is created from a principal the runs extension authorizes
// the way it authorizes a request, and a fire must go through that same
// create path, so the fire needs a principal that is a credential:
// ForUser's is not one, and must not become one. This is a separate
// seam from Principals, so an extension that only asks about people
// never holds the means to act for them.
type ScheduleCredentials interface {
	// ForSchedule is the credential for one fire of the schedule
	// scheduleID that userID owns: the account's standing and roles as
	// they are now, as ForUser loads them, with Via "schedule",
	// ScheduleID set, and auth.ScheduleScopes as its scopes, so
	// ScopeAllows, auth.Check and the Agents seam read it as they read a
	// token minted with exactly those scopes. It carries no session, no
	// token, no SSO freshness and no platform-staff standing: a schedule
	// acts as its owner's narrow token would, never as their session. An
	// account that does not exist or is not active is false with no
	// error, so a schedule of a suspended account does not fire. A nil
	// scheduleID is an error: the credential must name what it is.
	//
	// What it reaches in the extension that holds it is that
	// extension's rule; the vault's is that a schedule sets no secret,
	// so a run it starts resolves kept secrets only. Mint one per fire
	// and keep none: the account's standing is read at the moment of
	// the fire, so an entitlement that lapsed is seen.
	ForSchedule(ctx context.Context, userID, scheduleID uuid.UUID) (*Principal, bool, error)
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
	// ForkedFrom is the origin of a fork, nil otherwise: the agent it
	// was forked from and that agent's namespace, its publisher, for
	// the earnings a fork's runs owe the origin. A fork is private, so
	// Public is false on every agent that has one.
	ForkedFrom *AgentOrigin
}

// AgentOrigin is a fork's origin as the seams name it: ids, never a path,
// and the namespace's kind so an extension can tell a person's from an
// organization's.
type AgentOrigin struct {
	AgentID       uuid.UUID
	NamespaceID   uuid.UUID
	NamespaceKind NamespaceKind
}

// Orgs holds the acts on an organization the core owns and an extension
// triggers. Where an admission extension runs, an organization is
// created awaiting activation and its creator may not create another
// until it is activated; the extension that owns the org's standing
// activates it when the subscription starts.
type Orgs interface {
	// Activate marks the organization activated. Idempotent: it reports
	// whether this call did it, and an unknown org is false with no error.
	Activate(ctx context.Context, orgID uuid.UUID) (bool, error)
	// Decommission starts the organization's decommission hold the way
	// an admin's request does: read-only for the configured hold, then
	// erased, its handle and domain released; the core fires
	// org.decommissioning now and org.decommissioned after the erasure.
	// The hosted product's pending-payment sweep calls it for an
	// organization nobody paid for. Idempotent: it reports whether this
	// call did it; an organization that is not active, or unknown, is
	// false with no error.
	Decommission(ctx context.Context, orgID uuid.UUID, reason string) (bool, error)
}

// OrgGate answers for an organization's state the way the core's own
// routes do, so that an extension mirrors none of the rule in SQL. The core
// enforces an organization's state in one place (registry.OrgGate) for its
// API, listings, SCIM and git; an extension's routes never pass through the
// core's authorization, so they ask here. An organization is active,
// suspended by platform staff, in its decommission hold (read-only for the
// configured period) or erased.
type OrgGate interface {
	// Readable reports whether the organization is there to be read: it is
	// active or in its decommission hold. A suspended organization, an
	// erased one and one that does not exist are the same false with no
	// error, and a route answers each as not found, as the core's do. An
	// error is a fault to answer as one, never as an absence.
	Readable(ctx context.Context, orgID uuid.UUID) (bool, error)
	// Writable reports whether an act that changes the organization or
	// spends what it holds is permitted: only an active organization
	// permits it. One in its decommission hold is readable and not
	// writable; a suspended, erased or unknown one is neither.
	Writable(ctx context.Context, orgID uuid.UUID) (bool, error)
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

// ManagesDirectory is the optional interface for an extension that is the
// deployment's directory: the service that holds people's sign-in
// accounts. Its Directory is what the registry asks of a directory
// (api.Directory): erasure, and the superseded-account check. The rules
// stay the core's, the records the directory's. One extension at most; a
// nil Directory leaves the deployment without one. The directory's own
// sign-in work (its claims, remembered browsers, the checks its flows make,
// a staff mirror) is the extension's, through HearsSignIn,
// ReceivesCallbacks and EventStaffChanged.
type ManagesDirectory interface {
	Directory() Directory
}

// Directory and the types it speaks are the core's directory port.
type (
	Directory            = api.Directory
	DirectoryLink        = api.DirectoryLink
	DirectoryLookup      = api.DirectoryLookup
	DirectoryDevice      = api.DirectoryDevice
	DirectorySignInFacts = api.DirectorySignInFacts
	DirectorySource      = api.DirectorySource
	DirectoryAccount     = api.DirectoryAccount
)

// The rules a directory lookup ends by; the last three left an account the
// person may hold in place, which erasure reports as unresolved.
const (
	DirectoryLookupByID          = api.DirectoryLookupByID
	DirectoryLookupByUID         = api.DirectoryLookupByUID
	DirectoryLookupByAddress     = api.DirectoryLookupByAddress
	DirectoryLookupAddressShared = api.DirectoryLookupAddressShared
	DirectoryLookupIDMismatch    = api.DirectoryLookupIDMismatch
	DirectoryLookupSuperuser     = api.DirectoryLookupSuperuser
)

// ReceivesCallbacks is the optional interface for an extension that serves
// calls from a service of its own, such as its directory's sign-in flow
// asking whether a browser is remembered. They are mounted under
// /internal/x/<name>/, outside /api/, where no edge shipped with the
// registry routes, and the core holds the gate (api.ExtensionCallbacks):
// the secret as a bearer token, 404 to a request that came through a
// proxy or while the secret is unset, the declared rate class. A handler
// there has no Principal: its caller is infrastructure, not a person.
type ReceivesCallbacks interface {
	Callbacks() Callbacks
}

// Callbacks is an extension's callback mount.
type Callbacks = api.ExtensionCallbacks

// The rate classes a callback mount may draw from: none, for a caller that
// speaks for everyone signing in, or the anonymous bucket per address.
const (
	CallbackRateNone = api.RateNone
	CallbackRateAnon = api.RateAnon
)

// HearsSignIn is the optional interface for an extension that hears every
// sign-in through an individual provider that the callback gives a session,
// with every claim of the ID token, once the account is resolved and
// before the session is issued: a cookie it sets rides the session's
// response, SignIn.RememberBrowser mints a remembered browser from this
// sign-in's own evidence, and SignIn.AssertSSO says the sign-in came
// through an organization's own single sign-on, so that the session
// satisfies the organization's enforced SSO. It cannot refuse the sign-in,
// and it runs in the callback, so it is quick.
type HearsSignIn interface {
	SignedIn(ctx context.Context, in SignIn)
}

// SignIn is a sign-in as HearsSignIn hears it.
type SignIn = api.SignIn

// Staff is the read side of platform staff, which the registry alone
// decides (the staff organization's rule): for an extension that mirrors
// it somewhere else, on EventStaffChanged and on its own period.
type Staff interface {
	// Members lists every active account that is platform staff with a
	// verified address, by handle.
	Members(ctx context.Context) ([]StaffMember, error)
}

// StaffMember is one member of platform staff: account, handle, verified
// address (lower-cased).
type StaffMember = api.StaffMember

// Members is the core's membership door for an extension that learns from
// a directory whom an organization's identity provider provisioned and
// deprovisioned. The extension decides whom to name; what provisioning and
// deprovisioning do stays the core's: a provisioned person is only ever a
// pending member, whom an admin approves (seats count then), and a
// deprovisioned one loses the membership and every live credential at once.
type Members interface {
	// Provision makes the person a pending member of orgID: the account at
	// their address, or a new one with the address taken as verified on
	// the extension's word, so name only addresses the organization's
	// identity provider may vouch for. An existing membership, pending or
	// active, is left as it is. ErrOrgNotProvisionable for an organization
	// that is unknown, suspended or being decommissioned;
	// ErrAddressUnproven when the account at the address has not proved
	// it; ErrStaffOrgDomain for an address the staff organization does not
	// admit.
	Provision(ctx context.Context, orgID uuid.UUID, p ProvisionedMember) (userID uuid.UUID, err error)
	// Deprovision takes userID's membership of orgID away and revokes
	// their org-bound tokens for orgID, every session and every
	// remembered browser, in one transaction, audited. The organization's
	// last admin keeps the membership and those credentials are revoked
	// all the same; kept says so.
	// Idempotent.
	Deprovision(ctx context.Context, orgID, userID uuid.UUID) (kept bool, err error)
}

// ProvisionedMember is a person an organization's identity provider
// provisioned: their address, the name the provider calls them by (a seed
// for a new account's handle) and a display name.
type ProvisionedMember = api.ProvisionedMember

// The refusals of Members.Provision.
var (
	ErrOrgNotProvisionable = api.ErrOrgNotProvisionable
	ErrAddressUnproven     = api.ErrAddressUnproven
	ErrStaffOrgDomain      = registry.ErrStaffOrgDomain
)

// RememberedBrowsers is the core's remembered-browser credential as an
// extension may use it: a browser that answered the second factor at its
// directory may skip it there next time. One is minted only at a sign-in,
// by SignIn.RememberBrowser, from the verified token's own evidence (`amr`
// naming a second factor, `auth_time` minutes old), so no extension can
// mint one for an account on its own word. The core keeps the rules:
// stored only as its SHA-256, bound to one active account, an absolute
// lifetime, every use audited before it is granted.
type RememberedBrowsers interface {
	// Use reports whether token is a live remembered browser of userID's,
	// recording the use first. An error means the store could not answer:
	// treat it as no.
	Use(r *http.Request, userID uuid.UUID, token string) (bool, error)
}

// Sealer is the server's sealer as an extension uses it. Open refuses a
// value sealed under another key or changed since it was sealed.
type Sealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// DirectoryErasure is the optional interface for an extension's Directory
// that carries out the directory half of an erasure itself, retries
// included (api.DirectoryErasure): the core calls EraseErased once after
// the registry's erasure commits, in place of its own attempt and retry
// job, and reports the outcome it returns on the erasure's response.
type DirectoryErasure = api.DirectoryErasure

// ErasedAccount is what EraseErased is told of the erased account.
type ErasedAccount = api.ErasedAccount

// The outcomes EraseErased may return; any other is left off the response.
const (
	DirectoryErasureDeleted       = api.DirectoryErasureDeleted
	DirectoryErasureNotFound      = api.DirectoryErasureNotFound
	DirectoryErasureUnresolved    = api.DirectoryErasureUnresolved
	DirectoryErasureNotConfigured = api.DirectoryErasureNotConfigured
	DirectoryErasureFailed        = api.DirectoryErasureFailed
	DirectoryErasurePending       = api.DirectoryErasurePending
)

// ErrNoSecondFactor is SignIn.RememberBrowser's refusal of a sign-in whose
// token shows no second factor answered just now.
var ErrNoSecondFactor = api.ErrNoSecondFactor

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
