package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/httpmux"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/webhook"
)

// The extension seam (pkg/extension): a closed build mounts routes
// under /api/v1/x/<name>/ behind the same principal middleware, hears the
// events the core commits, and shows up in GET /meta. Nothing here runs in
// the core build unless something registers.

// Event is one committed event the core fans out to extensions: the org
// webhook kinds (version.published, agent.quarantined, org.member_added,
// org.policy_updated, …) carrying the owning org, plus user.registered,
// user.data_cleared, account.erased, staff.changed and org.created.
// Payload is the same map the webhook carries.
type Event struct {
	Kind    string
	OrgID   uuid.UUID // uuid.Nil for a personal namespace or a user event
	AgentID uuid.UUID // set for agent transitions
	UserID  uuid.UUID // set for user.registered, user.data_cleared and account.erased
	Payload map[string]any
	// Identities and Email are set for account.erased: the subjects the
	// account signed in with at individual providers ("<provider>:<sub>"),
	// oldest first, and the address it held. The account holds neither
	// address nor name by the time the event is heard, so this is the only
	// place an extension can learn them from.
	Identities []string
	Email      string
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

// AccountErasureKind says which of the core's two account clears an
// AccountEraser is called from: the account's erasure (POST /user/delete)
// or the clearing of its data (POST /user/clear-data), each named by the
// audit action that records it.
type AccountErasureKind string

// The two account clears.
const (
	AccountErased      = AccountErasureKind(audit.ActionUserDelete)
	AccountDataCleared = AccountErasureKind(audit.ActionUserDataClear)
)

// ErasureTx is the erasure's transaction as an eraser may use it:
// statements, and nothing that ends it. An eraser that could commit would
// commit the core's erasure half-done; one that could roll back would
// leave the core's later statements failing on a dead transaction.
type ErasureTx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// erasureTx narrows a pgx.Tx to ErasureTx, so an eraser cannot assert its
// way back to Commit.
type erasureTx struct{ tx pgx.Tx }

func (t erasureTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return t.tx.Exec(ctx, sql, args...)
}

func (t erasureTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return t.tx.Query(ctx, sql, args...)
}

func (t erasureTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return t.tx.QueryRow(ctx, sql, args...)
}

// AccountEraser deletes what an extension keeps about an account, inside
// the core's own transaction, and says how many rows went. An error rolls
// the whole erasure or clear back.
type AccountEraser func(ctx context.Context, tx ErasureTx, userID uuid.UUID, kind AccountErasureKind) (int64, error)

type namedEraser struct {
	name  string
	erase AccountEraser
}

// AddAccountEraser registers an extension's eraser (pkg/extension.
// ErasesAccounts), called in registration order inside the
// transaction of every account erasure and data clear.
// A name registered twice panics: the counts are keyed by it.
func (s *Server) AddAccountEraser(name string, fn AccountEraser) {
	for _, e := range s.accountErasers {
		if e.name == name {
			panic("api: account eraser registered twice: " + name)
		}
	}
	s.accountErasers = append(s.accountErasers, namedEraser{name: name, erase: fn})
}

// AccountErasers names the extensions whose erasers are registered, in
// the order they run.
func (s *Server) AccountErasers() []string {
	names := make([]string, len(s.accountErasers))
	for i, e := range s.accountErasers {
		names[i] = e.name
	}
	return names
}

// eraseInExtensions runs every registered eraser in tx. The counts, keyed
// by extension, are for the audit event's detail; nil when none is
// registered, so a core with no extension records exactly what it did.
func (s *Server) eraseInExtensions(ctx context.Context, tx pgx.Tx, userID uuid.UUID, kind AccountErasureKind) (map[string]int64, error) {
	if len(s.accountErasers) == 0 {
		return nil, nil
	}
	counts := make(map[string]int64, len(s.accountErasers))
	for _, e := range s.accountErasers {
		n, err := e.erase(ctx, erasureTx{tx}, userID, kind)
		if err != nil {
			return nil, fmt.Errorf("extension %s: erase account: %w", e.name, err)
		}
		counts[e.name] = n
	}
	return counts, nil
}

// SetExtensionUnthrottled names the routes of a mounted extension the
// anonymous rate class does not apply to: "METHOD /path", relative to the
// mount, exact (no wildcards — the seam is narrow on purpose). Only an
// extension's own receiver of signed callbacks belongs here; the route
// still passes the principal middleware
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

// ExtensionDeps is what an extension gets to work with (pkg/extension.Deps):
// the pool the core uses, the logger, and an audit writer
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

// orgsAwaitActivation reports whether an organization created now starts
// out awaiting activation. It does where an admission
// extension runs — the hosted product, where an organization is a paid
// thing and the extension that admits submissions is the one that sells
// it — and not on a registry that admits everything, where nothing would
// ever activate it.
func (s *Server) orgsAwaitActivation() bool {
	return s.reg != nil && s.reg.HasAdmitter()
}

// ActivateOrg marks an organization activated (pkg/extension.Deps.Orgs):
// the extension that owns its standing calls it when the subscription
// starts, and from then on the account that created the org may create
// another. Idempotent: an organization already activated, or unknown, is
// left alone and reported as false.
func (s *Server) ActivateOrg(ctx context.Context, orgID uuid.UUID) (bool, error) {
	if s.st == nil {
		return false, errors.New("api: no database to activate the organization in")
	}
	n, err := s.q().ActivateOrg(ctx, orgID)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// BaseURL is the deployment's public origin without a trailing slash, as
// the core's own links use it, for pkg/extension.Deps.
func (s *Server) BaseURL() string { return strings.TrimRight(s.cfg.BaseURL, "/") }

// Blobs is the deployment's object store for pkg/extension.Deps:
// nil when the server was built without a database, the
// way ExtensionDeps' pool is.
func (s *Server) Blobs() registry.BlobStore { return s.blobs }

// ExtensionSealer is a sealer for one extension's small values at rest,
// under a key derived from auth.sealingKey for that extension alone: it
// opens none of the server's own sealed values (webhook secrets, sign-in
// state) and none of another extension's.
func (s *Server) ExtensionSealer(name string) (*auth.Sealer, error) {
	return s.sealer.For("extension " + name)
}

// AgentReadable is the core's read of an agent for pkg/extension.Deps.Agents:
// whether p may read the agent at ns/name exactly as the
// core's own routes decide it — the effective role over the namespace and
// the grants (auth.CheckAgent), a PAT's agent:read, the owning
// organization's state (suspended: absent; in its hold: readable) — with
// the agent when they may. An agent that does not exist and one p may not
// read are the same false, never an error: an extension gets no way to
// tell a private agent's existence the core's routes would not give.
func (s *Server) AgentReadable(ctx context.Context, p *auth.Principal, ns, name string) (registry.Agent, bool, error) {
	if s.reg == nil {
		return registry.Agent{}, false, errors.New("api: no registry to read agents from")
	}
	// For a read, agentForAction answers a refused caller with ErrNotFound
	// and the organization's state with a gate error; anything else is a
	// fault the extension must answer as one, never as an absence.
	a, _, err := s.agentForAction(ctx, p, ns, name, auth.ActAgentRead)
	var gate *registry.OrgGateError
	switch {
	case err == nil:
		return a, true, nil
	case errors.Is(err, registry.ErrNotFound), errors.As(err, &gate):
		return registry.Agent{}, false, nil
	}
	return registry.Agent{}, false, err
}

// AgentMaintainable is the core's own maintain decision for an extension:
// agentForAction with the maintain action, the organization
// gate for a write included. Not found, not readable, readable but not
// maintainable and held by the gate are all false with no error, as a
// read's are in AgentReadable; anything else is a fault.
func (s *Server) AgentMaintainable(ctx context.Context, p *auth.Principal, ns, name string) (registry.Agent, bool, error) {
	if s.reg == nil {
		return registry.Agent{}, false, errors.New("api: no registry to read agents from")
	}
	a, _, err := s.agentForAction(ctx, p, ns, name, auth.ActAgentMaintain)
	var gate *registry.OrgGateError
	switch {
	case err == nil:
		return a, true, nil
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, auth.ErrForbidden), errors.Is(err, auth.ErrUnauthorized), errors.As(err, &gate):
		return registry.Agent{}, false, nil
	}
	return registry.Agent{}, false, err
}

// AgentPublishable is the core's own publish decision for an extension,
// shaped as AgentMaintainable: agentForAction with the
// publish action (the publish role over the namespace or a grant, a PAT's
// agent:publish), the organization gate for a write included. Not found,
// not readable, readable but not publishable and held by the gate are all
// false with no error; anything else is a fault.
func (s *Server) AgentPublishable(ctx context.Context, p *auth.Principal, ns, name string) (registry.Agent, bool, error) {
	if s.reg == nil {
		return registry.Agent{}, false, errors.New("api: no registry to read agents from")
	}
	a, _, err := s.agentForAction(ctx, p, ns, name, auth.ActAgentPublish)
	var gate *registry.OrgGateError
	switch {
	case err == nil:
		return a, true, nil
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, auth.ErrForbidden), errors.Is(err, auth.ErrUnauthorized), errors.As(err, &gate):
		return registry.Agent{}, false, nil
	}
	return registry.Agent{}, false, err
}

// PrincipalForUser is the principal the core would hold for userID with no
// credential presented, for pkg/extension.Deps.Principals: the
// account's current standing and memberships as a session would carry them
// — loaded now, so a role taken away since an earlier request is gone — with
// Via "user", no scopes and no session. An account that does not exist or
// is not active is false with no error, as a session of it would not
// resolve. It is a question to put to the Agents seam about a user an
// extension holds by id (a hosted run's owner at the release prefix), never
// a credential: auth.Check refuses Via "user", so it authorizes no route,
// and it satisfies no organization's enforced SSO.
func (s *Server) PrincipalForUser(ctx context.Context, userID uuid.UUID) (*auth.Principal, bool, error) {
	return s.loadPrincipal(ctx, userID)
}

// PrincipalForSchedule is pkg/extension.Deps.ScheduleCredentials: the
// credential of one fire of a
// schedule its owner made in the closed build. It is PrincipalForUser's
// account, standing and roles, loaded now, with Via "schedule", the
// schedule's id, and auth.ScheduleScopes — every scope gate reads it as a
// token minted with exactly those (auth.Principal.ScopeBound). The
// account's platform-staff standing is dropped: a schedule starts its
// owner's run and nothing that standing would add. An account that does
// not exist or is not active is false with no error, so a suspended
// owner's schedule does not fire; a nil schedule id is an error, because a
// credential that names nothing could not be told from another in audit.
func (s *Server) PrincipalForSchedule(ctx context.Context, userID, scheduleID uuid.UUID) (*auth.Principal, bool, error) {
	if scheduleID == uuid.Nil {
		return nil, false, errors.New("api: a schedule credential needs the schedule's id")
	}
	p, ok, err := s.loadPrincipal(ctx, userID)
	if err != nil || !ok {
		return nil, ok, err
	}
	p.Via = "schedule"
	p.ScheduleID = scheduleID
	p.Scopes = auth.ScheduleScopes()
	p.PlatformStaff = false
	return p, true, nil
}

// loadPrincipal is the account as a credential-less principal, Via "user":
// what PrincipalForUser hands out and PrincipalForSchedule narrows.
func (s *Server) loadPrincipal(ctx context.Context, userID uuid.UUID) (*auth.Principal, bool, error) {
	if s.st == nil {
		return nil, false, errors.New("api: no database to load the user from")
	}
	u, err := s.q().GetUserByID(ctx, userID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	case u.State != "active":
		return nil, false, nil
	}
	roles, err := s.loadOrgRoles(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	return &auth.Principal{
		UserID:        userID,
		Handle:        u.Handle,
		Via:           "user",
		OrgRoles:      roles,
		EmailVerified: u.EmailVerifiedAt != nil,
		Unactivated:   auth.Unactivated(u.EmailVerifiedAt, u.Email),
		PlatformStaff: u.PlatformStaff,
	}, true, nil
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

func (s *Server) mountExtensions(mux httpmux.Mux) {
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
		// Not Mount: the names are the extensions', so no entry in
		// authz_routes.go can list them. The prefix rule declares this mount
		// point and the extension's own matrix declares what sits behind it.
		mux.Handle(prefix+"/", s.principalMiddlewareOpts(http.StripPrefix(prefix, sub), principalOpts{unthrottled: unthrottled}))
	}
}

// SendToUser is the core's side of pkg/extension.Deps.Notifier.Send:
// a message an
// extension composed goes to the person only under the core's rule —
// notify.AllowsEmail, which is the verified-address rule and
// the person's switch for the kind — and only as a kind the core knows.
// It reports whether the message went; a suppression is false with no
// error, and the extension is not told why, because the address is the
// person's business and the switch is their choice. An unknown kind is
// refused outright: an extension sends as the classes it was given, so a
// billing notice cannot dress itself as a quarantine.
func (s *Server) SendToUser(ctx context.Context, userID uuid.UUID, kind, subject, text string) (bool, error) {
	if s.st == nil {
		return false, errors.New("api: no database to read the recipient from")
	}
	k, ok := extensionMailKinds[kind]
	if !ok {
		return false, fmt.Errorf("api: %q is not a kind an extension may send as", kind)
	}
	if strings.TrimSpace(subject) == "" || strings.TrimSpace(text) == "" {
		return false, errors.New("api: a message needs a subject and a body")
	}
	if !notify.AllowsEmail(ctx, s.q(), s.log, userID, k) {
		return false, nil
	}
	u, err := s.q().GetUserByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("api: recipient: %w", err)
	}
	if err := s.notifier.Rendered(ctx, notify.RenderedNotice{ToEmail: u.Email, Subject: subject, Text: text, Kind: k}); err != nil {
		return false, err
	}
	return true, nil
}

// extensionMailKinds is every class an extension may send as. It is the
// trust boundary, which is why the key is a plain string: what arrives
// here is the extension's word, and the map is the allowlist that turns
// it into a kind the core recognises — or refuses. The core's
// own other kinds stay the core's, and a new class is added here with
// its switch, its default and its column, never by a string an extension
// chooses.
var extensionMailKinds = map[string]notify.Kind{
	"billing": notify.KindBilling,
	// A dependency alert an extension routes to the person an
	// organization chose for it goes under the same
	// switch as the alert the core mails the author: it is the same
	// news, and the person's choice about that news holds wherever it
	// comes from.
	"dependency_alert": notify.KindDependencyAlert,
	// A scheduled run in Agentry that failed, or a schedule that paused
	// the schedules extension's mail, under its own
	// switch, so a person can silence it without losing billing mail.
	"schedule": notify.KindSchedule,
	// A bug report the person filed, marked complete by platform staff
	// the bug-reports extension's
	// "Reported bug fixed" mail, under its own switch.
	"bug_report": notify.KindBugReport,
}

// OrgAdminIDs is pkg/extension.Deps.Notifier.OrgAdmins: the active
// administrators of an organization. Pending administrators are left
// out — they hold nothing of the organization until approved — and an
// organization that does not exist is an empty list, not an error, so
// the seam cannot be used to tell one from the other.
func (s *Server) OrgAdminIDs(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	if s.st == nil {
		return nil, errors.New("api: no database to read memberships from")
	}
	ids, err := s.q().ListOrgAdminIDs(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("api: org admins: %w", err)
	}
	return ids, nil
}

// WebhookEndpointRef is an organization's webhook endpoint as an
// extension may name one (pkg/extension.Webhooks): what identifies it
// and what it subscribes to, and nothing that could deliver to it
// outside the core's transport — the secret stays in the row.
type WebhookEndpointRef struct {
	ID     uuid.UUID
	URL    string
	Events []string
	Active bool
}

// WebhookEndpoints is pkg/extension.Deps.Webhooks.Endpoints: the
// organization's endpoints, active or not, newest first. An organization
// that does not exist has none, not an error, the shape OrgAdminIDs has.
func (s *Server) WebhookEndpoints(ctx context.Context, orgID uuid.UUID) ([]WebhookEndpointRef, error) {
	if s.st == nil {
		return nil, errors.New("api: no database to read endpoints from")
	}
	rows, err := s.q().ListWebhookEndpoints(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("api: org webhook endpoints: %w", err)
	}
	out := make([]WebhookEndpointRef, 0, len(rows))
	for _, ep := range rows {
		out = append(out, WebhookEndpointRef{ID: ep.ID, URL: ep.Url, Events: ep.Events, Active: ep.Active})
	}
	return out, nil
}

// DeliverWebhook is pkg/extension.Deps.Webhooks.Deliver:
// one delivery of event to the endpoint an extension named, through the
// core's transport — the ledger row, the queued job with its signature,
// its retries and its SSRF guard — so a destination an organization
// chose for an extension's purpose is written to exactly the way its
// subscriptions are. It reports whether a delivery was recorded: an
// endpoint that is not this organization's, or is switched off, is false
// with no error — a destination that has gone stale, which the extension
// may report but cannot repair — and an event outside the catalog is
// refused, because a consumer's documentation is the core's promise.
func (s *Server) DeliverWebhook(ctx context.Context, orgID, endpointID uuid.UUID, event string, data any) (bool, error) {
	if s.st == nil || s.webhooks == nil {
		return false, errors.New("api: no webhook transport to deliver through")
	}
	if !webhook.ValidEvent(event) {
		return false, fmt.Errorf("api: %q is not an event of the webhook catalog", event)
	}
	ep, err := s.q().GetWebhookEndpoint(ctx, storegen.GetWebhookEndpointParams{ID: endpointID, OrgID: orgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("api: webhook endpoint: %w", err)
	}
	if !ep.Active {
		return false, nil
	}
	if err := s.webhooks.Deliver(ctx, ep.ID, event, data); err != nil {
		return false, err
	}
	return true, nil
}
