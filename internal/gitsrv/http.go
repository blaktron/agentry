package gitsrv

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/httpmux"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/ratelimit"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Handler serves the git smart-HTTP surface: info/refs, git-upload-pack,
// git-receive-pack. Auth is PAT-only Basic; sessions are
// never accepted on git endpoints (CSRF hygiene).
type Handler struct {
	cfg   config.Config
	st    *store.Store
	repos *RepoStore
	reg   *registry.Service
	aud   *audit.Writer
	log   *slog.Logger
	// sem bounds concurrent git subprocesses instance-wide, perRepo bounds
	// them per repository, and perClient per trusted client address.
	// nil perClient (tests) leaves only the first two.
	sem       chan struct{}
	perRepo   *repoSemaphores
	perClient *clientSemaphores
	// opTimeout bounds one git operation; postReceiveTimeout bounds the
	// bookkeeping that outlives the request (afterReceive).
	opTimeout          time.Duration
	postReceiveTimeout time.Duration
	// diskUsage measures a repo; a field so tests can force its failure path.
	diskUsage func(uuid.UUID) (int64, error)
	// queue, when set, receives one repo.pushed job per accepted push and
	// the bookkeeping runs from the queue. nil keeps the
	// inline path.
	queue queue.Client
	// PostReceive is invoked after a successful push with the updated refs
	// (the registry wires tag→submission here).
	PostReceive func(ctx context.Context, agent registry.Agent, refs []RefUpdate, pusher *auth.Principal)
	// pushes enforces the 60-pushes-per-hour-per-repo budget on both
	// transports; keyOffers bounds the public keys one source address may
	// offer the SSH listener (ssh.go). Per process, so an N-replica git
	// fleet allows roughly N× each (holding the budget across replicas
	// needs a shared store). Two stores because their windows differ by two
	// orders of magnitude and the idle TTL must exceed the window: a
	// stranger's address is forgotten two minutes after it stops offering
	// keys, a repository's budget only two hours after its last push.
	pushes    *ratelimit.Buckets
	keyOffers *ratelimit.Buckets
	// mx records git op counts, durations, concurrency and the clone
	// first-byte SLI. nil is a working no-op.
	mx *metrics.Metrics
	// inflight is the live count behind the GitOpConcurrency gauge.
	inflight atomic.Int64
}

// SetMetrics wires the git instrument set.
func (h *Handler) SetMetrics(m *metrics.Metrics) { h.mx = m }

// Close releases the two bucket stores' collector goroutines.
func (h *Handler) Close() error {
	if h == nil {
		return nil
	}
	return errors.Join(h.pushes.Close(), h.keyOffers.Close())
}

// SetQueue makes push bookkeeping a durable repo.pushed job.
func (h *Handler) SetQueue(q queue.Client) { h.queue = q }

// NewHandler assembles the git HTTP layer.
func NewHandler(cfg config.Config, st *store.Store, repos *RepoStore, reg *registry.Service, aud *audit.Writer, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{
		cfg: cfg, st: st, repos: repos, reg: reg, aud: aud, log: log,
		sem:                make(chan struct{}, globalGitConcurrency),
		perRepo:            newRepoSemaphores(perRepoGitConcurrency),
		perClient:          newClientSemaphores(gitConcurrentPerIP(cfg)),
		opTimeout:          5 * time.Minute,
		postReceiveTimeout: 2 * time.Minute,
		diskUsage:          repos.DiskUsage,
		// The idle TTL must exceed the one-hour push window: a bucket evicted
		// sooner comes back full, which would let a repo at its limit reset
		// the budget simply by pausing.
		pushes:    ratelimit.New(2 * time.Hour),
		keyOffers: ratelimit.New(2 * time.Minute),
	}
}

// gitConcurrentPerIP is the per-address budget of concurrent git
// operations from config, with the shipped default when unset.
func gitConcurrentPerIP(cfg config.Config) int {
	if n := cfg.Limits.GitConcurrentPerIP; n > 0 {
		return n
	}
	return 20
}

// gitClient is the address a git operation over smart HTTP is budgeted to:
// the one the middleware resolved after the trusted-proxy decision
// (http.trustedProxyCIDRs), so a client cannot pick its own
// by sending X-Forwarded-For. A handler reached without that middleware
// (tests) falls back to the peer.
func gitClient(r *http.Request) string {
	if ip := auth.ClientIPFrom(r.Context()); ip != "" {
		return ip
	}
	return clientHost(r.RemoteAddr)
}

// refuseClientBusy answers an address at its budget. 429, not 503: the
// instance is not busy, this address is.
func refuseClientBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	http.Error(w, errClientBusy.Error(), http.StatusTooManyRequests)
}

// pushesPerHour is the per-repo push budget from config, with the shipped
// default when unset.
func (h *Handler) pushesPerHour() int {
	if n := h.cfg.Limits.GitPushesPerHour; n > 0 {
		return n
	}
	return 60
}

// Mount registers the git routes on a mux (shared in `all`, alone in `git`).
// The mux is an interface so the api role can hand over one that records what
// it was given: that recording is what its authorization completeness gate
// reads, and these routes are not part of the OpenAPI surface the gate
// walks.
func (h *Handler) Mount(mux httpmux.Mux) {
	mux.HandleFunc("GET /{ns}/{repo}/info/refs", h.infoRefs)
	mux.HandleFunc("POST /{ns}/{repo}/git-upload-pack", h.uploadPack)
	mux.HandleFunc("POST /{ns}/{repo}/git-receive-pack", h.receivePack)
}

// resolve parses {ns}/{name}.git, loads the agent, resolves the principal
// (Basic PAT only), and authorizes the operation.
func (h *Handler) resolve(w http.ResponseWriter, r *http.Request, act auth.Action) (registry.Agent, *auth.Principal, auth.AgentRole, refView, bool) {
	ns := r.PathValue("ns")
	repo := r.PathValue("repo")
	name, ok := strings.CutSuffix(repo, ".git")
	if !ok {
		http.NotFound(w, r)
		return registry.Agent{}, nil, auth.AgentRoleNone, refView{}, false
	}

	principal := &auth.Principal{Anonymous: true}
	if _, pass, okBasic := r.BasicAuth(); okBasic && pass != "" {
		if !auth.IsPAT(pass) {
			h.unauthorized(w)
			return registry.Agent{}, nil, auth.AgentRoleNone, refView{}, false
		}
		p, err := auth.ResolvePAT(r.Context(), h.st.Queries(), pass)
		if err != nil {
			h.unauthorized(w)
			return registry.Agent{}, nil, auth.AgentRoleNone, refView{}, false
		}
		principal = p
	}

	agent, role, view, denial := h.authorizeGit(r.Context(), ns, name, principal, act)
	if denial != nil {
		switch denial.status {
		case http.StatusUnauthorized:
			h.unauthorized(w)
		case http.StatusNotFound:
			http.NotFound(w, r)
		default:
			http.Error(w, denial.message, denial.status)
		}
		return registry.Agent{}, nil, auth.AgentRoleNone, refView{}, false
	}
	return agent, principal, role, view, true
}

// gitDenial is why a git operation is refused, in HTTP terms so the two
// transports (smart HTTP, SSH) report the same decision.
type gitDenial struct {
	status  int
	message string
}

// refView is the repository a reader is served. The zero value is the
// agent's own. A reader who holds no role on a public agent (an anonymous
// caller, or a signed-in one with no grant and no membership) is served a
// separate repository holding only the tags that point at a reviewed
// version's commit and the objects they reach: no branch, and no tag or
// object of a version that is pending, rejected, blocked or quarantined.
// Hiding refs in the agent's own repository would not do: upload-pack
// serves an object a client names by id even when no advertised ref
// reaches it.
type refView struct {
	path string // the reviewed-only repository; "" for the agent's own
}

// repoPath is the repository a git command for this view runs in.
func (v refView) repoPath(repos *RepoStore, agent registry.Agent) string {
	if v.path != "" {
		return v.path
	}
	return repos.Path(agent.RepoID)
}

// authorizeGit resolves ns/name, lazily initializes the bare repo, and
// applies agent permission by effective role, existence privacy for
// private repos, the reviewed-only view of a public agent for a reader
// with no role on it, and enforced SSO (which needs an org-bound token for
// mutations). Transport-independent: HTTP and SSH both call it.
func (h *Handler) authorizeGit(ctx context.Context, ns, name string, principal *auth.Principal, act auth.Action) (registry.Agent, auth.AgentRole, refView, *gitDenial) {
	agent, err := h.reg.Resolve(ctx, ns, name)
	if err != nil {
		// 404 before auth probing for truly unknown paths is fine for
		// public repos; for private ones we must not reveal existence:
		// fall through to auth so anonymous gets 401 either way below.
		agent = registry.Agent{}
	}
	if agent.ID == [16]byte{} {
		// Unknown path. An anonymous client gets the same 401 a private
		// repo gives it (below), so the two cannot be told apart by
		// probing — and a git client that does hold
		// credentials sends them on that 401 and gets its real answer. A
		// signed-in caller gets 404: nothing to leak, the path is not there.
		if principal.Anonymous {
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusUnauthorized, "unauthorized"}
		}
		return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusNotFound, "not found"}
	}

	// The owning organization's state: the same gate the API consults. Suspended is an unknown path — anonymous gets the
	// credential prompt, a signed-in caller 404 — and the decommission
	// hold takes reads only.
	if err := h.reg.OrgGateFor(ctx, agent, act); err != nil {
		var gate *registry.OrgGateError
		switch {
		case errors.As(err, &gate) && gate.Absent():
			if principal.Anonymous {
				return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusUnauthorized, "unauthorized"}
			}
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusNotFound, "not found"}
		case errors.As(err, &gate):
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusForbidden, "forbidden: this organization is being decommissioned and its repositories are read-only"}
		default:
			h.log.ErrorContext(ctx, "git org gate", "err", err)
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusInternalServerError, "internal error"}
		}
	}

	// Lazy bare-repo init (only the git role mounts repo storage).
	// Not for a fork still being copied: its repository is
	// the worker's to make, and is refused below until it has.
	copying := agent.ForkState != nil && *agent.ForkState == registry.ForkCopying
	if _, statErr := os.Stat(h.repos.Path(agent.RepoID)); statErr != nil && !copying {
		if err := h.repos.InitBare(ctx, agent.RepoID, agent.DefaultBranch); err != nil {
			h.log.ErrorContext(ctx, "lazy repo init", "err", err)
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusInternalServerError, "internal error"}
		}
	}

	role, err := h.reg.EffectiveRole(ctx, principal, agent)
	if err != nil {
		h.log.ErrorContext(ctx, "git effective role", "err", err)
		return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusInternalServerError, "internal error"}
	}
	res := auth.AgentResource{Public: agent.Visibility == "public", EffectiveRole: role}
	if err := auth.CheckAgent(principal, res, act); err != nil {
		if principal.Anonymous {
			// The credential prompt; the same answer an unknown path gives.
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusUnauthorized, "unauthorized"}
		}
		// A signed-in caller who cannot read the repo gets a missing
		// path's 404 whatever they tried (existence privacy); a
		// write denied on a repo they can read is a 403.
		if auth.CheckAgent(principal, res, auth.ActAgentRepoRead) != nil {
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusNotFound, "not found"}
		}
		return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusForbidden, "forbidden"}
	}

	// A reader with no role on a public agent sees only what passed review,
	// and an agent with nothing reviewed is, to them, a missing path.
	var view refView
	if role == auth.AgentRoleNone && !copying {
		tags, head, err := h.reviewedTags(ctx, agent)
		if err != nil {
			h.log.ErrorContext(ctx, "git reviewed tags", "err", err)
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusInternalServerError, "internal error"}
		}
		if len(tags) == 0 {
			if principal.Anonymous {
				return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusUnauthorized, "unauthorized"}
			}
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusNotFound, "not found"}
		}
		path, err := h.repos.ReviewedView(ctx, agent.RepoID, tags, head)
		if err != nil {
			h.log.ErrorContext(ctx, "git reviewed view", "err", err)
			return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusInternalServerError, "internal error"}
		}
		view = refView{path: path}
	}

	// A fork's repository is the worker's until its copy is done:
	// a push now would be wiped by the copy, or a tag would
	// be submitted in place of the origin's content. Said only to a caller
	// who may read it, so it names no fork to anyone else.
	if copying {
		return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusConflict, "this fork is still being copied; try again in a minute"}
	}

	// An unactivated account reads but does not write: the API's gate does
	// not see git.
	if act == auth.ActAgentRepoWrite && principal.Unactivated && h.cfg.Auth.ExternalOnly {
		return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusForbidden, "forbidden: activate your account first, from the link we emailed you"}
	}

	// In an org that enforces SSO, mutating git operations
	// additionally require an org-bound PAT.
	allowed, err := h.ssoAllows(ctx, principal, agent, act)
	if err != nil {
		h.log.ErrorContext(ctx, "git sso gate", "err", err)
		return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusInternalServerError, "internal error"}
	}
	if !allowed {
		return registry.Agent{}, auth.AgentRoleNone, refView{}, &gitDenial{http.StatusForbidden, "forbidden: this organization requires an org-bound token"}
	}
	return agent, role, view, nil
}

// ssoAllows applies an org's enforced-SSO policy to a git operation.
// It is deliberately narrower than the API chokepoint: the org-bound-token
// requirement attaches to push (and to the publish permission that
// creates v* tags), so clone/fetch — including anonymous reads of public org
// repos and granted reads of private ones — is unaffected. Sessions are never
// accepted on git endpoints, so in practice this resolves to "the PAT must be
// bound to this org"; going through Principal.SSOSatisfied keeps the
// semantics identical to internal/api's gate rather than restating them.
func (h *Handler) ssoAllows(ctx context.Context, p *auth.Principal, agent registry.Agent, act auth.Action) (bool, error) {
	switch act {
	case auth.ActAgentRepoWrite, auth.ActAgentPublish:
	default:
		return true, nil
	}
	if agent.NamespaceKind != "org" || p == nil || p.Anonymous || h.st == nil {
		return true, nil
	}
	org, err := h.st.Queries().GetOrgByID(ctx, agent.NamespaceID)
	if err != nil {
		return false, fmt.Errorf("gitsrv: org lookup: %w", err)
	}
	if !org.SsoRequired {
		return true, nil
	}
	return p.SSOSatisfied(agent.NamespaceID, h.cfg.Auth.SSOMaxAge), nil
}

// reviewedVersionStatuses are the statuses of a version that passed the
// gate or a reviewer: published, and yanked, which the registry still
// serves by exact pin.
var reviewedVersionStatuses = []string{"published", "yanked"}

// reviewedTags maps each of the agent's tags that points, peeled, at the
// commit of a reviewed version to the tag's own object id, and names as
// head the commit of the newest reviewed version that has such a tag. An
// agent the platform has blocked or quarantined has none, and so has a
// version admitted without a scan: no review passed it.
func (h *Handler) reviewedTags(ctx context.Context, agent registry.Agent) (tags map[string]string, head string, err error) {
	if agent.QuarantineState != "none" {
		return nil, "", nil
	}
	versions, err := h.st.Queries().ListVersionsByStatus(ctx, storegen.ListVersionsByStatusParams{
		AgentID: agent.ID, Statuses: reviewedVersionStatuses,
	})
	if err != nil {
		return nil, "", fmt.Errorf("gitsrv: reviewed versions: %w", err)
	}
	var commits []string // newest first
	for _, v := range versions {
		if v.CommitSha != "" && v.ScanStatus == "pipeline" {
			commits = append(commits, v.CommitSha)
		}
	}
	if len(commits) == 0 {
		return nil, "", nil
	}
	all, err := h.repos.Tags(ctx, agent.RepoID)
	if err != nil {
		return nil, "", err
	}
	tagged := make(map[string]bool)
	tags = make(map[string]string)
	for ref, t := range all {
		if slices.Contains(commits, t.Commit) {
			tags[ref] = t.Object
			tagged[t.Commit] = true
		}
	}
	for _, c := range commits {
		if tagged[c] {
			return tags, c, nil
		}
	}
	return nil, "", nil
}

func (h *Handler) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="agentry git", charset="UTF-8"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// infoRefs implements GET /{ns}/{name}.git/info/refs?service=…
func (h *Handler) infoRefs(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	var act auth.Action
	switch service {
	case "git-upload-pack":
		act = auth.ActAgentRepoRead
	case "git-receive-pack":
		act = auth.ActAgentRepoWrite
	default:
		// Dumb protocol disabled.
		http.Error(w, "smart protocol only", http.StatusForbidden)
		return
	}
	agent, principal, role, view, ok := h.resolve(w, r, act)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.opTimeout)
	defer cancel()

	cmd, done, err := h.repos.Command(ctx, strings.TrimPrefix(service, "git-"), "--stateless-rpc", "--advertise-refs", view.repoPath(h.repos, agent))
	if err != nil {
		h.log.ErrorContext(r.Context(), "git hooks unavailable", "service", service, "err", err)
		http.Error(w, "git error", http.StatusInternalServerError)
		return
	}
	defer done()
	cmd.Env = h.gitEnv(r, agent, principal, role)

	// The advertisement is buffered rather than streamed on purpose: it is
	// small (one pkt-line per ref, bounded by the ref count of a ≤100 MB
	// repo) and buffering keeps the ability to answer a failed git with a
	// 500 — once the smart-HTTP prelude is written the status is committed
	// and a client can only be told "success, no refs". The push path, where
	// bodies are large, streams (see rpc).
	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := h.runLimited(ctx, agent.RepoID, gitClient(r), cmd); err != nil {
		if errors.Is(err, errClientBusy) {
			refuseClientBusy(w)
			return
		}
		h.log.ErrorContext(r.Context(), "info/refs", "err", err, "stderr", stderr.String())
		http.Error(w, "git error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
	w.Header().Set("Cache-Control", "no-cache")
	// Smart-HTTP prelude: pkt-line "# service=…" + flush.
	_, _ = fmt.Fprintf(w, "%04x# service=%s\n0000", len(service)+15, service)
	_, _ = io.Copy(w, &out)
}

// uploadPack implements POST git-upload-pack (clone/fetch).
func (h *Handler) uploadPack(w http.ResponseWriter, r *http.Request) {
	agent, principal, role, view, ok := h.resolve(w, r, auth.ActAgentRepoRead)
	if !ok {
		return
	}
	h.rpc(w, r, agent, principal, role, view, "upload-pack", nil)
}

// receivePack implements POST git-receive-pack (push). Ref policy is
// enforced by the pre-receive hook (hooks.go) with request context passed
// via environment; post-push bookkeeping happens here.
func (h *Handler) receivePack(w http.ResponseWriter, r *http.Request) {
	agent, principal, role, view, ok := h.resolve(w, r, auth.ActAgentRepoWrite)
	if !ok {
		return
	}
	if retry, ok := h.admitPush(r.Context(), agent); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds(retry)))
		http.Error(w, pushBudgetRefusal(retry), http.StatusTooManyRequests)
		return
	}
	var cmds bytes.Buffer
	h.rpc(w, r, agent, principal, role, view, "receive-pack", &cmds)
}

// admitPush spends one push from the repository's push budget (60/h per
// repo) and reports whether the push may proceed; when it may not, retry
// is how long until the budget next admits one. It is the one admission
// point for every transport — smart HTTP and SSH both call it — so the
// budget is one number wherever the push arrives. It sits
// here rather than in the pre-receive hook because the hook is a fresh
// process per push with no shared state, so a bucket there would be
// empty every time; refusing before the git subprocess starts also means
// a repository being hammered costs nothing but the refusal.
//
// Burst is the full hourly budget: the limit is "60 pushes/h", not "one per
// minute", and a developer landing a run of commits should not be paced.
func (h *Handler) admitPush(ctx context.Context, agent registry.Agent) (retry time.Duration, ok bool) {
	res := h.pushes.Allow("push", agent.RepoID.String(),
		ratelimit.PerHour(h.pushesPerHour()), h.pushesPerHour())
	if res.OK {
		return 0, true
	}
	h.mx.RecordGitOp(ctx, "receive-pack", "throttled", 0)
	h.log.InfoContext(ctx, "rate limited", logevent.HTTPRateLimited.Attr(), "class", "push", "agent", agent.ID)
	return res.Reset, false
}

// pushBudgetRefusal is what the pusher reads on either transport when the
// repository's push budget is spent.
func pushBudgetRefusal(retry time.Duration) string {
	return fmt.Sprintf("This repository is over its hourly push limit. Retry in %d seconds.", retrySeconds(retry))
}

// retrySeconds rounds a wait to whole seconds, never below one: a
// Retry-After of zero has the client spin.
func retrySeconds(d time.Duration) int {
	if n := int(d.Round(time.Second) / time.Second); n > 0 {
		return n
	}
	return 1
}

// rpc runs the stateless git service, streaming request→stdin, stdout→response.
// When cmdCapture is non-nil (receive-pack), the leading pkt-line command
// section is captured for post-receive processing.
func (h *Handler) rpc(w http.ResponseWriter, r *http.Request, agent registry.Agent, principal *auth.Principal, role auth.AgentRole, view refView, service string, cmdCapture *bytes.Buffer) {
	ctx, cancel := context.WithTimeout(r.Context(), h.opTimeout)
	defer cancel()

	// Git op telemetry. outcome is set on the way out of each branch so
	// a refused or failed operation is distinguishable from a served one.
	start := time.Now()
	outcome := "ok"
	h.mx.RecordGitConcurrency(ctx, service, h.inflight.Add(1))
	defer func() {
		h.mx.RecordGitConcurrency(ctx, service, h.inflight.Add(-1))
		h.mx.RecordGitOp(ctx, service, outcome, time.Since(start))
	}()

	body := r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip body", http.StatusBadRequest)
			return
		}
		defer func() { _ = gz.Close() }()
		body = gz
	}

	var stdin io.Reader = body
	if cmdCapture != nil {
		stdin = io.TeeReader(body, newCommandCapture(cmdCapture))
	}

	cmd, done, err := h.repos.Command(ctx, service, "--stateless-rpc", view.repoPath(h.repos, agent))
	if err != nil {
		outcome = "error"
		h.log.ErrorContext(r.Context(), "git hooks unavailable", "service", service, "err", err)
		http.Error(w, "git error", http.StatusInternalServerError)
		return
	}
	defer done()
	cmd.Env = h.gitEnv(r, agent, principal, role)
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	w.Header().Set("Content-Type", fmt.Sprintf("application/x-git-%s-result", service))
	w.Header().Set("Cache-Control", "no-cache")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		outcome = "error"
		http.Error(w, "git error", http.StatusInternalServerError)
		return
	}
	release, err := h.acquireGit(ctx, agent.RepoID, gitClient(r))
	if errors.Is(err, errClientBusy) {
		outcome = "throttled"
		refuseClientBusy(w)
		return
	}
	if err != nil {
		outcome = "busy"
		http.Error(w, "git busy", http.StatusServiceUnavailable)
		return
	}
	defer release()
	if err := cmd.Start(); err != nil {
		outcome = "error"
		h.log.ErrorContext(r.Context(), "git start", "service", service, "err", err)
		http.Error(w, "git error", http.StatusInternalServerError)
		return
	}
	// SLI: p95 first-byte under 2 s for a clone. Measured from the
	// start of the request, so it includes both the semaphore wait and git's
	// own startup — which is what a client actually experiences, and the
	// reason a queued clone must not look fast.
	var packOut io.Reader = stdout
	if service == "upload-pack" {
		packOut = &firstByteTimer{r: stdout, start: start, record: func(d time.Duration) {
			h.mx.RecordGitCloneFirstByte(ctx, d)
		}}
	}
	_, _ = io.Copy(w, packOut)
	err = cmd.Wait()
	if err != nil {
		outcome = "error"
		// Headers are already sent; the pkt-line stream carries the error
		// report to the client. Log for operators.
		h.log.WarnContext(r.Context(), "git rpc exit", "service", service, "err", err, "stderr", stderr.String())
		return
	}
	// git exits 0 on a push its pre-receive hook declined, and what it says
	// about why — a hook that could not even start, above all — goes to its
	// own stderr, which smart HTTP never shows the pusher.
	if stderr.Len() > 0 {
		h.log.WarnContext(r.Context(), "git rpc stderr", "service", service, "stderr", stderr.String())
	}

	if service == "receive-pack" {
		h.afterReceive(r.Context(), agent, principal, cmdCapture)
	}
}

// firstByteTimer records how long the first byte of pack data took to arrive.
// It wraps the git subprocess's stdout rather than the ResponseWriter because
// the writer has already had the smart-HTTP prelude written to it — timing
// that would measure our own header, not git's work.
type firstByteTimer struct {
	r      io.Reader
	start  time.Time
	record func(time.Duration)
	fired  bool
}

func (f *firstByteTimer) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if n > 0 && !f.fired {
		f.fired = true
		f.record(time.Since(f.start))
	}
	return n, err
}

// afterReceive updates repo bookkeeping and audit for the ref updates a push
// actually landed, and hands them to the publication trigger.
//
// Two properties this function owns:
//
//   - Only ACCEPTED updates count. receive-pack exits 0 even when the
//     pre-receive hook rejects the whole push — the refusal is reported per
//     ref as `ng` in report-status — so the requested command list is not
//     evidence that anything changed. acceptedRefs re-reads the refs from the
//     repository; a wholly rejected push writes no audit row, moves no
//     last_push_at, and auto-publishes no tag.
//   - The work outlives the request. A client that disconnects the moment it
//     has the report must not cancel the size update, the audit row or tag
//     auto-publish, so the caller's context is detached here (values kept,
//     cancellation dropped) and given a deadline of its own. Detaching inside
//     afterReceive — not at the call site — keeps the property from being
//     lost by a future caller.
func (h *Handler) afterReceive(ctx context.Context, agent registry.Agent, principal *auth.Principal, cmds *bytes.Buffer) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), h.postReceiveTimeout)
	defer cancel()

	refs := h.acceptedRefs(ctx, agent, parseReceiveCommands(cmds.Bytes()))
	if len(refs) == 0 {
		return
	}

	refNames := make([]string, 0, len(refs))
	for _, ru := range refs {
		refNames = append(refNames, ru.Ref)
	}
	args := RepoPushedArgs{AgentID: agent.ID, RepoID: agent.RepoID, ActorID: principal.UserID, Refs: refNames}
	if agent.NamespaceKind == "org" {
		args.OrgID = agent.NamespaceID
	}
	// Durable first (repo.pushed): one INSERT, and the size/audit
	// bookkeeping survives a crash of this process. Without a queue — or if
	// the INSERT itself fails — do it inline.
	enqueued := false
	if h.queue != nil {
		if _, err := h.queue.Enqueue(ctx, KindRepoPushed, "core", args); err != nil {
			h.log.ErrorContext(ctx, "post-receive enqueue", "err", err)
		} else {
			enqueued = true
			// Housekeeping later, when the burst is over.
			if _, err := h.queue.Enqueue(ctx, KindRepoGC, "core", RepoGCArgs{RepoID: agent.RepoID}, queue.WithDelay(gcDelay)); err != nil {
				h.log.WarnContext(ctx, "post-receive gc enqueue", "err", err)
			}
		}
	}
	if !enqueued {
		bk := &PushBookkeeper{st: h.st, repos: h.repos, aud: h.aud, log: h.log, diskUsage: h.diskUsage}
		if err := bk.Run(ctx, args); err != nil {
			h.log.ErrorContext(ctx, "post-receive bookkeeping", "err", err)
		}
	}
	if h.PostReceive != nil {
		h.PostReceive(ctx, agent, refs, principal)
	}

	// A new v* tag with auto-publish enabled submits the version: the
	// archive is built here and the scan is handed to the worker's sandbox
	// queue. The push already succeeded; submission failures
	// surface via the version (or its absence) in the API, and in logs.
	if agent.AutoPublishTags && agent.QuarantineState == "none" {
		for _, ru := range refs {
			tag, ok := strings.CutPrefix(ru.Ref, "refs/tags/")
			if !ok || !strings.HasPrefix(tag, "v") || ru.New == zeroOID {
				continue
			}
			e := audit.Event{Actor: principal.UserID, ActorKind: audit.ActorPAT}
			if _, err := h.reg.SubmitTag(ctx, principal, agent, tag, e); err != nil {
				// This includes an admission refusal (registry.ErrAdmissionRefused):
				// receive-pack has already answered the client, so the pusher
				// learns of it from the absent version, as with every other
				// submission failure here.
				h.log.WarnContext(ctx, "auto-publish refused", logevent.GitPushRefused.Attr(),
					"agent", agent.ID, "tag", tag, "err", err)
			}
		}
	}
}

// acceptedRefs narrows the ref updates a client asked for to the ones the
// repository now reflects: a create/update must be present at the requested
// object id, a delete must be gone. On any doubt (the ref listing fails) it
// returns nothing — bookkeeping is skipped rather than invented.
func (h *Handler) acceptedRefs(ctx context.Context, agent registry.Agent, want []RefUpdate) []RefUpdate {
	if len(want) == 0 {
		return nil
	}
	names := make([]string, 0, len(want))
	for _, ru := range want {
		names = append(names, ru.Ref)
	}
	have, err := h.repos.RefsAt(ctx, agent.RepoID, names)
	if err != nil {
		h.log.ErrorContext(ctx, "post-receive ref verify", "err", err)
		return nil
	}
	accepted := make([]RefUpdate, 0, len(want))
	for _, ru := range want {
		cur, exists := have[ru.Ref]
		if ru.New == zeroOID {
			if !exists {
				accepted = append(accepted, ru)
			}
			continue
		}
		if exists && cur == ru.New {
			accepted = append(accepted, ru)
		}
	}
	return accepted
}

// gitEnv builds the subprocess environment: protocol v2 plus the hook
// context (hooks.go) describing the pusher's permissions and quotas.
// CAN_PUBLISH goes through the chokepoint so PAT scope limits apply: a
// repo:write-only PAT cannot create v* tags even for an owner.
func (h *Handler) gitEnv(r *http.Request, agent registry.Agent, principal *auth.Principal, role auth.AgentRole) []string {
	return h.gitEnvFor(r.Context(), r.Header.Get("Git-Protocol"), agent, principal, role)
}

// gitEnvFor is gitEnv for any transport: gitProtocol is the
// client's Git-Protocol header / GIT_PROTOCOL env request.
func (h *Handler) gitEnvFor(ctx context.Context, gitProtocol string, agent registry.Agent, principal *auth.Principal, role auth.AgentRole) []string {
	canPublish := auth.CheckAgent(principal,
		auth.AgentResource{Public: agent.Visibility == "public", EffectiveRole: role},
		auth.ActAgentPublish) == nil
	if canPublish && agent.NamespaceKind == "org" {
		// Enforced SSO gates release just as it gates push;
		// a lookup failure denies the stricter permission, never grants it.
		allowed, err := h.ssoAllows(ctx, principal, agent, auth.ActAgentPublish)
		if err != nil {
			h.log.ErrorContext(ctx, "git sso gate (publish)", "err", err)
		}
		canPublish = allowed && err == nil
	}
	env := append(os.Environ(),
		"GIT_PROTOCOL="+gitProtocol,
		"AGENTRY_HOOK_BIN="+h.repos.hookBin,
		"AGENTRY_HOOK_DEFAULT_BRANCH="+agent.DefaultBranch,
		fmt.Sprintf("AGENTRY_HOOK_CAN_PUBLISH=%t", canPublish),
		fmt.Sprintf("AGENTRY_HOOK_MAX_BLOB_BYTES=%d", h.cfg.Limits.RepoMaxBlobBytes),
		fmt.Sprintf("AGENTRY_HOOK_QUOTA_BYTES=%d", h.cfg.Limits.RepoQuotaBytes),
		fmt.Sprintf("AGENTRY_HOOK_WARN_BYTES=%d", h.cfg.Limits.RepoWarnBytes),
		// Agent setting: maintainers may allow non-fast-forward
		// pushes to the default branch; deletion stays denied regardless.
		fmt.Sprintf("AGENTRY_HOOK_ALLOW_FORCE=%t", agent.AllowForcePush),
	)
	return env
}

func (h *Handler) runLimited(ctx context.Context, repoID uuid.UUID, client string, cmd *exec.Cmd) error {
	release, err := h.acquireGit(ctx, repoID, client)
	if err != nil {
		return err
	}
	defer release()
	return cmd.Run()
}

// RefUpdate is one receive-pack command (old, new, ref).
type RefUpdate struct {
	Old, New, Ref string
}
