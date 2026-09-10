package gitsrv

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/ratelimit"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/store"
)

// Handler serves the git smart-HTTP surface (§6.1): info/refs,
// git-upload-pack, git-receive-pack. Auth is PAT-only Basic; sessions are
// never accepted on git endpoints (CSRF hygiene).
type Handler struct {
	cfg   config.Config
	st    *store.Store
	repos *RepoStore
	reg   *registry.Service
	aud   *audit.Writer
	log   *slog.Logger
	// sem bounds concurrent git subprocesses instance-wide, perRepo bounds
	// them per repository (§6.2: a semaphore per repo and global).
	sem     chan struct{}
	perRepo *repoSemaphores
	// opTimeout bounds one git operation; postReceiveTimeout bounds the
	// bookkeeping that outlives the request (afterReceive).
	opTimeout          time.Duration
	postReceiveTimeout time.Duration
	// diskUsage measures a repo; a field so tests can force its failure path.
	diskUsage func(uuid.UUID) (int64, error)
	// queue, when set, receives one repo.pushed job per accepted push and
	// the bookkeeping runs from the queue (agentry#43). nil keeps the
	// inline path.
	queue queue.Client
	// PostReceive is invoked after a successful push with the updated refs
	// (M3 wires tag→submission here).
	PostReceive func(ctx context.Context, agent registry.Agent, refs []RefUpdate, pusher *auth.Principal)
	// pushes enforces the §19 60-pushes-per-hour-per-repo budget. Per
	// process, so an N-replica git fleet allows roughly N× that (D-06:
	// Redis replaces this on multi-node SaaS).
	pushes *ratelimit.Buckets
	// mx records §16.2 git op counts, durations, concurrency and the §16.1
	// clone first-byte SLI. nil is a working no-op.
	mx *metrics.Metrics
	// inflight is the live count behind the GitOpConcurrency gauge.
	inflight atomic.Int64
}

// SetMetrics wires the §16.2 instrument set.
func (h *Handler) SetMetrics(m *metrics.Metrics) { h.mx = m }

// Close releases the push-limiter's collector goroutine.
func (h *Handler) Close() error {
	if h == nil {
		return nil
	}
	return h.pushes.Close()
}

// NewHandler assembles the git HTTP layer.
// SetQueue makes push bookkeeping a durable repo.pushed job (agentry#43).
func (h *Handler) SetQueue(q queue.Client) { h.queue = q }

func NewHandler(cfg config.Config, st *store.Store, repos *RepoStore, reg *registry.Service, aud *audit.Writer, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{
		cfg: cfg, st: st, repos: repos, reg: reg, aud: aud, log: log,
		sem:                make(chan struct{}, globalGitConcurrency),
		perRepo:            newRepoSemaphores(perRepoGitConcurrency),
		opTimeout:          5 * time.Minute,
		postReceiveTimeout: 2 * time.Minute,
		diskUsage:          repos.DiskUsage,
		// The idle TTL must exceed the one-hour push window: a bucket evicted
		// sooner comes back full, which would let a repo at its limit reset
		// the budget simply by pausing.
		pushes: ratelimit.New(2 * time.Hour),
	}
}

// pushesPerHour is the §19 per-repo push budget from config, with the shipped
// default when unset.
func (h *Handler) pushesPerHour() int {
	if n := h.cfg.Limits.GitPushesPerHour; n > 0 {
		return n
	}
	return 60
}

// Mount registers the git routes on a mux (shared in `all`, alone in `git`).
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /{ns}/{repo}/info/refs", h.infoRefs)
	mux.HandleFunc("POST /{ns}/{repo}/git-upload-pack", h.uploadPack)
	mux.HandleFunc("POST /{ns}/{repo}/git-receive-pack", h.receivePack)
}

// resolve parses {ns}/{name}.git, loads the agent, resolves the principal
// (Basic PAT only), and authorizes the operation.
func (h *Handler) resolve(w http.ResponseWriter, r *http.Request, act auth.Action) (registry.Agent, *auth.Principal, auth.AgentRole, bool) {
	ns := r.PathValue("ns")
	repo := r.PathValue("repo")
	name, ok := strings.CutSuffix(repo, ".git")
	if !ok {
		http.NotFound(w, r)
		return registry.Agent{}, nil, auth.AgentRoleNone, false
	}

	principal := &auth.Principal{Anonymous: true}
	if _, pass, okBasic := r.BasicAuth(); okBasic && pass != "" {
		if !auth.IsPAT(pass) {
			h.unauthorized(w)
			return registry.Agent{}, nil, auth.AgentRoleNone, false
		}
		p, err := auth.ResolvePAT(r.Context(), h.st.Queries(), pass)
		if err != nil {
			h.unauthorized(w)
			return registry.Agent{}, nil, auth.AgentRoleNone, false
		}
		principal = p
	}

	agent, role, denial := h.authorizeGit(r.Context(), ns, name, principal, act)
	if denial != nil {
		switch denial.status {
		case http.StatusUnauthorized:
			h.unauthorized(w)
		case http.StatusNotFound:
			http.NotFound(w, r)
		default:
			http.Error(w, denial.message, denial.status)
		}
		return registry.Agent{}, nil, auth.AgentRoleNone, false
	}
	return agent, principal, role, true
}

// gitDenial is why a git operation is refused, in HTTP terms so the two
// transports (smart HTTP, SSH — agentry#70) report the same decision.
type gitDenial struct {
	status  int
	message string
}

// authorizeGit resolves ns/name, lazily initializes the bare repo, and
// applies §6.4 (agent permission by effective role, existence privacy for
// private repos) and §12.4 (enforced SSO needs an org-bound token for
// mutations). Transport-independent: HTTP and SSH both call it.
func (h *Handler) authorizeGit(ctx context.Context, ns, name string, principal *auth.Principal, act auth.Action) (registry.Agent, auth.AgentRole, *gitDenial) {
	agent, err := h.reg.Resolve(ctx, ns, name)
	if err != nil {
		// 404 before auth probing for truly unknown paths is fine for
		// public repos; for private ones we must not reveal existence:
		// fall through to auth so anonymous gets 401 either way below.
		agent = registry.Agent{}
	}
	if agent.ID == [16]byte{} {
		// Unknown path: 404 for anonymous+public probing parity, 404 for
		// authed too (nothing to leak — path simply doesn't exist).
		if principal.Anonymous && act != auth.ActAgentRepoRead {
			return registry.Agent{}, auth.AgentRoleNone, &gitDenial{http.StatusUnauthorized, "unauthorized"}
		}
		return registry.Agent{}, auth.AgentRoleNone, &gitDenial{http.StatusNotFound, "not found"}
	}

	// Lazy bare-repo init (§13.3: only the git role mounts repo storage).
	if _, statErr := os.Stat(h.repos.Path(agent.RepoID)); statErr != nil {
		if err := h.repos.InitBare(ctx, agent.RepoID, agent.DefaultBranch); err != nil {
			h.log.Error("lazy repo init", "err", err)
			return registry.Agent{}, auth.AgentRoleNone, &gitDenial{http.StatusInternalServerError, "internal error"}
		}
	}

	role, err := h.reg.EffectiveRole(ctx, principal, agent)
	if err != nil {
		h.log.Error("git effective role", "err", err)
		return registry.Agent{}, auth.AgentRoleNone, &gitDenial{http.StatusInternalServerError, "internal error"}
	}
	res := auth.AgentResource{Public: agent.Visibility == "public", EffectiveRole: role}
	if err := auth.CheckAgent(principal, res, act); err != nil {
		if principal.Anonymous {
			return registry.Agent{}, auth.AgentRoleNone, &gitDenial{http.StatusUnauthorized, "unauthorized"}
		}
		// Hide private repos from unauthorized principals (§6.4 table
		// implies existence-privacy for read; write denial on a repo
		// you can read is a plain 403).
		if act == auth.ActAgentRepoRead {
			return registry.Agent{}, auth.AgentRoleNone, &gitDenial{http.StatusNotFound, "not found"}
		}
		return registry.Agent{}, auth.AgentRoleNone, &gitDenial{http.StatusForbidden, "forbidden"}
	}

	// §6.4 + §12.4: in an org that enforces SSO, mutating git operations
	// additionally require an org-bound PAT.
	allowed, err := h.ssoAllows(ctx, principal, agent, act)
	if err != nil {
		h.log.Error("git sso gate", "err", err)
		return registry.Agent{}, auth.AgentRoleNone, &gitDenial{http.StatusInternalServerError, "internal error"}
	}
	if !allowed {
		return registry.Agent{}, auth.AgentRoleNone, &gitDenial{http.StatusForbidden, "forbidden: this organization requires an org-bound token"}
	}
	return agent, role, nil
}

// ssoAllows applies an org's enforced-SSO policy to a git operation (§12.4).
// It is deliberately narrower than the API chokepoint: §6.4's table attaches
// the org-bound-token requirement to push (and to the publish permission that
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

func (h *Handler) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="agentry git", charset="UTF-8"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// infoRefs implements GET /{ns}/{name}.git/info/refs?service=… (§6.1).
func (h *Handler) infoRefs(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	var act auth.Action
	switch service {
	case "git-upload-pack":
		act = auth.ActAgentRepoRead
	case "git-receive-pack":
		act = auth.ActAgentRepoWrite
	default:
		// Dumb protocol disabled (§6.1).
		http.Error(w, "smart protocol only", http.StatusForbidden)
		return
	}
	agent, principal, role, ok := h.resolve(w, r, act)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.opTimeout)
	defer cancel()

	args := []string{strings.TrimPrefix(service, "git-"), "--stateless-rpc", "--advertise-refs", h.repos.Path(agent.RepoID)}
	cmd := exec.CommandContext(ctx, h.repos.GitBin(), args...)
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
	if err := h.runLimited(ctx, agent.RepoID, cmd); err != nil {
		h.log.Error("info/refs", "err", err, "stderr", stderr.String())
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
	agent, principal, role, ok := h.resolve(w, r, auth.ActAgentRepoRead)
	if !ok {
		return
	}
	h.rpc(w, r, agent, principal, role, "upload-pack", nil)
}

// receivePack implements POST git-receive-pack (push). Ref policy is
// enforced by the pre-receive hook (hooks.go) with request context passed
// via environment; post-push bookkeeping happens here.
func (h *Handler) receivePack(w http.ResponseWriter, r *http.Request) {
	agent, principal, role, ok := h.resolve(w, r, auth.ActAgentRepoWrite)
	if !ok {
		return
	}
	// §19: 60 pushes/h per repo. Enforced HERE, at the admission point, rather
	// than in the pre-receive hook: the hook is a fresh process per push with
	// no shared state, so a bucket there would be empty every time. Refusing
	// before the git subprocess starts also means a repo being hammered costs
	// nothing but a 429.
	//
	// Burst is the full hourly budget: §19 says "60 pushes/h", not "one per
	// minute", and a developer landing a run of commits should not be paced.
	res := h.pushes.Allow("push", agent.RepoID.String(),
		ratelimit.PerHour(h.pushesPerHour()), h.pushesPerHour())
	if !res.OK {
		h.mx.RecordGitOp(r.Context(), "receive-pack", "throttled", 0)
		w.Header().Set("Retry-After", strconv.Itoa(int(res.Reset.Round(time.Second)/time.Second)))
		http.Error(w, "This repository is over its hourly push limit. Retry after the delay in the Retry-After header.", http.StatusTooManyRequests)
		return
	}
	var cmds bytes.Buffer
	h.rpc(w, r, agent, principal, role, "receive-pack", &cmds)
}

// rpc runs the stateless git service, streaming request→stdin, stdout→response.
// When cmdCapture is non-nil (receive-pack), the leading pkt-line command
// section is captured for post-receive processing.
func (h *Handler) rpc(w http.ResponseWriter, r *http.Request, agent registry.Agent, principal *auth.Principal, role auth.AgentRole, service string, cmdCapture *bytes.Buffer) {
	ctx, cancel := context.WithTimeout(r.Context(), h.opTimeout)
	defer cancel()

	// §16.2 git op telemetry. outcome is set on the way out of each branch so
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

	cmd := exec.CommandContext(ctx, h.repos.GitBin(), service, "--stateless-rpc", h.repos.Path(agent.RepoID))
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
	release, err := h.acquireGit(ctx, agent.RepoID)
	if err != nil {
		outcome = "busy"
		http.Error(w, "git busy", http.StatusServiceUnavailable)
		return
	}
	defer release()
	if err := cmd.Start(); err != nil {
		outcome = "error"
		h.log.Error("git start", "service", service, "err", err)
		http.Error(w, "git error", http.StatusInternalServerError)
		return
	}
	// §16.1 SLI: p95 first-byte under 2 s for a clone. Measured from the
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
		h.log.Warn("git rpc exit", "service", service, "err", err, "stderr", stderr.String())
		return
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
// actually landed, and hands them to the M3 publication trigger.
//
// Two properties this function owns (§6.3):
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
	// Durable first (§6.3 repo.pushed, agentry#43): one INSERT, and the
	// size/audit bookkeeping survives a crash of this process. Without a
	// queue — or if the INSERT itself fails — do it inline as before.
	enqueued := false
	if h.queue != nil {
		if _, err := h.queue.Enqueue(ctx, KindRepoPushed, "core", args); err != nil {
			h.log.Error("post-receive enqueue", "err", err)
		} else {
			enqueued = true
			// Housekeeping later, when the burst is over (agentry#55).
			if _, err := h.queue.Enqueue(ctx, KindRepoGC, "core", RepoGCArgs{RepoID: agent.RepoID}, queue.WithDelay(gcDelay)); err != nil {
				h.log.Warn("post-receive gc enqueue", "err", err)
			}
		}
	}
	if !enqueued {
		bk := &PushBookkeeper{st: h.st, repos: h.repos, aud: h.aud, log: h.log, diskUsage: h.diskUsage}
		if err := bk.Run(ctx, args); err != nil {
			h.log.Error("post-receive bookkeeping", "err", err)
		}
	}
	if h.PostReceive != nil {
		h.PostReceive(ctx, agent, refs, principal)
	}

	// §6.3: a new v* tag with auto-publish enabled submits the version.
	// Runs inline for now — the M4 queue moves this to a worker job. The
	// push already succeeded; submission failures surface via the version
	// (or its absence) in the API, and in logs.
	if agent.AutoPublishTags && agent.QuarantineState == "none" {
		for _, ru := range refs {
			tag, ok := strings.CutPrefix(ru.Ref, "refs/tags/")
			if !ok || !strings.HasPrefix(tag, "v") || ru.New == zeroOID {
				continue
			}
			e := audit.Event{Actor: principal.UserID, ActorKind: audit.ActorPAT}
			if _, err := h.reg.SubmitTag(ctx, principal, agent, tag, e); err != nil {
				h.log.Warn("auto-publish submit", "tag", tag, "err", err)
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
		h.log.Error("post-receive ref verify", "err", err)
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
// repo:write-only PAT cannot create v* tags even for an owner (§6.4).
func (h *Handler) gitEnv(r *http.Request, agent registry.Agent, principal *auth.Principal, role auth.AgentRole) []string {
	return h.gitEnvFor(r.Context(), r.Header.Get("Git-Protocol"), agent, principal, role)
}

// gitEnvFor is gitEnv for any transport (agentry#70): gitProtocol is the
// client's Git-Protocol header / GIT_PROTOCOL env request.
func (h *Handler) gitEnvFor(ctx context.Context, gitProtocol string, agent registry.Agent, principal *auth.Principal, role auth.AgentRole) []string {
	canPublish := auth.CheckAgent(principal,
		auth.AgentResource{Public: agent.Visibility == "public", EffectiveRole: role},
		auth.ActAgentPublish) == nil
	if canPublish && agent.NamespaceKind == "org" {
		// Enforced SSO gates release just as it gates push (§6.4, §12.4);
		// a lookup failure denies the stricter permission, never grants it.
		allowed, err := h.ssoAllows(ctx, principal, agent, auth.ActAgentPublish)
		if err != nil {
			h.log.Error("git sso gate (publish)", "err", err)
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
		// §6.3 agent setting (agentry#48): maintainers may allow non-fast-forward
		// pushes to the default branch; deletion stays denied regardless.
		fmt.Sprintf("AGENTRY_HOOK_ALLOW_FORCE=%t", agent.AllowForcePush),
	)
	return env
}

func (h *Handler) runLimited(ctx context.Context, repoID uuid.UUID, cmd *exec.Cmd) error {
	release, err := h.acquireGit(ctx, repoID)
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
