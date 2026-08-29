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
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
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
	// PostReceive is invoked after a successful push with the updated refs
	// (M3 wires tag→submission here).
	PostReceive func(ctx context.Context, agent registry.Agent, refs []RefUpdate, pusher *auth.Principal)
}

// NewHandler assembles the git HTTP layer.
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
	}
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

	agent, err := h.reg.Resolve(r.Context(), ns, name)
	if err != nil {
		// 404 before auth probing for truly unknown paths is fine for
		// public repos; for private ones we must not reveal existence:
		// fall through to auth so anonymous gets 401 either way below.
		agent = registry.Agent{}
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

	if agent.ID == [16]byte{} {
		// Unknown path: 404 for anonymous+public probing parity, 404 for
		// authed too (nothing to leak — path simply doesn't exist).
		if principal.Anonymous && act != auth.ActAgentRepoRead {
			h.unauthorized(w)
			return registry.Agent{}, nil, auth.AgentRoleNone, false
		}
		http.NotFound(w, r)
		return registry.Agent{}, nil, auth.AgentRoleNone, false
	}

	// Lazy bare-repo init (§13.3: only the git role mounts repo storage).
	if _, statErr := os.Stat(h.repos.Path(agent.RepoID)); statErr != nil {
		if err := h.repos.InitBare(r.Context(), agent.RepoID, agent.DefaultBranch); err != nil {
			h.log.Error("lazy repo init", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return registry.Agent{}, nil, auth.AgentRoleNone, false
		}
	}

	role, err := h.reg.EffectiveRole(r.Context(), principal, agent)
	if err != nil {
		h.log.Error("git effective role", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return registry.Agent{}, nil, auth.AgentRoleNone, false
	}
	res := auth.AgentResource{Public: agent.Visibility == "public", EffectiveRole: role}
	if err := auth.CheckAgent(principal, res, act); err != nil {
		if principal.Anonymous {
			h.unauthorized(w)
		} else {
			// Hide private repos from unauthorized principals (§6.4 table
			// implies existence-privacy for read; write denial on a repo
			// you can read is a plain 403).
			if act == auth.ActAgentRepoRead {
				http.NotFound(w, r)
			} else {
				http.Error(w, "forbidden", http.StatusForbidden)
			}
		}
		return registry.Agent{}, nil, auth.AgentRoleNone, false
	}

	// §6.4 + §12.4: in an org that enforces SSO, mutating git operations
	// additionally require an org-bound PAT.
	allowed, err := h.ssoAllows(r.Context(), principal, agent, act)
	if err != nil {
		h.log.Error("git sso gate", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return registry.Agent{}, nil, auth.AgentRoleNone, false
	}
	if !allowed {
		http.Error(w, "forbidden: this organization requires an org-bound token", http.StatusForbidden)
		return registry.Agent{}, nil, auth.AgentRoleNone, false
	}
	return agent, principal, role, true
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
	var cmds bytes.Buffer
	h.rpc(w, r, agent, principal, role, "receive-pack", &cmds)
}

// rpc runs the stateless git service, streaming request→stdin, stdout→response.
// When cmdCapture is non-nil (receive-pack), the leading pkt-line command
// section is captured for post-receive processing.
func (h *Handler) rpc(w http.ResponseWriter, r *http.Request, agent registry.Agent, principal *auth.Principal, role auth.AgentRole, service string, cmdCapture *bytes.Buffer) {
	ctx, cancel := context.WithTimeout(r.Context(), h.opTimeout)
	defer cancel()

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
		http.Error(w, "git error", http.StatusInternalServerError)
		return
	}
	release, err := h.acquireGit(ctx, agent.RepoID)
	if err != nil {
		http.Error(w, "git busy", http.StatusServiceUnavailable)
		return
	}
	defer release()
	if err := cmd.Start(); err != nil {
		h.log.Error("git start", "service", service, "err", err)
		http.Error(w, "git error", http.StatusInternalServerError)
		return
	}
	_, _ = io.Copy(w, stdout)
	err = cmd.Wait()
	if err != nil {
		// Headers are already sent; the pkt-line stream carries the error
		// report to the client. Log for operators.
		h.log.Warn("git rpc exit", "service", service, "err", err, "stderr", stderr.String())
		return
	}

	if service == "receive-pack" {
		h.afterReceive(r.Context(), agent, principal, cmdCapture)
	}
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

	q := h.st.Queries()
	if size, err := h.diskUsage(agent.RepoID); err != nil {
		// Never write a fabricated 0 on a measurement failure: keep the last
		// known size and only record that a push landed.
		h.log.Warn("post-receive du", "err", err)
		if err := q.TouchRepoOnPush(ctx, agent.RepoID); err != nil {
			h.log.Error("post-receive touch", "err", err)
		}
	} else if err := q.UpdateRepoOnPush(ctx, storegen.UpdateRepoOnPushParams{ID: agent.RepoID, SizeBytes: size}); err != nil {
		h.log.Error("post-receive size", "err", err)
	}
	refNames := make([]string, 0, len(refs))
	for _, ru := range refs {
		refNames = append(refNames, ru.Ref)
	}
	e := audit.Event{
		Actor: principal.UserID, ActorKind: audit.ActorPAT,
		Action: audit.ActionRepoPush, TargetKind: "agent", TargetID: agent.ID,
		Detail: map[string]any{"refs": refNames},
	}
	if agent.NamespaceKind == "org" {
		e.OrgID = agent.NamespaceID
	}
	if err := h.aud.Write(ctx, q, e); err != nil {
		h.log.Error("post-receive audit", "err", err)
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
	canPublish := auth.CheckAgent(principal,
		auth.AgentResource{Public: agent.Visibility == "public", EffectiveRole: role},
		auth.ActAgentPublish) == nil
	if canPublish && agent.NamespaceKind == "org" {
		// Enforced SSO gates release just as it gates push (§6.4, §12.4);
		// a lookup failure denies the stricter permission, never grants it.
		allowed, err := h.ssoAllows(r.Context(), principal, agent, auth.ActAgentPublish)
		if err != nil {
			h.log.Error("git sso gate (publish)", "err", err)
		}
		canPublish = allowed && err == nil
	}
	env := append(os.Environ(),
		"GIT_PROTOCOL="+r.Header.Get("Git-Protocol"),
		"AGENTRY_HOOK_BIN="+h.repos.hookBin,
		"AGENTRY_HOOK_DEFAULT_BRANCH="+agent.DefaultBranch,
		fmt.Sprintf("AGENTRY_HOOK_CAN_PUBLISH=%t", canPublish),
		fmt.Sprintf("AGENTRY_HOOK_MAX_BLOB_BYTES=%d", h.cfg.Limits.RepoMaxBlobBytes),
		fmt.Sprintf("AGENTRY_HOOK_QUOTA_BYTES=%d", h.cfg.Limits.RepoQuotaBytes),
		"AGENTRY_HOOK_ALLOW_FORCE=false",
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
