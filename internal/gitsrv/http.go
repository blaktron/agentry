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
	// sem bounds concurrent git subprocesses (§6.2).
	sem chan struct{}
	// opTimeout bounds one git operation.
	opTimeout time.Duration
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
		sem:       make(chan struct{}, 32),
		opTimeout: 5 * time.Minute,
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
	return agent, principal, role, true
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

	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := h.runLimited(cmd); err != nil {
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
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
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

// afterReceive updates repo bookkeeping and audit after a successful push,
// and hands ref updates to the M3 publication trigger.
func (h *Handler) afterReceive(ctx context.Context, agent registry.Agent, principal *auth.Principal, cmds *bytes.Buffer) {
	refs := parseReceiveCommands(cmds.Bytes())
	size, err := h.repos.DiskUsage(agent.RepoID)
	if err != nil {
		h.log.Warn("post-receive du", "err", err)
	}

	q := h.st.Queries()
	if err := q.UpdateRepoOnPush(ctx, storegen.UpdateRepoOnPushParams{ID: agent.RepoID, SizeBytes: size}); err != nil {
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
			if !ok || !strings.HasPrefix(tag, "v") || ru.New == strings.Repeat("0", 40) {
				continue
			}
			e := audit.Event{Actor: principal.UserID, ActorKind: audit.ActorPAT}
			if _, err := h.reg.SubmitTag(ctx, principal, agent, tag, e); err != nil {
				h.log.Warn("auto-publish submit", "tag", tag, "err", err)
			}
		}
	}
}

// gitEnv builds the subprocess environment: protocol v2 plus the hook
// context (hooks.go) describing the pusher's permissions and quotas.
// CAN_PUBLISH goes through the chokepoint so PAT scope limits apply: a
// repo:write-only PAT cannot create v* tags even for an owner (§6.4).
func (h *Handler) gitEnv(r *http.Request, agent registry.Agent, principal *auth.Principal, role auth.AgentRole) []string {
	canPublish := auth.CheckAgent(principal,
		auth.AgentResource{Public: agent.Visibility == "public", EffectiveRole: role},
		auth.ActAgentPublish) == nil
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

func (h *Handler) runLimited(cmd *exec.Cmd) error {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	return cmd.Run()
}

// RefUpdate is one receive-pack command (old, new, ref).
type RefUpdate struct {
	Old, New, Ref string
}
