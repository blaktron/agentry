package gitsrv_test

// §17.2 git protocol conformance: clone/fetch/push × public/private ×
// correct/wrong/absent PAT × shallow/partial × policy rejections
// (oversize, protected v* tags, force-push, nested .git), all through the
// real git CLI against the assembled server.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/gitsrv"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// TestMain doubles as the git hook shim: bare repos created in tests carry
// hooks that exec this test binary with `hook pre-receive` (the production
// path execs agentryd the same way).
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "hook" && os.Args[2] == "pre-receive" {
		os.Exit(gitsrv.RunPreReceiveHook(os.Stdin, os.Stderr))
	}
	os.Exit(m.Run())
}

type gitEnv struct {
	t     *testing.T
	srv   *httptest.Server
	st    *store.Store
	reg   *registry.Service
	repos *gitsrv.RepoStore
	git   *gitsrv.Handler
	sfx   string
	owner struct {
		handle string
		id     uuid.UUID
		patRW  string // repo:read+repo:write+agent:publish
		patRO  string // repo:read
		patW   string // repo:read+repo:write (no publish)
	}
}

func newGitEnv(t *testing.T) *gitEnv {
	t.Helper()
	return newGitEnvCfg(t, nil)
}

// newGitEnvCfg is newGitEnv with a hook to adjust the config before the
// handler is built (quota tests need a budget small enough to exhaust).
func newGitEnvCfg(t *testing.T, cfgFn func(*config.Config)) *gitEnv {
	t.Helper()
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set; skipping git conformance")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	st, err := store.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	cfg := config.Default()
	cfg.Git.DataDir = t.TempDir()
	cfg.Limits.RepoMaxBlobBytes = 1 << 20 // 1 MB single-object cap for tests
	cfg.Limits.RepoQuotaBytes = 100 << 20
	cfg.Limits.LoginPerMin = 100000
	cfg.Limits.AnonymousPerMin = 1000000
	cfg.Limits.AuthedPerHour = 10000000
	cfg.Limits.AuthedBurstPerMin = 1000000

	cfg.Storage.LocalDir = t.TempDir()
	if cfgFn != nil {
		cfgFn(&cfg)
	}

	repos, err := gitsrv.NewRepoStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	apiSrv := api.New(cfg, st, nil)
	reg := apiSrv.Reg()
	reg.SetGitArchiver(repos)
	aud := audit.NewWriter(nil)
	git := gitsrv.NewHandler(cfg, st, repos, reg, aud, nil)
	srv := httptest.NewServer(api.NewHandlerWithGit(apiSrv, git.Mount))
	t.Cleanup(srv.Close)

	env := &gitEnv{t: t, srv: srv, st: st, reg: reg, repos: repos, git: git, sfx: fmt.Sprintf("%06x", rand.Int63n(1<<24))} //nolint:gosec

	// Seed the owner directly through the store (API flows are covered by
	// internal/api tests; here git transport is the subject).
	env.owner.handle = "gito" + env.sfx
	env.owner.id = env.seedUser(env.owner.handle)
	env.owner.patRW = env.seedPAT(env.owner.id, "rw", "repo:read", "repo:write", "agent:publish")
	env.owner.patRO = env.seedPAT(env.owner.id, "ro", "repo:read")
	env.owner.patW = env.seedPAT(env.owner.id, "w", "repo:read", "repo:write")
	return env
}

func (e *gitEnv) seedUser(handle string) uuid.UUID {
	e.t.Helper()
	q := e.st.Queries()
	ctx := context.Background()
	id := newUUID(e.t)
	if err := q.CreateHandle(ctx, storegen.CreateHandleParams{ID: id, Handle: handle, Kind: "user"}); err != nil {
		e.t.Fatal(err)
	}
	hash := "x"
	if _, err := q.CreateUser(ctx, storegen.CreateUserParams{ID: id, Email: handle + "@example.test", DisplayName: handle, PasswordHash: &hash}); err != nil {
		e.t.Fatal(err)
	}
	if err := q.MarkEmailVerified(ctx, id); err != nil {
		e.t.Fatal(err)
	}
	// Age the account past the §19 new-publisher velocity ramp so routine
	// multi-publish test flows aren't flagged by S8 (that ramp is exercised
	// directly in internal/scan tests).
	if _, err := e.st.Pool().Exec(ctx, `UPDATE users SET created_at = now() - interval '30 days' WHERE id = $1`, id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *gitEnv) seedPAT(userID uuid.UUID, name string, scopes ...string) string {
	e.t.Helper()
	tok, err := auth.NewToken(auth.PATPrefix)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.st.Queries().CreatePAT(context.Background(), storegen.CreatePATParams{
		ID: newUUID(e.t), UserID: userID, Name: name,
		TokenSha256: auth.HashToken(tok), TokenPrefix: auth.DisplayPrefix(tok),
		Scopes: scopes, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *gitEnv) seedAgent(name, visibility string) registry.Agent {
	return e.seedAgentModes(name, []string{"autonomous"}, visibility)
}

func (e *gitEnv) seedAgentModes(name string, modes []string, visibility string) registry.Agent {
	e.t.Helper()
	p := &auth.Principal{UserID: e.owner.id, Handle: e.owner.handle, Via: "session", EmailVerified: true}
	a, err := e.reg.CreateAgent(context.Background(), p, registry.CreateAgentInput{
		Namespace: e.owner.handle, Name: name, Modes: modes, Visibility: visibility,
	}, audit.Event{Actor: e.owner.id, ActorKind: audit.ActorUser})
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

// cloneURL embeds a PAT as the Basic password (GitHub convention, §6.1).
func (e *gitEnv) cloneURL(agent, pat string) string {
	return e.cloneURLNS(e.owner.handle, agent, pat)
}

// cloneURLNS is cloneURL for any namespace (org repos, §6.4).
func (e *gitEnv) cloneURLNS(ns, agent, pat string) string {
	host := strings.TrimPrefix(e.srv.URL, "http://")
	if pat == "" {
		return fmt.Sprintf("http://%s/%s/%s.git", host, ns, agent)
	}
	return fmt.Sprintf("http://token:%s@%s/%s/%s.git", pat, host, ns, agent)
}

// seedOrg creates an org the owner belongs to, optionally enforcing SSO
// (§12.4). Enforcement is set directly: the API surface for it belongs to
// internal/api's org settings, not to the git layer under test.
func (e *gitEnv) seedOrg(handle string, ssoRequired bool) uuid.UUID {
	e.t.Helper()
	ctx := context.Background()
	q := e.st.Queries()
	id := newUUID(e.t)
	if err := q.CreateHandle(ctx, storegen.CreateHandleParams{ID: id, Handle: handle, Kind: "org"}); err != nil {
		e.t.Fatal(err)
	}
	if _, err := q.CreateOrg(ctx, storegen.CreateOrgParams{ID: id, DisplayName: handle}); err != nil {
		e.t.Fatal(err)
	}
	if err := q.UpsertMembership(ctx, storegen.UpsertMembershipParams{OrgID: id, UserID: e.owner.id, Role: "owner"}); err != nil {
		e.t.Fatal(err)
	}
	if ssoRequired {
		if _, err := e.st.Pool().Exec(ctx, `UPDATE orgs SET sso_required = true WHERE id = $1`, id); err != nil {
			e.t.Fatal(err)
		}
	}
	return id
}

// seedOrgAgent creates an agent in an org namespace, owned by the org owner.
func (e *gitEnv) seedOrgAgent(orgHandle string, orgID uuid.UUID, name, visibility string) registry.Agent {
	e.t.Helper()
	p := &auth.Principal{
		UserID: e.owner.id, Handle: e.owner.handle, Via: "session", EmailVerified: true,
		OrgRoles: map[uuid.UUID]auth.OrgRole{orgID: auth.RoleOwner},
	}
	a, err := e.reg.CreateAgent(context.Background(), p, registry.CreateAgentInput{
		Namespace: orgHandle, Name: name, Modes: []string{"autonomous"}, Visibility: visibility,
	}, audit.Event{Actor: e.owner.id, ActorKind: audit.ActorUser, OrgID: orgID})
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

// seedOrgPAT mints an org-bound PAT (pats.org_id — minted during an SSO-fresh
// session in production, §12.4).
func (e *gitEnv) seedOrgPAT(userID, orgID uuid.UUID, name string, scopes ...string) string {
	e.t.Helper()
	tok, err := auth.NewToken(auth.PATPrefix)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.st.Queries().CreatePAT(context.Background(), storegen.CreatePATParams{
		ID: newUUID(e.t), UserID: userID, Name: name, OrgID: &orgID,
		TokenSha256: auth.HashToken(tok), TokenPrefix: auth.DisplayPrefix(tok),
		Scopes: scopes, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// git runs the git CLI in dir, returning combined output and error.
func gitRun(t *testing.T, dir string, args ...string) (string, error) {
	return gitRunWithEnv(t, dir, nil, args...)
}

func gitRunWithEnv(t *testing.T, dir string, extra []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	// Isolate the client completely from ambient credential sources:
	// user/system config (macOS ships a keychain helper), GIT_ASKPASS
	// injected by IDE/agent environments, and anything else GIT_*.
	env := make([]string, 0, 16)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") || strings.HasPrefix(kv, "SSH_ASKPASS") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/usr/bin/true",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_GLOBAL=/dev/null",
		// Apple git compiles in credential-osxkeychain; an empty
		// credential.helper entry clears the helper list entirely so
		// tests neither read nor write the user's keychain.
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=credential.helper",
		"GIT_CONFIG_VALUE_0=",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test",
	)
	cmd.Env = append(cmd.Env, extra...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitRun(t, dir, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// seedWorkdir creates a local repo with an initial commit on main.
func seedWorkdir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "init", "-b", "main")
	for path, content := range files {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustGit(t, dir, "add", "-A")
	mustGit(t, dir, "commit", "-m", "initial")
	return dir
}

func TestGitConformance(t *testing.T) {
	env := newGitEnv(t)

	pub := env.seedAgent("pub-agent", "public")
	_ = pub
	priv := env.seedAgent("priv-agent", "private")
	_ = priv

	work := seedWorkdir(t, map[string]string{
		"agent.yaml": "schemaVersion: \"1\"\n",
		"README.md":  "# test agent\n",
	})

	t.Run("push public with write PAT", func(t *testing.T) {
		mustGit(t, work, "remote", "add", "origin", env.cloneURL("pub-agent", env.owner.patRW))
		mustGit(t, work, "push", "origin", "main")
	})

	t.Run("anonymous clone public", func(t *testing.T) {
		dst := t.TempDir()
		mustGit(t, dst, "clone", env.cloneURL("pub-agent", ""), "c")
		if _, err := os.Stat(filepath.Join(dst, "c", "README.md")); err != nil {
			t.Fatal("cloned content missing")
		}
	})

	t.Run("shallow clone", func(t *testing.T) {
		dst := t.TempDir()
		mustGit(t, dst, "clone", "--depth", "1", env.cloneURL("pub-agent", ""), "c")
	})

	t.Run("partial clone", func(t *testing.T) {
		dst := t.TempDir()
		mustGit(t, dst, "clone", "--filter=blob:none", env.cloneURL("pub-agent", ""), "c")
	})

	t.Run("anonymous push denied", func(t *testing.T) {
		mustGit(t, work, "commit", "--allow-empty", "-m", "anon-attempt")
		out, err := gitRun(t, work, "push", env.cloneURL("pub-agent", ""), "main")
		if err == nil {
			t.Fatalf("anonymous push must fail:\n%s", out)
		}
		mustGit(t, work, "reset", "--hard", "HEAD~1")
	})

	t.Run("read-only PAT push denied", func(t *testing.T) {
		out, err := gitRun(t, work, "push", env.cloneURL("pub-agent", env.owner.patRO), "main")
		if err == nil || !strings.Contains(out, "403") {
			t.Fatalf("read-only PAT push must 403: %v\n%s", err, out)
		}
	})

	t.Run("invalid PAT rejected", func(t *testing.T) {
		out, err := gitRun(t, work, "push", env.cloneURL("pub-agent", "agy_bogusbogusbogusbogusbogusbogusbogusbogus"), "main")
		if err == nil {
			t.Fatalf("bogus PAT must fail:\n%s", out)
		}
	})

	t.Run("anonymous clone private prompts auth", func(t *testing.T) {
		dst := t.TempDir()
		out, err := gitRun(t, dst, "clone", env.cloneURL("priv-agent", ""), "c")
		if err == nil {
			t.Fatalf("anonymous private clone must fail:\n%s", out)
		}
	})

	t.Run("anonymous cannot tell a private repo from a missing one", func(t *testing.T) {
		// agentry#313: the info/refs probe is what a scanner would use.
		// Both answers are the credential prompt, byte for byte the same
		// status, so the name leaks nothing; a reader's credentials on
		// that 401 get the real answer.
		probe := func(agent string) int {
			res, err := http.Get(env.cloneURL(agent, "") + "/info/refs?service=git-upload-pack")
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			return res.StatusCode
		}
		if got := probe("priv-agent"); got != http.StatusUnauthorized {
			t.Fatalf("private: got %d want 401", got)
		}
		if got := probe("no-such-agent"); got != http.StatusUnauthorized {
			t.Fatalf("unknown: got %d want 401 (the same as private)", got)
		}
	})

	t.Run("owner clones private", func(t *testing.T) {
		privWork := seedWorkdir(t, map[string]string{"SKILL.md": "private\n"})
		mustGit(t, privWork, "push", env.cloneURL("priv-agent", env.owner.patRW), "main")
		dst := t.TempDir()
		mustGit(t, dst, "clone", env.cloneURL("priv-agent", env.owner.patRO), "c")
	})

	t.Run("granted reader clones private", func(t *testing.T) {
		readerID := env.seedUser("gitr" + env.sfx)
		readerPAT := env.seedPAT(readerID, "r", "repo:read")
		if err := env.st.Queries().UpsertAgentUserGrant(context.Background(), storegen.UpsertAgentUserGrantParams{
			AgentID: priv.ID, UserID: readerID, Role: "read",
		}); err != nil {
			t.Fatal(err)
		}
		dst := t.TempDir()
		mustGit(t, dst, "clone", env.cloneURL("priv-agent", readerPAT), "c")
	})

	t.Run("ungranted user cannot clone private", func(t *testing.T) {
		strangerID := env.seedUser("gits" + env.sfx)
		strangerPAT := env.seedPAT(strangerID, "s", "repo:read")
		dst := t.TempDir()
		out, err := gitRun(t, dst, "clone", env.cloneURL("priv-agent", strangerPAT), "c")
		if err == nil {
			t.Fatalf("stranger private clone must fail:\n%s", out)
		}
	})

	t.Run("version tag requires publish permission", func(t *testing.T) {
		mustGit(t, work, "tag", "v0.0.1")
		out, err := gitRun(t, work, "push", env.cloneURL("pub-agent", env.owner.patW), "v0.0.1")
		if err == nil || !strings.Contains(out, "publish permission") {
			t.Fatalf("v* tag without publish scope must be rejected: %v\n%s", err, out)
		}
		mustGit(t, work, "push", env.cloneURL("pub-agent", env.owner.patRW), "v0.0.1")
	})

	t.Run("version tags immutable", func(t *testing.T) {
		out, err := gitRun(t, work, "push", env.cloneURL("pub-agent", env.owner.patRW), ":refs/tags/v0.0.1")
		if err == nil || !strings.Contains(out, "immutable") {
			t.Fatalf("v* tag delete must be rejected: %v\n%s", err, out)
		}
	})

	t.Run("force-push allowed once the agent setting is on (agentry#48)", func(t *testing.T) {
		if _, err := env.st.Pool().Exec(context.Background(),
			`UPDATE agents SET allow_force_push = true WHERE name = 'pub-agent'`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = env.st.Pool().Exec(context.Background(), `UPDATE agents SET allow_force_push = false WHERE name = 'pub-agent'`)
		}()
		mustGit(t, work, "commit", "--amend", "--allow-empty", "-m", "rewritten while allowed")
		if out, err := gitRun(t, work, "push", "--force", env.cloneURL("pub-agent", env.owner.patRW), "main"); err != nil {
			t.Fatalf("force-push must succeed when allowed: %v\n%s", err, out)
		}
	})

	t.Run("force-push to default branch rejected", func(t *testing.T) {
		mustGit(t, work, "commit", "--amend", "--allow-empty", "-m", "rewritten")
		out, err := gitRun(t, work, "push", "--force", env.cloneURL("pub-agent", env.owner.patRW), "main")
		if err == nil || !strings.Contains(out, "force-push") {
			t.Fatalf("force-push to main must be rejected: %v\n%s", err, out)
		}
		// Restore local state to the remote's to keep later cases sane.
		mustGit(t, work, "fetch", env.cloneURL("pub-agent", env.owner.patRO), "main")
		mustGit(t, work, "reset", "--hard", "FETCH_HEAD")
	})

	t.Run("force-push to feature branch allowed", func(t *testing.T) {
		mustGit(t, work, "checkout", "-b", "feature")
		mustGit(t, work, "commit", "--allow-empty", "-m", "f1")
		mustGit(t, work, "push", env.cloneURL("pub-agent", env.owner.patRW), "feature")
		mustGit(t, work, "commit", "--amend", "--allow-empty", "-m", "f1-rewritten")
		mustGit(t, work, "push", "--force", env.cloneURL("pub-agent", env.owner.patRW), "feature")
		mustGit(t, work, "checkout", "main")
	})

	t.Run("default branch delete rejected", func(t *testing.T) {
		out, err := gitRun(t, work, "push", env.cloneURL("pub-agent", env.owner.patRW), ":refs/heads/main")
		if err == nil {
			t.Fatalf("default branch delete must be rejected:\n%s", out)
		}
	})

	t.Run("nested git dir rejected", func(t *testing.T) {
		// The porcelain refuses to stage ".git" path components, so build
		// the hostile tree with plumbing — exactly what an attacker would do.
		mustGit(t, work, "checkout", "main")
		blob := strings.TrimSpace(mustGit(t, work, "hash-object", "-w", "--stdin", "--path", "config"))
		_ = blob
		blobOut, err := gitRun(t, work, "hash-object", "-w", "--stdin")
		if err != nil {
			t.Fatal(blobOut)
		}
		blob = strings.TrimSpace(blobOut)
		t1 := strings.TrimSpace(mustGit(t, work, "mktree", "--missing"))
		_ = t1
		mk := func(entries string) string {
			cmd := exec.Command("git", "mktree")
			cmd.Dir = work
			cmd.Stdin = strings.NewReader(entries)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("mktree: %v\n%s", err, out)
			}
			return strings.TrimSpace(string(out))
		}
		inner := mk("100644 blob " + blob + "\tconfig\n")
		dotgit := mk("040000 tree " + inner + "\t.git\n")
		root := mk("040000 tree " + dotgit + "\tvendor\n")
		commit := strings.TrimSpace(mustGit(t, work, "commit-tree", root, "-p", "HEAD", "-m", "nested"))
		mustGit(t, work, "update-ref", "refs/heads/nested", commit)
		out, err := gitRun(t, work, "push", env.cloneURL("pub-agent", env.owner.patRW), "nested")
		if err == nil || !strings.Contains(out, ".git") {
			t.Fatalf("nested .git must be rejected: %v\n%s", err, out)
		}
		mustGit(t, work, "update-ref", "-d", "refs/heads/nested")
	})

	t.Run("oversized blob rejected", func(t *testing.T) {
		mustGit(t, work, "checkout", "main")
		big := make([]byte, 2<<20) // 2 MB > 1 MB test cap
		for i := range big {
			big[i] = byte(i % 251) // incompressible enough
		}
		if err := os.WriteFile(filepath.Join(work, "big.bin"), big, 0o644); err != nil {
			t.Fatal(err)
		}
		mustGit(t, work, "add", "big.bin")
		mustGit(t, work, "commit", "-m", "big")
		out, err := gitRun(t, work, "push", env.cloneURL("pub-agent", env.owner.patRW), "main")
		if err == nil || !strings.Contains(out, "single-file limit") {
			t.Fatalf("oversize blob must be rejected: %v\n%s", err, out)
		}
		mustGit(t, work, "reset", "--hard", "HEAD~1")
	})

	t.Run("push updates repo bookkeeping", func(t *testing.T) {
		repo, err := env.st.Queries().GetRepo(context.Background(), pub.RepoID)
		if err != nil {
			t.Fatal(err)
		}
		if repo.SizeBytes == 0 || repo.LastPushAt == nil {
			t.Fatalf("repo bookkeeping not updated: %+v", repo)
		}
	})

	t.Run("push audited", func(t *testing.T) {
		n, err := env.st.Queries().CountAuditEvents(context.Background(), storegen.CountAuditEventsParams{Action: "repo.push"})
		if err != nil || n == 0 {
			t.Fatalf("repo.push audit rows: n=%d err=%v", n, err)
		}
	})
}

// pushAudits counts repo.push audit rows recorded against one agent.
func (e *gitEnv) pushAudits(agentID uuid.UUID) int {
	e.t.Helper()
	var n int
	err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'repo.push' AND target_id = $1`, agentID).Scan(&n)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

// TestPushRejectionLeavesNoTrace pins the §6.3 bookkeeping contract: a push
// the pre-receive hook denies still exits receive-pack 0, and none of the
// post-push side effects — size, last_push_at, repo.push audit — may fire for
// the refs it refused.
func TestPushRejectionLeavesNoTrace(t *testing.T) {
	env := newGitEnv(t)
	agent := env.seedAgent("rejectbk", "public")

	oversize := func(work string) {
		big := make([]byte, 2<<20) // 2 MB against the 1 MB test cap
		for i := range big {
			big[i] = byte(i % 251)
		}
		if err := os.WriteFile(filepath.Join(work, "big.bin"), big, 0o644); err != nil {
			t.Fatal(err)
		}
		mustGit(t, work, "add", "big.bin")
		mustGit(t, work, "commit", "-m", "oversize")
	}

	work := seedWorkdir(t, map[string]string{"agent.yaml": "schemaVersion: \"1\"\n"})
	url := env.cloneURL("rejectbk", env.owner.patRW)

	// A push rejected outright must leave the repo row untouched.
	oversize(work)
	if out, err := gitRun(t, work, "push", url, "main"); err == nil || !strings.Contains(out, "single-file limit") {
		t.Fatalf("oversize push must be rejected: %v\n%s", err, out)
	}
	repo, err := env.st.Queries().GetRepo(context.Background(), agent.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if repo.LastPushAt != nil || repo.SizeBytes != 0 {
		t.Fatalf("rejected push was bookkept: last_push_at=%v size=%d", repo.LastPushAt, repo.SizeBytes)
	}
	if n := env.pushAudits(agent.ID); n != 0 {
		t.Fatalf("rejected push wrote %d repo.push audit rows", n)
	}

	// An accepted push is bookkept normally.
	mustGit(t, work, "reset", "--hard", "HEAD~1")
	mustGit(t, work, "push", url, "main")
	accepted, err := env.st.Queries().GetRepo(context.Background(), agent.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.LastPushAt == nil || accepted.SizeBytes == 0 {
		t.Fatalf("accepted push not bookkept: %+v", accepted)
	}
	if n := env.pushAudits(agent.ID); n != 1 {
		t.Fatalf("accepted push wrote %d repo.push audit rows, want 1", n)
	}

	// A later rejection must not disturb what the accepted push recorded.
	oversize(work)
	if out, err := gitRun(t, work, "push", url, "main"); err == nil {
		t.Fatalf("second oversize push must be rejected:\n%s", out)
	}
	after, err := env.st.Queries().GetRepo(context.Background(), agent.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.LastPushAt.Equal(*accepted.LastPushAt) || after.SizeBytes != accepted.SizeBytes {
		t.Fatalf("rejected push moved bookkeeping: %v/%d → %v/%d",
			accepted.LastPushAt, accepted.SizeBytes, after.LastPushAt, after.SizeBytes)
	}
	if n := env.pushAudits(agent.ID); n != 1 {
		t.Fatalf("repo.push audit rows = %d after a rejection, want 1", n)
	}
}

// TestReleaseArchiveIgnoresExportIgnore pins §6.5's invariant that the
// manifest allowlist is the only filter: a pushed .gitattributes marking
// manifest-included files export-ignore must not remove them from the
// materialized workspace or from the published release.
func TestReleaseArchiveIgnoresExportIgnore(t *testing.T) {
	env := newGitEnv(t)
	const name = "exportignore"
	agent := env.seedAgent(name, "public")

	files := kindFixture("skill", env.owner.handle, name, "1.2.0")
	files[".gitattributes"] = "SKILL.md export-ignore\nREADME.md export-ignore\n"
	work := seedWorkdir(t, files)
	mustGit(t, work, "push", env.cloneURL(name, env.owner.patRW), "main")
	mustGit(t, work, "tag", "v1.2.0")
	mustGit(t, work, "push", env.cloneURL(name, env.owner.patRW), "v1.2.0")

	dst := t.TempDir()
	if _, err := env.repos.MaterializeTag(context.Background(), agent.RepoID, "v1.2.0", dst); err != nil {
		t.Fatalf("materialize v1.2.0: %v", err)
	}
	for _, f := range []string{"agent.yaml", "README.md", "SKILL.md"} {
		if _, err := os.Stat(filepath.Join(dst, f)); err != nil {
			t.Fatalf("export-ignore dropped %s from the release workspace", f)
		}
	}

	// End to end: the same tree must reach the published archive.
	env.waitPublished(name, "1.2.0")
	env.installRoundTrip(name, "1.2.0", "1.2.0", "agent.yaml", "README.md", "SKILL.md")

	// $GIT_DIR/info/attributes has no git switch that disables it, so an
	// archive must refuse to run under one rather than filter silently.
	info := filepath.Join(env.repos.Path(agent.RepoID), "info")
	if err := os.MkdirAll(info, 0o750); err != nil {
		t.Fatal(err)
	}
	attrs := filepath.Join(info, "attributes")
	if err := os.WriteFile(attrs, []byte("SKILL.md export-ignore\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := env.repos.MaterializeTag(context.Background(), agent.RepoID, "v1.2.0", t.TempDir()); err == nil {
		t.Fatal("archive must fail closed while $GIT_DIR/info/attributes exists")
	}
	if err := os.Remove(attrs); err != nil {
		t.Fatal(err)
	}
}

// TestGitEnforcedSSO pins §6.4's push row under §12.4: in an org with
// sso_required, git writes and releases need an org-bound PAT; reads and
// non-enforcing orgs are untouched.
func TestGitEnforcedSSO(t *testing.T) {
	env := newGitEnv(t)

	entHandle := "gitent" + env.sfx
	entID := env.seedOrg(entHandle, true)
	env.seedOrgAgent(entHandle, entID, "ssoagent", "public")
	bound := env.seedOrgPAT(env.owner.id, entID, "bound", "repo:read", "repo:write", "agent:publish")

	openHandle := "gitopen" + env.sfx
	openID := env.seedOrg(openHandle, false)
	env.seedOrgAgent(openHandle, openID, "openagent", "public")

	work := seedWorkdir(t, kindFixture("skill", entHandle, "ssoagent", "1.0.0"))

	t.Run("personal PAT denied on enforced org", func(t *testing.T) {
		out, err := gitRun(t, work, "push", env.cloneURLNS(entHandle, "ssoagent", env.owner.patRW), "main")
		if err == nil || !strings.Contains(out, "403") {
			t.Fatalf("push with a personal PAT must 403 under enforced SSO: %v\n%s", err, out)
		}
	})

	t.Run("reads unaffected", func(t *testing.T) {
		// §6.4 attaches the org-bound requirement to push, not to fetch.
		dst := t.TempDir()
		mustGit(t, dst, "clone", env.cloneURLNS(entHandle, "ssoagent", env.owner.patRO), "c")
	})

	t.Run("org-bound PAT accepted", func(t *testing.T) {
		mustGit(t, work, "push", env.cloneURLNS(entHandle, "ssoagent", bound), "main")
		// The publish permission travels the same gate (v* tag creation).
		mustGit(t, work, "tag", "v1.0.0")
		mustGit(t, work, "push", env.cloneURLNS(entHandle, "ssoagent", bound), "v1.0.0")
	})

	t.Run("non-enforcing org unaffected", func(t *testing.T) {
		other := seedWorkdir(t, kindFixture("skill", openHandle, "openagent", "1.0.0"))
		mustGit(t, other, "push", env.cloneURLNS(openHandle, "openagent", env.owner.patRW), "main")
	})
}

// TestPreReceiveHookFailsClosed: the hook must never accept a push whose ref
// list it could not read in full (§6.3 is a deny-by-default policy point).
func TestPreReceiveHookFailsClosed(t *testing.T) {
	line := zeroesOID + " " + strings.Repeat("a", 40) + " refs/heads/feature\n"

	t.Run("stdin read error", func(t *testing.T) {
		var stderr bytes.Buffer
		in := io.MultiReader(strings.NewReader(line), errReader{})
		if code := gitsrv.RunPreReceiveHook(in, &stderr); code == 0 {
			t.Fatalf("hook accepted a push it could not read: %q", stderr.String())
		}
		if !strings.Contains(stderr.String(), "could not read") {
			t.Fatalf("expected a read-failure message, got %q", stderr.String())
		}
	})

	t.Run("malformed ref line", func(t *testing.T) {
		var stderr bytes.Buffer
		if code := gitsrv.RunPreReceiveHook(strings.NewReader("not a ref update\n"), &stderr); code == 0 {
			t.Fatalf("hook accepted an unparsable ref update: %q", stderr.String())
		}
	})
}

// TestPreReceiveHookWarnTier: past the warn tier the push goes through and
// the pusher is told (git relays the hook's stderr as "remote:" lines);
// past the quota it is refused (§19, agentry#44).
func TestPreReceiveHookWarnTier(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "objects.pack"), bytes.Repeat([]byte{'x'}, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	// Deleting a non-default branch: no tree to check, only the usage checks.
	line := strings.Repeat("a", 40) + " " + zeroesOID + " refs/heads/feature\n"

	t.Setenv("AGENTRY_HOOK_WARN_BYTES", "1024")
	t.Setenv("AGENTRY_HOOK_QUOTA_BYTES", "10485760")
	var stderr bytes.Buffer
	if code := gitsrv.RunPreReceiveHook(strings.NewReader(line), &stderr); code != 0 {
		t.Fatalf("push over the warn tier was refused: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "warning: repository is") {
		t.Fatalf("no warning for a repo over the warn tier: %q", stderr.String())
	}

	t.Setenv("AGENTRY_HOOK_QUOTA_BYTES", "1024")
	stderr.Reset()
	if code := gitsrv.RunPreReceiveHook(strings.NewReader(line), &stderr); code == 0 {
		t.Fatalf("push over the quota was accepted: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "exceeds") {
		t.Fatalf("no quota refusal: %q", stderr.String())
	}
}

const zeroesOID = "0000000000000000000000000000000000000000"

// errReader fails on first read, standing in for a truncated hook stdin.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("stdin: connection reset") }

func newUUID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
