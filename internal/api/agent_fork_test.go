package api_test

// Forks: a
// private copy of a public QuickAgent, recorded by the request and copied
// by a worker, whose first version is the origin's renamed and submitted
// through the pipeline. Each invariant this touches is a test here: a
// fork is never public, nothing becomes installable without the pipeline,
// private stays invisible, the origin's publisher learns how many forks
// there are and never whose.

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/gitsrv"
	"github.com/blaktron/agentry/internal/registry"
)

// forkCapture is the fork hand-off a test drives: it keeps what the
// request enqueued, and runCopies runs those copies as the worker would.
type forkCapture struct {
	mu   sync.Mutex
	args []registry.CopyForkArgs
}

func (f *forkCapture) CopyFork(_ context.Context, a registry.CopyForkArgs) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.args = append(f.args, a)
	return nil
}

func (f *forkCapture) take() []registry.CopyForkArgs {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.args
	f.args = nil
	return out
}

type forkEnv struct {
	*testEnv
	copies *forkCapture
	repos  *gitsrv.RepoStore
}

// newForkEnv is a test server whose registry holds a repository store,
// as the worker's and `all`'s do, with the copy captured rather than
// enqueued.
func newForkEnv(t *testing.T, opts ...func(*api.Server)) *forkEnv {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	env := newTestEnvWith(t, opts...)
	repos, err := gitsrv.NewRepoStore(config.Config{Git: config.Git{DataDir: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	copies := &forkCapture{}
	reg := env.srvObj.Reg()
	reg.SetForkHandOff(copies)
	reg.SetForkRepos(repos)
	reg.SetGitArchiver(repos)
	return &forkEnv{testEnv: env, copies: copies, repos: repos}
}

// runCopies runs every copy the requests handed off, as JobCopyFork's
// handler does: the forker's standing reloaded, the registry's own
// (synchronous, in tests) pipeline taking the first version.
func (env *forkEnv) runCopies() {
	env.t.Helper()
	ctx := context.Background()
	for _, a := range env.copies.take() {
		p, ok, err := env.srvObj.PrincipalForUser(ctx, a.UserID)
		if err != nil {
			env.t.Fatal(err)
		}
		if !ok {
			p = nil
		}
		if err := env.srvObj.Reg().CopyFork(ctx, a, p, nil); err != nil {
			env.t.Fatalf("copy fork %s: %v", a.AgentID, err)
		}
	}
}

type forkAgentOut struct {
	ID         uuid.UUID `json:"id"`
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	Visibility string    `json:"visibility"`
	ForkState  *string   `json:"forkState"`
	ForkDetail *string   `json:"forkDetail"`
	ForkCount  *int      `json:"forkCount"`
	ForkedFrom *struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Available bool   `json:"available"`
	} `json:"forkedFrom"`
	QuarantineState string `json:"quarantineState"`
}

// fork forks ns/name as c, which must be accepted (202).
func (env *forkEnv) fork(c caller, ns, name string, body map[string]any) forkAgentOut {
	env.t.Helper()
	var out forkAgentOut
	env.doJSON(c, http.MethodPost, "/api/v1/agents/"+ns+"/"+name+"/fork", body, &out, http.StatusAccepted)
	return out
}

// problemSlug is a refused request's status and problem slug.
func (env *testEnv) problemSlug(c caller, method, path string, body any) (int, string) {
	env.t.Helper()
	res := env.do(c, method, path, body)
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	slug := ""
	if i := strings.Index(string(raw), "problems/"); i >= 0 {
		rest := string(raw)[i+len("problems/"):]
		if j := strings.IndexByte(rest, '"'); j >= 0 {
			slug = rest[:j]
		}
	}
	return res.StatusCode, slug
}

func (env *testEnv) repoOf(ns, name string) uuid.UUID {
	env.t.Helper()
	var id uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT a.repo_id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = $2`, ns, name).Scan(&id); err != nil {
		env.t.Fatal(err)
	}
	return id
}

// versionStatus is a version's status as the database holds it: a fork is
// private, so the anonymous waitStatus cannot see it. The pipeline is
// synchronous in tests, so the copy has finished with it.
func (env *testEnv) versionStatus(ns, name, version string) string {
	env.t.Helper()
	var st string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT v.status FROM agent_versions v JOIN agents a ON a.id = v.agent_id JOIN handles h ON h.id = a.namespace_id
		 WHERE h.handle = $1 AND a.name = $2 AND v.version = $3`, ns, name, version).Scan(&st); err != nil {
		env.t.Fatalf("version %s/%s@%s: %v", ns, name, version, err)
	}
	return st
}

// wantPublished says the fork's first version, 1.0.0 in every fixture
// here, is published.
func (env *testEnv) wantPublished(ns, name string) {
	env.t.Helper()
	if st := env.versionStatus(ns, name, "1.0.0"); st != "published" {
		env.t.Fatalf("%s/%s@1.0.0 is %s, want published", ns, name, st)
	}
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestForkIsAPrivateCopyWhoseFirstVersionGoesThroughThePipeline: the fork
// is recorded private and copying, with its origin; the worker's copy
// renames the manifest in one commit, tags it with the origin's version
// and submits it, which the pipeline publishes in the fork's namespace; the
// fork then reads ready; the origin counts it and names no fork.
func TestForkIsAPrivateCopyWhoseFirstVersionGoesThroughThePipeline(t *testing.T) {
	env := newForkEnv(t)
	alice := env.register("fk-alice")
	env.verifyEmail(alice)
	aliceS := env.login(alice)
	bob := env.register("fk-bob")
	env.verifyEmail(bob)
	bobS := env.login(bob)
	carol := env.login(env.register("fk-carol"))
	env.publishedAgent(aliceS, alice, "summarize")

	f := env.fork(bobS, alice, "summarize", map[string]any{"namespace": bob})
	if f.Namespace != bob || f.Name != "summarize" || f.Visibility != "private" {
		t.Fatalf("fork: %s/%s %s, want %s/summarize private", f.Namespace, f.Name, f.Visibility, bob)
	}
	if f.ForkState == nil || *f.ForkState != "copying" {
		t.Fatalf("forkState = %v, want copying", f.ForkState)
	}
	if f.ForkedFrom == nil || f.ForkedFrom.Namespace != alice || f.ForkedFrom.Name != "summarize" || f.ForkedFrom.Version != "1.0.0" || !f.ForkedFrom.Available {
		t.Fatalf("forkedFrom = %+v", f.ForkedFrom)
	}
	// Nothing is installable yet: the fork has no version until the
	// pipeline has taken one.
	var versions []map[string]any
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents/"+bob+"/summarize/versions", nil, &versions, http.StatusOK)
	if len(versions) != 0 {
		t.Fatalf("the fork has versions before its copy ran: %v", versions)
	}

	env.runCopies()
	env.wantPublished(bob, "summarize")
	var ready forkAgentOut
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents/"+bob+"/summarize", nil, &ready, http.StatusOK)
	if ready.ForkState == nil || *ready.ForkState != "ready" || ready.ForkDetail != nil {
		t.Fatalf("after the copy: forkState %v detail %v, want ready", ready.ForkState, ready.ForkDetail)
	}
	// The version went through the gate as any submission does: it has a
	// scan report of its own, and its manifest names the fork.
	var manifest map[string]any
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents/"+bob+"/summarize/versions/1.0.0/manifest", nil, &manifest, http.StatusOK)
	if manifest["namespace"] != bob || manifest["name"] != "summarize" {
		t.Fatalf("the fork's manifest names %v/%v", manifest["namespace"], manifest["name"])
	}
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents/"+bob+"/summarize/versions/1.0.0/report", nil, nil, http.StatusOK)

	// The repository: one commit, "Fork of …", with the branch and the
	// release tag on it. The origin was published by upload, so it has no
	// history of its own and the commit is a root.
	dir := env.repos.Path(env.repoOf(bob, "summarize"))
	if msg := gitIn(t, dir, "log", "-1", "--format=%s", "v1.0.0"); msg != "Fork of "+alice+"/summarize@1.0.0" {
		t.Fatalf("the fork's commit reads %q", msg)
	}
	if main, tag := gitIn(t, dir, "rev-parse", "main"), gitIn(t, dir, "rev-parse", "v1.0.0^{commit}"); main != tag {
		t.Fatalf("main %s and v1.0.0 %s differ", main, tag)
	}

	// Private stays invisible: a stranger gets a missing
	// name's 404, and the fork is in no public listing.
	if code := statusOf(t, env.do(carol, http.MethodGet, "/api/v1/agents/"+bob+"/summarize", nil)); code != http.StatusNotFound {
		t.Fatalf("a stranger reading the fork: %d, want 404", code)
	}

	// The origin counts its forks and names none.
	res := env.do(aliceS, http.MethodGet, "/api/v1/agents/"+alice+"/summarize", nil)
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !strings.Contains(string(raw), `"forkCount":1`) {
		t.Fatalf("the origin's read: %s, want forkCount 1", raw)
	}
	if strings.Contains(string(raw), bob) {
		t.Fatalf("the origin's read names the fork's namespace: %s", raw)
	}
	var originList []forkAgentOut
	env.doJSON(aliceS, http.MethodGet, "/api/v1/agents?namespace="+alice, nil, &originList, http.StatusOK)
	if len(originList) != 1 || originList[0].ForkCount == nil || *originList[0].ForkCount != 1 {
		t.Fatalf("the origin's list: %+v, want forkCount 1", originList)
	}

	// The list's forks filter.
	var only, none []forkAgentOut
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents?namespace="+bob+"&forks=only", nil, &only, http.StatusOK)
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents?namespace="+bob+"&forks=none", nil, &none, http.StatusOK)
	if len(only) != 1 || only[0].ForkedFrom == nil || only[0].ForkedFrom.Name != "summarize" || len(none) != 0 {
		t.Fatalf("forks=only %+v, forks=none %+v", only, none)
	}

	// The same name again is taken; another name is a second fork.
	if code, slug := env.problemSlug(bobS, http.MethodPost, "/api/v1/agents/"+alice+"/summarize/fork", map[string]any{"namespace": bob}); code != http.StatusConflict || slug != "name-taken" {
		t.Fatalf("a second fork under the same name: %d %s, want 409 name-taken", code, slug)
	}
	env.fork(bobS, alice, "summarize", map[string]any{"namespace": bob, "name": "summarize-2"})

	// Retiring the origin touches none of the fork's: its version still
	// resolves for its owner, and its read says the origin is not there to
	// link (it is private now).
	env.doJSON(aliceS, http.MethodPost, "/api/v1/agents/"+alice+"/summarize/retire", nil, nil, http.StatusOK)
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents/"+bob+"/summarize/versions/1.0.0/download", nil, nil, http.StatusOK)
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents/"+bob+"/summarize", nil, &ready, http.StatusOK)
	if ready.ForkedFrom == nil || ready.ForkedFrom.Available {
		t.Fatalf("after the origin's retire, forkedFrom = %+v, want it not available", ready.ForkedFrom)
	}
}

// TestAForkIsNeverPublic: the API's named refusal, under
// whichever role, and the database's CHECK behind it; lineage is permanent.
func TestAForkIsNeverPublic(t *testing.T) {
	env := newForkEnv(t)
	alice := env.register("fkp-alice")
	env.verifyEmail(alice)
	env.publishedAgent(env.login(alice), alice, "tool")
	bob := env.register("fkp-bob")
	env.verifyEmail(bob)
	bobS := env.login(bob)
	f := env.fork(bobS, alice, "tool", map[string]any{"namespace": bob})
	env.runCopies()

	if code, slug := env.problemSlug(bobS, http.MethodPatch, "/api/v1/agents/"+bob+"/tool", map[string]any{"visibility": "public"}); code != http.StatusConflict || slug != "fork-stays-private" {
		t.Fatalf("PATCH a fork public: %d %s, want 409 fork-stays-private", code, slug)
	}
	// Retire and Restore bring it back private, as it was.
	var a forkAgentOut
	env.doJSON(bobS, http.MethodPost, "/api/v1/agents/"+bob+"/tool/retire", nil, nil, http.StatusOK)
	env.doJSON(bobS, http.MethodPost, "/api/v1/agents/"+bob+"/tool/restore", nil, &a, http.StatusOK)
	if a.Visibility != "private" {
		t.Fatalf("a restored fork is %s", a.Visibility)
	}
	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx, `UPDATE agents SET visibility = 'public' WHERE id = $1`, f.ID); err == nil || !strings.Contains(err.Error(), "agents_fork_is_private") {
		t.Fatalf("the database let a fork be public: %v", err)
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE agents SET forked_from_agent_id = NULL, forked_from_version_id = NULL, fork_state = NULL WHERE id = $1`, f.ID); err == nil || !strings.Contains(err.Error(), "permanent") {
		t.Fatalf("the database let a fork detach: %v", err)
	}
}

// TestForkRefusesWhatCannotBeForkedAndWhereItCannotGo: what may be
// forked, by whom, into where.
func TestForkRefusesWhatCannotBeForkedAndWhereItCannotGo(t *testing.T) {
	env := newForkEnv(t)
	alice := env.register("fkr-alice")
	env.verifyEmail(alice)
	aliceS := env.login(alice)
	bob := env.register("fkr-bob")
	env.verifyEmail(bob)
	bobS := env.login(bob)
	env.publishedAgent(aliceS, alice, "pub")
	env.doJSON(aliceS, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": alice, "name": "secret", "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)
	env.doJSON(aliceS, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": alice, "name": "empty", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	forkPath := func(ns, name string) string { return "/api/v1/agents/" + ns + "/" + name + "/fork" }
	to := func(ns string) map[string]any { return map[string]any{"namespace": ns} }

	for _, c := range []struct {
		who  caller
		path string
		body map[string]any
		code int
		slug string
		why  string
	}{
		{anonymous, forkPath(alice, "pub"), to(bob), http.StatusUnauthorized, "", "an anonymous caller"},
		{bobS, forkPath(alice, "secret"), to(bob), http.StatusNotFound, "", "a private agent the caller cannot read"},
		{aliceS, forkPath(alice, "secret"), to(alice), http.StatusConflict, "fork-source", "a private agent, by its owner"},
		{bobS, forkPath(alice, "empty"), to(bob), http.StatusConflict, "nothing-to-fork", "an agent with no published version"},
		{bobS, forkPath(alice, "pub"), to(alice), http.StatusForbidden, "", "into someone else's namespace"},
		{bobS, forkPath(alice, "pub"), to("fkr-nobody" + env.sfx), http.StatusNotFound, "", "into a namespace that does not exist"},
		{bobS, forkPath(alice, "pub"), map[string]any{"namespace": bob, "name": "Not A Name"}, http.StatusUnprocessableEntity, "", "under a name that is not one"},
	} {
		code, slug := env.problemSlug(c.who, http.MethodPost, c.path, c.body)
		if code != c.code || (c.slug != "" && slug != c.slug) {
			t.Errorf("%s: %d %s, want %d %s", c.why, code, slug, c.code, c.slug)
		}
	}

	// A fork of a fork cannot happen: a fork is private, so only its owner
	// reads it, and to its owner it is not forkable.
	env.fork(bobS, alice, "pub", map[string]any{"namespace": bob})
	env.runCopies()
	if code, slug := env.problemSlug(bobS, http.MethodPost, forkPath(bob, "pub"), map[string]any{"namespace": bob, "name": "pub-2"}); code != http.StatusConflict || slug != "fork-source" {
		t.Errorf("a fork of a fork: %d %s, want 409 fork-source", code, slug)
	}

	// A quarantined origin is not forkable.
	staff := env.register("fkr-staff")
	env.makePlatformStaff(t, staff)
	staffS := env.login(staff)
	env.doJSON(staffS, http.MethodPost, "/api/v1/platform/agents/"+alice+"/pub/quarantine", map[string]any{"reason": "test"}, nil, http.StatusNoContent)
	carol := env.register("fkr-carol")
	env.verifyEmail(carol)
	if code, slug := env.problemSlug(env.login(carol), http.MethodPost, forkPath(alice, "pub"), to(carol)); code != http.StatusConflict || slug != "fork-source" {
		t.Errorf("a quarantined origin: %d %s, want 409 fork-source", code, slug)
	}
}

// TestAQuarantinedOriginLeavesItsForksAlone: a fork went through its
// own pipeline, so the origin's quarantine or block does not reach it.
func TestAQuarantinedOriginLeavesItsForksAlone(t *testing.T) {
	env := newForkEnv(t)
	alice := env.register("fkq-alice")
	env.verifyEmail(alice)
	env.publishedAgent(env.login(alice), alice, "flagged")
	bob := env.register("fkq-bob")
	env.verifyEmail(bob)
	bobS := env.login(bob)
	env.fork(bobS, alice, "flagged", map[string]any{"namespace": bob})
	env.runCopies()
	env.wantPublished(bob, "flagged")

	staff := env.register("fkq-staff")
	env.makePlatformStaff(t, staff)
	env.doJSON(env.login(staff), http.MethodPost, "/api/v1/platform/agents/"+alice+"/flagged/block", map[string]any{"reason": "test"}, nil, http.StatusNoContent)

	var f forkAgentOut
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents/"+bob+"/flagged", nil, &f, http.StatusOK)
	if f.QuarantineState != "none" {
		t.Fatalf("the fork's quarantineState is %s after its origin's block", f.QuarantineState)
	}
	env.wantPublished(bob, "flagged")
	// The act's record says how many forks it left as they are.
	var forks string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'forks' FROM audit_events WHERE action = 'agent.block' AND target_id = (
		   SELECT a.id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'flagged')`, alice).Scan(&forks); err != nil {
		t.Fatal(err)
	}
	if forks != "1" {
		t.Fatalf("the block's audit detail says %q forks, want 1", forks)
	}
}

// TestAMemberForksIntoTheOrganizationWithinItsCap: a member forks into the organization's
// namespace, under its private-agent cap; a copy whose forker lost the
// right to publish there by the time it runs fails in words; a name a
// deleted agent holds is refused.
func TestAMemberForksIntoTheOrganizationWithinItsCap(t *testing.T) {
	env := newForkEnv(t, onTier(func(f *entitlements.Features) {
		f.PrivateAgents = entitlements.Cap{Enabled: true, Max: 2}
	}))
	alice := env.register("fko-alice")
	env.verifyEmail(alice)
	env.publishedAgent(env.login(alice), alice, "helper")
	admin := env.register("fko-admin")
	env.verifyEmail(admin)
	adminS := env.login(admin)
	org := "fko-org" + env.sfx
	env.createOrg(adminS, org)
	member := env.register("fko-mem")
	env.joinOrg(adminS, org, member)
	memberS := env.login(member)

	f := env.fork(memberS, alice, "helper", map[string]any{"namespace": org})
	if f.Namespace != org || f.Visibility != "private" {
		t.Fatalf("fork into the organization: %s %s", f.Namespace, f.Visibility)
	}
	env.runCopies()
	env.wantPublished(org, "helper")

	// The second private agent fills the cap; a third fork is refused.
	env.fork(memberS, alice, "helper", map[string]any{"namespace": org, "name": "helper-2"})
	if code, slug := env.problemSlug(memberS, http.MethodPost, "/api/v1/agents/"+alice+"/helper/fork", map[string]any{"namespace": org, "name": "helper-3"}); code != http.StatusUnprocessableEntity || slug != "private-agent-cap" {
		t.Fatalf("a fork past the cap: %d %s, want 422 private-agent-cap", code, slug)
	}

	// helper-2's copy runs after its forker left the organization.
	if _, err := env.st.Pool().Exec(context.Background(),
		`DELETE FROM memberships WHERE org_id = (SELECT id FROM handles WHERE handle = $1) AND user_id = (SELECT id FROM handles WHERE handle = $2)`, org, member); err != nil {
		t.Fatal(err)
	}
	env.runCopies()
	var failed forkAgentOut
	env.doJSON(adminS, http.MethodGet, "/api/v1/agents/"+org+"/helper-2", nil, &failed, http.StatusOK)
	if failed.ForkState == nil || *failed.ForkState != "failed" || failed.ForkDetail == nil || !strings.Contains(*failed.ForkDetail, "can no longer publish in "+org) {
		t.Fatalf("a copy whose forker left: state %v detail %v", failed.ForkState, failed.ForkDetail)
	}

	// A name a deleted agent holds is held for forks too.
	env.doJSON(adminS, http.MethodDelete, "/api/v1/agents/"+org+"/helper?confirm=helper", nil, nil, http.StatusNoContent)
	if code, slug := env.problemSlug(adminS, http.MethodPost, "/api/v1/agents/"+alice+"/helper/fork", map[string]any{"namespace": org}); code != http.StatusConflict || slug != "name-held" {
		t.Fatalf("a fork onto a held name: %d %s, want 409 name-held", code, slug)
	}
}

// TestAForkOfATaggedOriginContinuesItsHistory: an origin published from a
// git tag has a commit behind its version, so the fork's commit is built on
// that commit: the origin's history is the fork's past, its other files
// and branches come over, and the manifest alone changes.
func TestAForkOfATaggedOriginContinuesItsHistory(t *testing.T) {
	env := newForkEnv(t)
	alice := env.register("fkt-alice")
	env.verifyEmail(alice)
	aliceS := env.login(alice)
	env.doJSON(aliceS, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": alice, "name": "tagged", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	_, pat := env.mintPAT(aliceS, "pub-tagged", "agent:publish", "agent:read")

	// The origin's repository, as a push would leave it: two commits on
	// main, the second tagged v1.0.0, and a file outside the release's
	// include list that a fork still carries.
	originRepo := env.repoOf(alice, "tagged")
	ctx := context.Background()
	if err := env.repos.InitBare(ctx, originRepo, "main"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = work
		cmd.Env = append(cmd.Environ(), "GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@example.test",
			"GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@example.test", "GIT_CONFIG_NOSYSTEM=1", "HOME="+work)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q", "-b", "main")
	for name, body := range skillFiles(alice, "tagged", "0.9.0", nil) {
		write(name, body)
	}
	git("add", ".")
	git("commit", "-q", "-m", "start")
	first := git("rev-parse", "HEAD")
	for name, body := range skillFiles(alice, "tagged", "1.0.0", nil) {
		write(name, body)
	}
	write("NOTES.md", "not in the release, still in the repository\n")
	git("add", ".")
	git("commit", "-q", "-m", "one point oh")
	git("tag", "v1.0.0")
	tagged := git("rev-parse", "HEAD")
	// The origin's main moves on after its release.
	write("NOTES.md", "later work\n")
	git("commit", "-q", "-am", "later")
	later := git("rev-parse", "HEAD")
	gitIn(t, env.repos.Path(originRepo), "fetch", "-q", work, "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
	env.doJSON(caller{name: "pat", pat: pat}, http.MethodPost, "/api/v1/agents/"+alice+"/tagged/versions", map[string]any{"tag": "v1.0.0"}, nil, http.StatusAccepted)
	env.waitStatus(alice, "tagged", "1.0.0", "published")

	bob := env.register("fkt-bob")
	env.verifyEmail(bob)
	bobS := env.login(bob)
	env.fork(bobS, alice, "tagged", map[string]any{"namespace": bob})
	env.runCopies()
	env.wantPublished(bob, "tagged")

	dir := env.repos.Path(env.repoOf(bob, "tagged"))
	if log := gitIn(t, dir, "log", "--format=%H %s", "main"); !strings.Contains(log, first+" start") || !strings.Contains(log, "one point oh") {
		t.Fatalf("the fork's history does not run back through the origin's:\n%s", log)
	}
	if parent := gitIn(t, dir, "rev-parse", "main^"); parent != tagged {
		t.Fatalf("main's parent %s is not the origin's release %s", parent, tagged)
	}
	// The origin's later work is kept beside the fork's branch.
	if kept := gitIn(t, dir, "rev-parse", "origin-main"); kept != later {
		t.Fatalf("origin-main = %s, want the origin's later commit %s", kept, later)
	}
	if notes := gitIn(t, dir, "show", "main:NOTES.md"); notes != "not in the release, still in the repository" {
		t.Fatalf("NOTES.md = %q", notes)
	}
	if diff := gitIn(t, dir, "diff", "--name-only", "main^", "main"); diff != "agent.yaml" {
		t.Fatalf("the fork's commit changes %q, want agent.yaml alone", diff)
	}
	if y := gitIn(t, dir, "show", "main:agent.yaml"); !strings.Contains(y, "namespace: "+bob) || !strings.Contains(y, "name: tagged") {
		t.Fatalf("the renamed manifest:\n%s", y)
	}
}

// TestAForkWhoseCopyNeverRunsIsMarkedFailed: the watchdog marks a fork
// still copying past StuckForkCap as failed, saying so; a fork that is
// ready is left as it is.
func TestAForkWhoseCopyNeverRunsIsMarkedFailed(t *testing.T) {
	env := newForkEnv(t)
	alice := env.register("fks-alice")
	env.verifyEmail(alice)
	env.publishedAgent(env.login(alice), alice, "slow")
	bob := env.register("fks-bob")
	env.verifyEmail(bob)
	bobS := env.login(bob)
	stuck := env.fork(bobS, alice, "slow", map[string]any{"namespace": bob})
	env.copies.take() // the job never runs
	done := env.fork(bobS, alice, "slow", map[string]any{"namespace": bob, "name": "slow-2"})
	env.runCopies()
	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx, `UPDATE agents SET created_at = now() - interval '3 hours' WHERE id = ANY($1)`,
		[]uuid.UUID{stuck.ID, done.ID}); err != nil {
		t.Fatal(err)
	}
	n, err := env.srvObj.Reg().ReconcileStuckForks(ctx)
	if err != nil || n != 1 {
		t.Fatalf("ReconcileStuckForks = %d, %v; want 1", n, err)
	}
	var a forkAgentOut
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents/"+bob+"/slow", nil, &a, http.StatusOK)
	if a.ForkState == nil || *a.ForkState != "failed" || a.ForkDetail == nil || !strings.Contains(*a.ForkDetail, "did not finish") {
		t.Fatalf("the stuck fork: state %v detail %v", a.ForkState, a.ForkDetail)
	}
	env.doJSON(bobS, http.MethodGet, "/api/v1/agents/"+bob+"/slow-2", nil, &a, http.StatusOK)
	if a.ForkState == nil || *a.ForkState != "ready" {
		t.Fatalf("the finished fork: state %v", a.ForkState)
	}
	// A failed fork with no version is the publisher's to delete outright.
	env.doJSON(bobS, http.MethodDelete, "/api/v1/agents/"+bob+"/slow", nil, nil, http.StatusNoContent)
}

// TestTheCopyRefusesAForkTakenOffThePipelineOrInAStoppedOrganization: a
// fork's first version is always scanned, so a fork an administrator took
// off the pipeline before its copy ran fails in words; and the worker
// meets the organization's gate the request did, so a fork in an
// organization suspended meanwhile fails too.
func TestTheCopyRefusesAForkTakenOffThePipelineOrInAStoppedOrganization(t *testing.T) {
	env := newForkEnv(t)
	alice := env.register("fkg-alice")
	env.verifyEmail(alice)
	env.publishedAgent(env.login(alice), alice, "kit")
	ctx := context.Background()
	for _, c := range []struct {
		org, setup, want string
	}{
		{"fkg-skip", `UPDATE agents SET pipeline_skip = true WHERE id = $1`, "taken off the pipeline"},
		{"fkg-susp", `UPDATE orgs SET state = 'suspended' WHERE id = (SELECT namespace_id FROM agents WHERE id = $1)`, "is not taking new versions"},
	} {
		admin := env.register(c.org + "-adm")
		env.verifyEmail(admin)
		adminS := env.login(admin)
		org := c.org + env.sfx
		env.createOrg(adminS, org)
		f := env.fork(adminS, alice, "kit", map[string]any{"namespace": org})
		if _, err := env.st.Pool().Exec(ctx, c.setup, f.ID); err != nil {
			t.Fatal(err)
		}
		env.runCopies()
		var state, detail string
		if err := env.st.Pool().QueryRow(ctx, `SELECT fork_state, fork_detail FROM agents WHERE id = $1`, f.ID).Scan(&state, &detail); err != nil {
			t.Fatal(err)
		}
		if state != "failed" || !strings.Contains(detail, c.want) {
			t.Errorf("%s: state %q detail %q, want failed saying %q", c.org, state, detail, c.want)
		}
		var versions int
		if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM agent_versions WHERE agent_id = $1`, f.ID).Scan(&versions); err != nil || versions != 0 {
			t.Errorf("%s: %d versions (%v), want none", c.org, versions, err)
		}
	}
}
