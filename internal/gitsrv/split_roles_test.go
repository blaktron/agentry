package gitsrv_test

// A tag pushed on a split deployment: the git role holds no object-store
// credential (the chart gives the store's Secret to the api and worker pods
// only), so it records the version and hands the archive write
// to a worker, which rebuilds the archive from the recorded commit, checks
// the digest, stores it and enters the version into the machine.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
)

// splitGitRole builds the git environment wired as agentryd wires the git
// role: scans and tag archive writes handed off. Its store is gitStore, so
// a write by the git role would show up there.
func splitGitRole(t *testing.T, gitStore string) *gitEnv {
	t.Helper()
	env := newGitEnvCfg(t, func(c *config.Config) { c.Storage.LocalDir = gitStore })
	env.api.HandOffScans()
	env.api.DeferTagArchives()
	return env
}

// worker builds the worker role beside env: the same database and git
// data, its own store, and the handlers newWorkerQueue registers.
func (e *gitEnv) worker(store string) *queue.RiverClient {
	e.t.Helper()
	cfg := e.cfg
	cfg.Storage.LocalDir = store
	srv := api.New(cfg, e.st, nil)
	srv.Reg().SetGitArchiver(e.repos)
	w := queue.NewRiverClient(e.st, nil)
	w.SetTestOnly(true)
	srv.Pipeline().RegisterHandlers(w)
	srv.RegisterQueueHandlers(w)
	return w
}

// storedFiles lists the regular files under a local blob store.
func storedFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// versionRow reads the 1.0.0 row of an owner agent.
func (e *gitEnv) versionRow(agent string) (id, status, digest, key string) {
	e.t.Helper()
	if err := e.st.Pool().QueryRow(context.Background(), `
		SELECT v.id::text, v.status, coalesce(v.archive_digest, ''), coalesce(v.archive_key, '')
		FROM agent_versions v JOIN agents a ON a.id = v.agent_id JOIN handles h ON h.id = a.namespace_id
		WHERE h.handle = $1 AND a.name = $2 AND v.version = '1.0.0'`, e.owner.handle, agent,
	).Scan(&id, &status, &digest, &key); err != nil {
		e.t.Fatalf("version row %s@1.0.0: %v", agent, err)
	}
	return id, status, digest, key
}

// pushTag seeds a public skill agent and pushes main and its v1.0.0 tag.
func (e *gitEnv) pushTag(agent string) {
	const version = "1.0.0"
	e.t.Helper()
	e.seedAgent(agent, "public")
	work := seedWorkdir(e.t, kindFixture("skill", e.owner.handle, agent, version))
	mustGit(e.t, work, "push", e.cloneURL(agent, e.owner.patRW), "main")
	mustGit(e.t, work, "tag", "v"+version)
	mustGit(e.t, work, "push", e.cloneURL(agent, e.owner.patRW), "v"+version)
}

func TestSplitGitRoleLeavesTheTagArchiveToTheWorker(t *testing.T) {
	gitStore, workerStore := t.TempDir(), t.TempDir()
	env := splitGitRole(t, gitStore)
	env.pushTag("splitpub")

	// The git role recorded the version with its digest and key, wrote
	// nothing to its store, and left one store job for the worker.
	id, status, digest, key := env.versionRow("splitpub")
	if status != "submitted" || digest == "" || key == "" {
		t.Fatalf("after the push: status=%q digest=%q key=%q, want submitted with a digest and a key", status, digest, key)
	}
	if files := storedFiles(t, gitStore); len(files) != 0 {
		t.Fatalf("the git role wrote to the object store: %v", files)
	}
	var jobs int
	if err := env.st.Pool().QueryRow(context.Background(), `
		SELECT count(*) FROM river_job WHERE kind = $1 AND queue = 'sandbox' AND args->>'versionId' = $2`,
		registry.JobStoreTagArchive, id).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("store jobs for the version = %d, want 1", jobs)
	}

	// The worker stores the archive the git role described and takes the
	// version through the scan it enqueues.
	w := env.worker(workerStore)
	w.Drain(context.Background(), "sandbox")

	if _, status, _, _ = env.versionRow("splitpub"); status != "published" {
		t.Fatalf("after the worker ran the version is %q, want published", status)
	}
	if files := storedFiles(t, gitStore); len(files) != 0 {
		t.Fatalf("the git role's store is no longer empty: %v", files)
	}
	blob, err := os.ReadFile(filepath.Join(workerStore, filepath.FromSlash(key)))
	if err != nil {
		t.Fatalf("the archive is not in the worker's store at %s: %v", key, err)
	}
	sum := sha256.Sum256(blob)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
		t.Fatalf("stored archive digest %s, recorded %s (archives are byte-reproducible)", got, digest)
	}

	// The api role, which reads the same store, serves the release the
	// worker stored (downloads are the api role's, not the git role's).
	apiCfg := env.cfg
	apiCfg.Storage.LocalDir = workerStore
	apiRole := httptest.NewServer(api.NewHandler(api.New(apiCfg, env.st, nil, api.WithoutSigningKey())))
	t.Cleanup(apiRole.Close)
	env.srv = apiRole
	env.installRoundTrip("splitpub", "1.0.0", "1.0.0", "agent.yaml", "SKILL.md")
}

// TestSplitGitRoleStuckSubmissionIsRejected: a handed-off submission whose
// archive is never stored (here: no worker ever runs) is rejected by the
// watchdog once past the cap, never left `submitted` and never routed to a
// review that could publish a version with no archive.
func TestSplitGitRoleStuckSubmissionIsRejected(t *testing.T) {
	env := splitGitRole(t, t.TempDir())
	env.pushTag("splitstuck")
	id, status, _, _ := env.versionRow("splitstuck")
	if status != "submitted" {
		t.Fatalf("after the push: %q, want submitted", status)
	}

	ctx := context.Background()
	// Inside the cap the watchdog leaves it alone.
	if n, err := env.reg.ReconcileStuckSubmissions(ctx); err != nil || n != 0 {
		t.Fatalf("watchdog inside the cap: moved %d, err %v", n, err)
	}
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE agent_versions SET updated_at = now() - interval '121 minutes' WHERE id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := env.reg.ReconcileStuckSubmissions(ctx); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT status, coalesce(status_reason, '') FROM agent_versions WHERE id = $1::uuid`, id).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "rejected" || !strings.Contains(reason, "archive was not stored") {
		t.Fatalf("after the watchdog: %q (%q), want rejected naming the unstored archive", status, reason)
	}
	var items int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM review_items WHERE version_id = $1::uuid`, id).Scan(&items); err != nil {
		t.Fatal(err)
	}
	if items != 0 {
		t.Fatalf("the stuck submission was routed to review (%d item(s))", items)
	}
}

// TestSplitGitRoleWorkerRefusesADigestItCannotReproduce: the worker stores
// nothing unless the archive it rebuilds from the recorded commit has the
// recorded digest, so a row that describes other bytes never gets an
// object under its key and never enters the machine.
func TestSplitGitRoleWorkerRefusesADigestItCannotReproduce(t *testing.T) {
	workerStore := t.TempDir()
	env := splitGitRole(t, t.TempDir())
	env.pushTag("splitmismatch")
	id, _, _, _ := env.versionRow("splitmismatch")

	const forged = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE agent_versions SET archive_digest = $2, archive_key = $3 WHERE id = $1::uuid`,
		id, forged, registry.ArchiveKey(forged)); err != nil {
		t.Fatal(err)
	}
	w := env.worker(workerStore)
	w.Drain(ctx, "sandbox")

	if _, status, _, _ := env.versionRow("splitmismatch"); status != "submitted" {
		t.Fatalf("after the worker ran on a forged digest the version is %q, want submitted", status)
	}
	if files := storedFiles(t, workerStore); len(files) != 0 {
		t.Fatalf("the worker stored an archive it could not reproduce: %v", files)
	}
}
