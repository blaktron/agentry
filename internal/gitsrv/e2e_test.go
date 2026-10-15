package gitsrv_test

// M3 acceptance (§18.2): publish→install round-trip for all 3 kinds × both
// sources (git-tag, cli-upload), plus yank semantics — against the fully
// wired server (dev-mode auto-approve pipeline stub).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/registry"
	pkgarchive "github.com/blaktron/agentry/pkg/archive"
	"github.com/blaktron/agentry/pkg/manifest"
)

// kindFixture returns manifest + files for one agent kind.
func kindFixture(kind, ns, name, version string) map[string]string {
	base := map[string]string{
		"README.md": "# " + name + "\n",
		"LICENSE":   "Apache-2.0 placeholder text\n",
	}
	switch kind {
	case "skill":
		base["SKILL.md"] = "Do the thing carefully.\n"
		base["agent.yaml"] = fmt.Sprintf(`schemaVersion: "1"
name: %s
namespace: %s
kind: skill
version: %s
summary: "Test skill"
license: Apache-2.0
entrypoints:
  skill: SKILL.md
publish:
  include: [agent.yaml, README.md, SKILL.md, LICENSE]
`, name, ns, version)
	case "prompt-agent":
		base["prompts/main.md"] = "You are a careful assistant.\n"
		base["agent.yaml"] = fmt.Sprintf(`schemaVersion: "1"
name: %s
namespace: %s
kind: prompt-agent
version: %s
summary: "Test prompt agent"
license: Apache-2.0
publish:
  include: [agent.yaml, README.md, prompts/**, LICENSE]
`, name, ns, version)
	case "v2":
		base["AGENT.md"] = "---\nname: " + name + "\n---\nDo the thing carefully, and ask when unsure.\n"
		base["agent.yaml"] = fmt.Sprintf(`schemaVersion: "2"
name: %s
namespace: %s
version: %s
summary: "Test v2 agent"
license: Apache-2.0
modes: [autonomous, interactive]
entrypoints:
  instruction: AGENT.md
intake:
  - id: topic
    prompt: "What should I look at?"
interactive:
  opening: "What should I look at?"
publish:
  include: [agent.yaml, README.md, AGENT.md, LICENSE]
`, name, ns, version)
	case "mcp-server":
		base["src/server.js"] = "console.log('mcp server')\n"
		base["package-lock.json"] = `{"name":"t","lockfileVersion":3,"packages":{}}` + "\n"
		base["agent.yaml"] = fmt.Sprintf(`schemaVersion: "1"
name: %s
namespace: %s
kind: mcp-server
version: %s
summary: "Test MCP server"
license: Apache-2.0
entrypoints:
  mcp:
    command: node
    args: [src/server.js]
    transport: stdio
publish:
  include: [agent.yaml, README.md, src/**, package-lock.json, LICENSE]
`, name, ns, version)
	}
	return base
}

// waitPublished polls until the version leaves the pipeline (dev stub is
// synchronous today, but the M4 orchestrator won't be).
func (e *gitEnv) waitPublished(agent, version string) {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, err := http.Get(fmt.Sprintf("%s/api/v1/agents/%s/%s/versions/%s", e.srv.URL, e.owner.handle, agent, version))
		if err != nil {
			e.t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode == 200 {
			var v map[string]any
			if err := json.Unmarshal(body, &v); err != nil {
				e.t.Fatal(err)
			}
			switch v["status"] {
			case "published":
				return
			case "rejected", "needs_review":
				e.t.Fatalf("version %s ended in %v: %v", version, v["status"], v["statusReason"])
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("version %s not published in time (last: %d %s)", version, res.StatusCode, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// wantAgentModes reads the agent back through the API and asserts the run
// modes a publish left on the row.
func (e *gitEnv) wantAgentModes(agent string, want []string) {
	e.t.Helper()
	res, err := http.Get(e.srv.URL + "/api/v1/agents/" + e.owner.handle + "/" + agent)
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	var a struct {
		Modes []string `json:"modes"`
	}
	if res.StatusCode != 200 || json.Unmarshal(body, &a) != nil {
		e.t.Fatalf("get agent %s: %d %s", agent, res.StatusCode, body)
	}
	if strings.Join(a.Modes, ",") != strings.Join(want, ",") {
		e.t.Fatalf("agent %s modes after publish = %v, want %v", agent, a.Modes, want)
	}
}

// installRoundTrip resolves, downloads, verifies the digest, and extracts.
func (e *gitEnv) installRoundTrip(agent, rangeStr, wantVersion string, wantFiles ...string) {
	e.t.Helper()
	ref := e.owner.handle + "/" + agent
	if rangeStr != "" {
		ref += "@" + rangeStr
	}
	res, err := http.Get(e.srv.URL + "/api/v1/resolve?ref=" + ref)
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 200 {
		e.t.Fatalf("resolve %s: %d %s", ref, res.StatusCode, body)
	}
	var rr struct {
		Version    string `json:"version"`
		Digest     string `json:"digest"`
		ArchiveUrl string `json:"archiveUrl"`
		Yanked     bool   `json:"yanked"`
	}
	if err := json.Unmarshal(body, &rr); err != nil {
		e.t.Fatal(err)
	}
	if rr.Version != wantVersion {
		e.t.Fatalf("resolve %s: got %s want %s", ref, rr.Version, wantVersion)
	}

	dl, err := http.Get(e.srv.URL + "/api/v1/agents/" + e.owner.handle + "/" + agent + "/versions/" + rr.Version + "/download")
	if err != nil {
		e.t.Fatal(err)
	}
	archive, _ := io.ReadAll(dl.Body)
	_ = dl.Body.Close()
	if dl.StatusCode != 200 {
		e.t.Fatalf("download: %d %s", dl.StatusCode, archive)
	}

	// Client-side digest verification (§9.4 step 3).
	sum := sha256Hex(archive)
	if "sha256:"+sum != rr.Digest {
		e.t.Fatalf("digest mismatch: got sha256:%s want %s", sum, rr.Digest)
	}

	dst := e.t.TempDir()
	if err := pkgarchive.Unpack(bytes.NewReader(archive), dst, 5<<20, 10<<20); err != nil {
		e.t.Fatal(err)
	}
	for _, f := range wantFiles {
		if _, err := os.Stat(filepath.Join(dst, f)); err != nil {
			e.t.Fatalf("installed tree missing %s", f)
		}
	}
}

// TestPublishInstallRoundTrip covers the manifest shapes that publish ×
// 2 sources: the two v1 kinds still accepted, and a v2 manifest (modes,
// DEV-088).
func TestPublishInstallRoundTrip(t *testing.T) {
	env := newGitEnv(t)

	kinds := []struct {
		kind      string   // fixture shape
		seedModes []string // the agent row's modes at creation
		wantModes []string // the row's modes after the publish (agentry#162)
		entryFile string
	}{
		{"skill", []string{"autonomous"}, []string{"autonomous"}, "SKILL.md"},
		{"prompt-agent", []string{"autonomous"}, []string{"autonomous"}, "prompts/main.md"},
		// Seeded autonomous-only on purpose: the v2 manifest declares both
		// modes and the publish must be what makes that true of the agent.
		{"v2", []string{"autonomous"}, []string{"autonomous", "interactive"}, "AGENT.md"},
	}

	for _, k := range kinds {
		k := k
		t.Run(k.kind+"/git-tag", func(t *testing.T) {
			name := strings.ReplaceAll(k.kind, "-", "") + "gt"
			env.seedAgentModes(name, k.seedModes, "public")
			work := seedWorkdir(t, kindFixture(k.kind, env.owner.handle, name, "1.0.0"))
			mustGit(t, work, "push", env.cloneURL(name, env.owner.patRW), "main")
			mustGit(t, work, "tag", "v1.0.0")
			mustGit(t, work, "push", env.cloneURL(name, env.owner.patRW), "v1.0.0")
			env.waitPublished(name, "1.0.0")
			env.wantAgentModes(name, k.wantModes)
			env.installRoundTrip(name, "^1.0", "1.0.0", "agent.yaml", "README.md", k.entryFile)
		})

		t.Run(k.kind+"/cli-upload", func(t *testing.T) {
			name := strings.ReplaceAll(k.kind, "-", "") + "up"
			env.seedAgentModes(name, k.seedModes, "public")
			ws := t.TempDir()
			for path, content := range kindFixture(k.kind, env.owner.handle, name, "1.0.0") {
				full := filepath.Join(ws, path)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			status, body := env.uploadVersion(name, ws)
			if status != http.StatusAccepted {
				t.Fatalf("upload: %d %s", status, body)
			}
			env.waitPublished(name, "1.0.0")
			env.wantAgentModes(name, k.wantModes)
			env.installRoundTrip(name, "1.0.0", "1.0.0", "agent.yaml", k.entryFile)
		})
	}
}

// TestWithdrawnKindIsRefused: kind mcp-server is withdrawn (DEV-088). An
// agent of that kind can no longer be created (the registry refuses it;
// the rows that predate the withdrawal are blocked by migration 00023), so
// the manifest arrives against an instruction agent and is refused on both
// sources, and nothing resolves. The tag submission runs inline in
// post-receive and a refused manifest leaves no version row at all
// (http.go: failures surface as the version's absence), so once the push
// has returned the absence is the assertion; the CLI upload is refused
// with 422 naming the withdrawal.
func TestWithdrawnKindIsRefused(t *testing.T) {
	env := newGitEnv(t)

	t.Run("git-tag", func(t *testing.T) {
		name := "mcpservergt"
		env.seedAgentModes(name, []string{"autonomous"}, "public")
		work := seedWorkdir(t, kindFixture("mcp-server", env.owner.handle, name, "1.0.0"))
		mustGit(t, work, "push", env.cloneURL(name, env.owner.patRW), "main")
		mustGit(t, work, "tag", "v1.0.0")
		mustGit(t, work, "push", env.cloneURL(name, env.owner.patRW), "v1.0.0")
		for _, path := range []string{
			"/api/v1/agents/" + env.owner.handle + "/" + name + "/versions/1.0.0",
			"/api/v1/resolve?ref=" + env.owner.handle + "/" + name,
		} {
			res, err := http.Get(env.srv.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode != http.StatusNotFound {
				t.Fatalf("GET %s after a refused tag push: %d %s (want 404: no version may exist)", path, res.StatusCode, body)
			}
		}
	})

	t.Run("cli-upload", func(t *testing.T) {
		name := "mcpserverup"
		env.seedAgentModes(name, []string{"autonomous"}, "public")
		ws := t.TempDir()
		for path, content := range kindFixture("mcp-server", env.owner.handle, name, "1.0.0") {
			full := filepath.Join(ws, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		status, body := env.uploadVersion(name, ws)
		if status != http.StatusUnprocessableEntity || !strings.Contains(body, "withdrawn") {
			t.Fatalf("upload of a withdrawn kind: %d %s (want 422 naming the withdrawal)", status, body)
		}
	})
}

// uploadVersion packs ws exactly like the CLI will (deterministic archive of
// the include set) and POSTs it as multipart.
func (e *gitEnv) uploadVersion(agent, ws string) (int, string) {
	e.t.Helper()
	files, err := registry.WalkWorkspace(ws)
	if err != nil {
		e.t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(ws, "agent.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	include := manifest.ResolveInclude(m.Publish.Include, files)
	var archive bytes.Buffer
	info, err := registry.BuildArchive(ws, include, &archive)
	if err != nil {
		e.t.Fatal(err)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("archive", "agent.tar.zst")
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := part.Write(archive.Bytes()); err != nil {
		e.t.Fatal(err)
	}
	if err := mw.WriteField("digest", info.Digest); err != nil {
		e.t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		e.t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost,
		e.srv.URL+"/api/v1/agents/"+e.owner.handle+"/"+agent+"/versions", &body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+e.owner.patRW)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	respBody, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(respBody)
}

// TestYankSemantics pins §5.5: ranges skip yanked, exact pins resolve
// with a warning, and re-publish of a yanked version string is impossible.
func TestYankSemantics(t *testing.T) {
	env := newGitEnv(t)
	name := "yankcase"
	env.seedAgent(name, "public")

	publish := func(version string) {
		ws := t.TempDir()
		for path, content := range kindFixture("skill", env.owner.handle, name, version) {
			full := filepath.Join(ws, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if status, body := env.uploadVersion(name, ws); status != http.StatusAccepted {
			t.Fatalf("upload %s: %d %s", version, status, body)
		}
		env.waitPublished(name, version)
	}
	publish("1.0.0")
	publish("1.1.0")

	// Yank 1.1.0.
	req, _ := http.NewRequest(http.MethodPost,
		env.srv.URL+"/api/v1/agents/"+env.owner.handle+"/"+name+"/versions/1.1.0/yank",
		strings.NewReader(`{"reason":"broken build"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+env.owner.patRW)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("yank: %d", res.StatusCode)
	}

	// Range resolution skips the yanked version.
	env.installRoundTrip(name, "^1.0", "1.0.0", "agent.yaml")

	// Exact pin still resolves, flagged yanked.
	res, err = http.Get(env.srv.URL + "/api/v1/resolve?ref=" + env.owner.handle + "/" + name + "@1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	var rr struct {
		Yanked bool `json:"yanked"`
	}
	if err := json.Unmarshal(body, &rr); err != nil || !rr.Yanked {
		t.Fatalf("exact pin of yanked version: %d %s (err %v)", res.StatusCode, body, err)
	}

	// The version string is burned forever (§5.5): re-upload rejected.
	ws := t.TempDir()
	for path, content := range kindFixture("skill", env.owner.handle, name, "1.1.0") {
		full := filepath.Join(ws, path)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(content), 0o644)
	}
	if status, body := env.uploadVersion(name, ws); status != http.StatusUnprocessableEntity {
		t.Fatalf("re-publish of yanked version string must 422, got %d %s", status, body)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
