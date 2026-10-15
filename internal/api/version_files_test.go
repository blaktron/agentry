package api_test

// Public archive browsing (file browser): the same hardened walk as
// the review viewer, opened under the download gate. Pins what a consumer
// sees: anonymous listing, text round-trip, binary withheld, path safety,
// and the block gate.

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestVersionFilesBrowsing(t *testing.T) {
	env := newTestEnv(t)
	author := env.register("vfb-auth")
	env.verifyEmail(author)
	authorSess := env.login(author)
	_, _ = env.st.Pool().Exec(context.Background(),
		`UPDATE users SET created_at = now() - interval '30 days' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, author)

	env.doJSON(authorSess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": author, "name": "browsable", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(authorSess, "pub", "agent:publish", "agent:read", "repo:read")

	files := map[string]string{
		"agent.yaml": `schemaVersion: "2"
name: browsable
namespace: ` + author + `
modes: [autonomous]
version: 1.0.0
summary: "test"
license: Apache-2.0
entrypoints:
  instruction: SKILL.md
publish:
  include: [agent.yaml, README.md, SKILL.md, LICENSE, img.png]
`,
		"README.md": "# browsable\n",
		"SKILL.md":  "Summarize the input politely.\n",
		"LICENSE":   "Apache-2.0\n",
		"img.png":   "\x89PNG\r\n\x1a\n\x00\x00binarybytes",
	}
	if status, body := env.uploadVersionCLI(author, "browsable", pat, files); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	env.waitStatus(author, "browsable", "1.0.0", "published")

	base := "/api/v1/agents/" + author + "/browsable/versions/1.0.0"

	// Anonymous listing carries every file in the archive.
	var list struct {
		Files []struct {
			Path string `json:"path"`
			Size int64  `json:"size"`
		} `json:"files"`
	}
	env.doJSON(anonymous, http.MethodGet, base+"/files", nil, &list, http.StatusOK)
	paths := map[string]bool{}
	for _, f := range list.Files {
		paths[f.Path] = true
	}
	for _, want := range []string{"agent.yaml", "README.md", "SKILL.md", "LICENSE", "img.png"} {
		if !paths[want] {
			t.Fatalf("listing missing %s: %v", want, paths)
		}
	}

	// Text content round-trips for anonymous callers.
	var fc struct {
		Binary    bool    `json:"binary"`
		Truncated bool    `json:"truncated"`
		Content   *string `json:"content"`
	}
	env.doJSON(anonymous, http.MethodGet, base+"/file?path=SKILL.md", nil, &fc, http.StatusOK)
	if fc.Binary || fc.Content == nil || !strings.Contains(*fc.Content, "politely") {
		t.Fatalf("SKILL.md content wrong: %+v", fc)
	}

	// Binary files are flagged and withheld.
	fc.Content = nil
	env.doJSON(anonymous, http.MethodGet, base+"/file?path=img.png", nil, &fc, http.StatusOK)
	if !fc.Binary || fc.Content != nil {
		t.Fatalf("binary file must be flagged without content: %+v", fc)
	}

	// Unknown path is 404; traversal is 422.
	res := env.do(anonymous, http.MethodGet, base+"/file?path=nope.md", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path: got %d want 404", res.StatusCode)
	}
	res = env.do(anonymous, http.MethodGet, base+"/file?path=../../etc/passwd", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("traversal path: got %d want 422", res.StatusCode)
	}

	// The block gate applies to browsing exactly as it does to downloads.
	staff := env.register("vfb-staff")
	env.verifyEmail(staff)
	env.makePlatformStaff(t, staff)
	staffSess := env.login(staff)
	res = env.do(staffSess, http.MethodPost,
		"/api/v1/platform/agents/"+author+"/browsable/block", map[string]any{"reason": "test"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("block: got %d want 204", res.StatusCode)
	}
	res = env.do(anonymous, http.MethodGet, base+"/files", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusGone {
		t.Fatalf("blocked listing: got %d want 410", res.StatusCode)
	}
}
