package api_test

// Public archive browsing (file browser): the same hardened walk as
// the review viewer, opened under the download gate. Pins what a consumer
// sees: anonymous listing, text round-trip, binary withheld, path safety,
// and the block gate.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// displayCap is the most of a file the browser shows (512 KiB).
const displayCap = 512 << 10

// noiseOfSize is an image-shaped file of exactly n bytes that does not
// compress away.
func noiseOfSize(n int) string {
	var sb strings.Builder
	sb.WriteString("\x89PNG\r\n\x1a\n")
	seed := sha256.Sum256([]byte("version files fixture"))
	for sb.Len() < n {
		seed = sha256.Sum256(seed[:])
		sb.WriteString(hex.EncodeToString(seed[:]))
		sb.WriteByte('\n')
	}
	return sb.String()[:n]
}

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
  include: [agent.yaml, README.md, SKILL.md, LICENSE, img.png, at.png, over.png]
`,
		"README.md": "# browsable\n",
		"SKILL.md":  "Summarize the input politely.\n",
		"LICENSE":   "Apache-2.0\n",
		"img.png":   "\x89PNG\r\n\x1a\n\x00\x00binarybytes",
		"at.png":    noiseOfSize(displayCap),
		"over.png":  noiseOfSize(displayCap + 1),
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
	for _, f := range list.Files {
		if want, ok := files[f.Path]; ok && f.Size != int64(len(want)) {
			t.Fatalf("listing says %s is %d bytes, want %d", f.Path, f.Size, len(want))
		}
	}

	// Text content round-trips for anonymous callers.
	var fc struct {
		Binary    bool    `json:"binary"`
		Truncated bool    `json:"truncated"`
		Size      int64   `json:"size"`
		Content   *string `json:"content"`
	}
	env.doJSON(anonymous, http.MethodGet, base+"/file?path=SKILL.md", nil, &fc, http.StatusOK)
	if fc.Binary || fc.Content == nil || !strings.Contains(*fc.Content, "politely") {
		t.Fatalf("SKILL.md content wrong: %+v", fc)
	}

	if fc.Size != int64(len(files["SKILL.md"])) || fc.Truncated {
		t.Fatalf("SKILL.md size %d truncated %v, want %d and whole", fc.Size, fc.Truncated, len(files["SKILL.md"]))
	}
	// A path inside the archive reads the same by any spelling of it.
	for _, spelling := range []string{"./SKILL.md", "docs/../SKILL.md"} {
		var again struct {
			Path    string  `json:"path"`
			Content *string `json:"content"`
		}
		env.doJSON(anonymous, http.MethodGet, base+"/file?path="+spelling, nil, &again, http.StatusOK)
		if again.Path != "SKILL.md" || again.Content == nil || !strings.Contains(*again.Content, "politely") {
			t.Fatalf("path %q: %+v", spelling, again)
		}
	}

	// Binary files are flagged and withheld.
	fc.Content = nil
	env.doJSON(anonymous, http.MethodGet, base+"/file?path=img.png", nil, &fc, http.StatusOK)
	if !fc.Binary || fc.Content != nil {
		t.Fatalf("binary file must be flagged without content: %+v", fc)
	}
	// What is shown is capped: a file of exactly the cap is whole, one byte
	// more is marked cut.
	for _, tc := range []struct {
		path      string
		truncated bool
	}{{"at.png", false}, {"over.png", true}} {
		var big struct {
			Size      int64 `json:"size"`
			Truncated bool  `json:"truncated"`
		}
		env.doJSON(anonymous, http.MethodGet, base+"/file?path="+tc.path, nil, &big, http.StatusOK)
		if big.Size != int64(len(files[tc.path])) || big.Truncated != tc.truncated {
			t.Fatalf("%s: size %d truncated %v, want %d and %v", tc.path, big.Size, big.Truncated, len(files[tc.path]), tc.truncated)
		}
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
	for _, bad := range []string{"/etc/passwd", "..", "../SKILL.md", ".", "%2E%2F"} {
		res = env.do(anonymous, http.MethodGet, base+"/file?path="+bad, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("path %q: got %d want 422", bad, res.StatusCode)
		}
	}

	// Browsing is not installing: none of the reads above counted as one.
	var listing []struct {
		Name        string `json:"name"`
		Installs30d *int   `json:"installs30d"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents?namespace="+author, nil, &listing, http.StatusOK)
	if len(listing) != 1 || listing[0].Installs30d == nil || *listing[0].Installs30d != 0 {
		t.Fatalf("after browsing the archive the agent's installs read %+v, want 0", listing)
	}

	// The version's own status gates browsing as it gates the download:
	// yanked is browsable and marked so, quarantined and blocked are
	// refused as the download is, and a version not yet decided is absent.
	for _, tc := range []struct {
		status string
		code   int
		yanked bool
	}{
		{"yanked", http.StatusOK, true}, {"quarantined", http.StatusConflict, false}, {"blocked", http.StatusGone, false},
		{"needs_review", http.StatusNotFound, false}, {"scanning", http.StatusNotFound, false}, {"rejected", http.StatusNotFound, false},
		{"published", http.StatusOK, false},
	} {
		if _, err := env.st.Pool().Exec(context.Background(),
			`UPDATE agent_versions av SET status = $2 FROM agents a JOIN handles h ON h.id = a.namespace_id
			 WHERE av.agent_id = a.id AND h.handle = $1 AND a.name = 'browsable'`, author, tc.status); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/files", "/file?path=SKILL.md"} {
			res = env.do(anonymous, http.MethodGet, base+path, nil)
			_ = res.Body.Close()
			if res.StatusCode != tc.code || (res.Header.Get("X-Agentry-Yanked") == "true") != tc.yanked {
				t.Fatalf("%s of a %s version: %d (yanked header %q), want %d and yanked %v", path, tc.status, res.StatusCode, res.Header.Get("X-Agentry-Yanked"), tc.code, tc.yanked)
			}
		}
	}

	// A private agent's archive is not a stranger's to read.
	env.doJSON(authorSess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": author, "name": "hidden", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	if status, body := env.uploadVersionCLI(author, "hidden", pat, skillFiles(author, "hidden", "1.0.0", nil)); status != http.StatusAccepted {
		t.Fatalf("submit to the private agent: %d %s", status, body)
	}
	stranger := env.login(env.register("vfb-str"))
	hidden := "/api/v1/agents/" + author + "/hidden/versions/1.0.0"
	for _, c := range []caller{authorSess, stranger, anonymous} {
		for _, path := range []string{"/files", "/file?path=SKILL.md"} {
			want := http.StatusNotFound
			if c.name == authorSess.name {
				want = http.StatusOK
			}
			res = env.do(c, http.MethodGet, hidden+path, nil)
			_ = res.Body.Close()
			if res.StatusCode != want {
				t.Fatalf("%s of the private agent's version for %s: %d, want %d", path, c.name, res.StatusCode, want)
			}
		}
	}

	// The agent's own block gates browsing before any version has been
	// walked to blocked, as it gates the download.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agents SET quarantine_state = 'blocked' WHERE id = (SELECT a.id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'browsable')`, author); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/files", "/file?path=SKILL.md"} {
		res = env.do(anonymous, http.MethodGet, base+path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusGone {
			t.Fatalf("%s of an agent blocked before its versions were: got %d want 410", path, res.StatusCode)
		}
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agents SET quarantine_state = 'none' WHERE id = (SELECT a.id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'browsable')`, author); err != nil {
		t.Fatal(err)
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
