package api_test

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/pkg/manifest"
)

// uploadVersionCLI packs files into a deterministic archive (as the CLI does)
// and submits the cli-upload multipart to the running server with a PAT.
func (env *testEnv) uploadVersionCLI(ns, name, pat string, files map[string]string) (int, string) {
	env.t.Helper()
	return env.uploadVersionCLIWithHeaders(ns, name, pat, files, nil)
}

// uploadVersionCLIWithHeaders is uploadVersionCLI with extra request headers
// (Idempotency-Key in the replay tests).
func (env *testEnv) uploadVersionCLIWithHeaders(ns, name, pat string, files map[string]string, headers map[string]string) (int, string) {
	env.t.Helper()
	return env.uploadVersionCLIFull(ns, name, pat, files, headers, "", nil)
}

// uploadVersionCLIWithDigest claims a digest of the caller's choosing, for
// the tests that need the server-built digest to disagree with it.
func (env *testEnv) uploadVersionCLIWithDigest(ns, name, pat string, files map[string]string, digest string) (int, string) {
	env.t.Helper()
	return env.uploadVersionCLIFull(ns, name, pat, files, nil, digest, nil)
}

// uploadVersionCLIWithFields adds form fields to the upload (draftRun in
// the provenance tests).
func (env *testEnv) uploadVersionCLIWithFields(ns, name, pat string, files map[string]string, fields map[string]string) (int, string) {
	env.t.Helper()
	return env.uploadVersionCLIFull(ns, name, pat, files, nil, "", fields)
}

func (env *testEnv) uploadVersionCLIFull(ns, name, pat string, files map[string]string, headers map[string]string, claimedDigest string, fields map[string]string) (int, string) {
	env.t.Helper()
	ws := env.t.TempDir()
	for path, content := range files {
		full := filepath.Join(ws, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			env.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			env.t.Fatal(err)
		}
	}
	inv, err := registry.WalkWorkspace(ws)
	if err != nil {
		env.t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(ws, "agent.yaml"))
	if err != nil {
		env.t.Fatal(err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		env.t.Fatal(err)
	}
	include := manifest.ResolveInclude(m.Publish.Include, inv)
	var archive bytes.Buffer
	info, err := registry.BuildArchive(ws, include, &archive)
	if err != nil {
		env.t.Fatal(err)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("archive", "a.tar.zst")
	_, _ = part.Write(archive.Bytes())
	if claimedDigest == "" {
		claimedDigest = info.Digest
	}
	_ = mw.WriteField("digest", claimedDigest)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	_ = mw.Close()

	req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/api/v1/agents/"+ns+"/"+name+"/versions", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+pat)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := env.srv.Client().Do(req)
	if err != nil {
		env.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	rb, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(rb)
}

func sleep10ms() { time.Sleep(10 * time.Millisecond) }
