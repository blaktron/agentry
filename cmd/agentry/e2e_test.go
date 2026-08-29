package main

// End-to-end tests for the two §11 promises this wave implements: install
// verifies a signature, and validate can update its rule bundle.
//
// The registry under test is the REAL server handler (api.NewHandler) for the
// endpoints this wave added — GET /meta and GET /ruleset-releases/latest/bundle
// are served by the shipped code, not by a stub. The release plumbing that a
// full publish would produce (resolve, archive bytes, DSSE attestation,
// signing keys) is fixtured on top, but signed and verified with the REAL
// internal/scan signer and verifier, so a change to either side's crypto or
// envelope format breaks these tests.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/PLACEHOLDER_ORG/agentry/internal/api"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/internal/scan"
	"github.com/PLACEHOLDER_ORG/agentry/internal/scan/ruleset"
	"github.com/PLACEHOLDER_ORG/agentry/pkg/rules"
)

// ---------------------------------------------------------------- fixtures

// testRegistry is a registry the CLI can be pointed at: the real API handler
// underneath, release fixtures on top.
type testRegistry struct {
	srv    *httptest.Server
	signer scan.Signer
	// archive is the tar.zst the CLI will download, and digest its sha256.
	archive []byte
	digest  string
	// manifestJSON is what /resolve reports as the version's manifest.
	manifestJSON map[string]any
	// signed controls whether an attestation is published at all.
	signed bool
	// tamper, when set, corrupts the served archive AFTER the attestation was
	// built over the honest bytes.
	tamper bool
	// noKeys serves an empty signing-key set.
	noKeys bool
	// archiveHits counts archive downloads, so a test can assert that a
	// rejected flag cost no bytes.
	archiveHits int
	ns          string
	name        string
	ver         string
}

// newTestRegistry boots the fixture registry. The api.Server runs without a
// database (New tolerates a nil store), which is all the endpoints under test
// need: the rule bundle is embedded and /meta reads config.
func newTestRegistry(t *testing.T, reg *testRegistry) *testRegistry {
	t.Helper()
	if reg == nil {
		reg = &testRegistry{}
	}
	if reg.ns == "" {
		reg.ns = "acme"
	}
	if reg.name == "" {
		reg.name = "helper"
	}
	if reg.ver == "" {
		reg.ver = "1.0.0"
	}

	signer, err := scan.NewFileSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	reg.signer = signer

	cfg := config.Default()
	cfg.DevMode = true
	apiHandler := api.NewHandler(api.New(cfg, nil, nil))

	mux := http.NewServeMux()
	// Fixture endpoints, most specific first.
	mux.HandleFunc("GET /.well-known/agentry/signing-keys.json", reg.serveKeys)
	mux.HandleFunc("GET /api/v1/resolve", reg.serveResolve)
	mux.HandleFunc("GET /fixtures/archive.tar.zst", reg.serveArchive)
	mux.HandleFunc("GET /fixtures/attestation.json", reg.serveAttestation)
	// The canonical attestation path the CLI probes when a resolve result
	// carries no attestationUrl. A real registry answers 404 there for an
	// unsigned version, and that 404 is what "unsigned" means to the client.
	mux.HandleFunc("GET /api/v1/agents/{ns}/{name}/versions/{version}/attestation", reg.serveAttestation)
	// Everything else — /api/v1/meta, /api/v1/ruleset-releases/latest/bundle —
	// is the real server.
	mux.Handle("/", apiHandler)

	reg.srv = httptest.NewServer(mux)
	t.Cleanup(reg.srv.Close)
	return reg
}

func (r *testRegistry) url() string { return r.srv.URL }

func (r *testRegistry) serveKeys(w http.ResponseWriter, _ *http.Request) {
	type key struct {
		KeyID     string `json:"keyId"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"publicKeyPem"`
	}
	out := struct {
		Keys []key `json:"keys"`
	}{Keys: []key{}}
	if !r.noKeys {
		out.Keys = append(out.Keys, key{
			KeyID: r.signer.KeyID(), Algorithm: "ecdsa-p256-sha256",
			PublicKey: r.signer.PublicKeyPEM(),
		})
	}
	writeTestJSON(w, out)
}

func (r *testRegistry) serveResolve(w http.ResponseWriter, _ *http.Request) {
	att := "/fixtures/attestation.json"
	body := map[string]any{
		"namespace":  r.ns,
		"name":       r.name,
		"version":    r.ver,
		"digest":     r.digest,
		"archiveUrl": "/fixtures/archive.tar.zst",
		"manifest":   r.manifestJSON,
		"yanked":     false,
	}
	if r.signed {
		body["attestationUrl"] = att
	}
	writeTestJSON(w, body)
}

func (r *testRegistry) serveArchive(w http.ResponseWriter, _ *http.Request) {
	r.archiveHits++
	body := r.archive
	if r.tamper {
		// Flip a byte in the compressed stream: the digest check must catch
		// this before the signature check ever runs.
		body = append([]byte(nil), r.archive...)
		body[len(body)/2] ^= 0xff
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(body)
}

func (r *testRegistry) serveAttestation(w http.ResponseWriter, _ *http.Request) {
	if !r.signed {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	stmt := scan.BuildStatement(r.srv.URL, r.ns+"/"+r.name, r.ver, r.digest, "", "upload",
		scan.ScanRunRef{RulesetVer: "1.0.0", ReportDigest: "sha256:deadbeef", JudgeModel: "none"}, 1)
	env, err := r.signer.Sign(stmt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeTestJSON(w, env)
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// buildFixtureArchive makes a tar.zst holding one SKILL.md, the shape
// scan.Extract expects.
func buildFixtureArchive(t *testing.T, files map[string]string) ([]byte, string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var raw bytes.Buffer
	tw := newTarWriter(&raw)
	for name, content := range files {
		tw.add(t, name, content)
	}
	tw.close(t)

	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := out.Bytes()
	return data, sha256Digest(data)
}

// fixtureManifest is the canonical manifest JSON a resolve result carries.
//
//nolint:unparam // ns is part of the fixture's address; every test uses "acme"
func fixtureManifest(ns, name string, caps map[string]any) map[string]any {
	m := map[string]any{
		"schemaVersion": "1",
		"name":          name,
		"namespace":     ns,
		"kind":          "skill",
		"version":       "1.0.0",
		"summary":       "A fixture skill",
		"entrypoints":   map[string]any{"skill": "SKILL.md"},
	}
	if caps != nil {
		m["capabilities"] = caps
	}
	return m
}

// runCLI executes the command tree with isolated config/state directories.
func runCLI(t *testing.T, home string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("AGENTRY_CONFIG_DIR", filepath.Join(home, "config"))
	t.Setenv("AGENTRY_NO_KEYRING", "1")
	t.Setenv("AGENTRY_TOKEN", "")

	root := newRootCmd()
	var so, se bytes.Buffer
	root.SetOut(&so)
	root.SetErr(&se)
	root.SetIn(strings.NewReader("")) // never a TTY: prompts must refuse
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return so.String(), se.String(), err
}

// ------------------------------------------------------------ install e2e

const fixtureSkill = "---\nname: helper\n---\n\n# Helper\n\nDoes one thing.\n"

func TestInstallVerifiesSignature(t *testing.T) {
	archive, digest := buildFixtureArchive(t, map[string]string{"SKILL.md": fixtureSkill})
	reg := newTestRegistry(t, &testRegistry{
		archive: archive, digest: digest, signed: true,
		manifestJSON: fixtureManifest("acme", "helper", nil),
	})
	home := t.TempDir()
	dest := filepath.Join(home, "skills")

	stdout, _, err := runCLI(t, home, "install", "acme/helper",
		"--registry", reg.url(), "--target", "claude-skill", "--dir", dest, "--yes")
	if err != nil {
		t.Fatalf("signed install failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "attestation:   verified") {
		t.Errorf("install did not report a verified attestation:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(dest, "helper", "SKILL.md")); err != nil {
		t.Fatalf("skill not installed: %v", err)
	}

	// The signing keys were pinned on first use, and the install manifest
	// recorded what was accepted.
	pinned := filepath.Join(home, "config", "keys")
	if entries, rerr := os.ReadDir(pinned); rerr != nil || len(entries) == 0 {
		t.Errorf("signing keys were not pinned in %s (%v)", pinned, rerr)
	}
	state, err := loadInstallState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Records) != 1 || state.Records[0].Version != "1.0.0" {
		t.Fatalf("install state = %+v, want one 1.0.0 record", state.Records)
	}
}

func TestInstallAbortsOnTamperedArchive(t *testing.T) {
	archive, digest := buildFixtureArchive(t, map[string]string{"SKILL.md": fixtureSkill})
	reg := newTestRegistry(t, &testRegistry{
		archive: archive, digest: digest, signed: true, tamper: true,
		manifestJSON: fixtureManifest("acme", "helper", nil),
	})
	home := t.TempDir()
	dest := filepath.Join(home, "skills")

	_, _, err := runCLI(t, home, "install", "acme/helper",
		"--registry", reg.url(), "--target", "claude-skill", "--dir", dest, "--yes")
	if err == nil {
		t.Fatal("install accepted a tampered archive")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("error = %v, want a digest mismatch", err)
	}
	if _, serr := os.Stat(filepath.Join(dest, "helper")); serr == nil {
		t.Error("a refused install still wrote files")
	}
}

// TestInstallAbortsOnBadSignature: the archive matches its advertised digest,
// but the attestation was signed by a key this machine has pinned against.
func TestInstallAbortsOnBadSignature(t *testing.T) {
	archive, digest := buildFixtureArchive(t, map[string]string{"SKILL.md": fixtureSkill})
	reg := newTestRegistry(t, &testRegistry{
		archive: archive, digest: digest, signed: true,
		manifestJSON: fixtureManifest("acme", "helper", nil),
	})
	home := t.TempDir()
	dest := filepath.Join(home, "skills")

	// Pin a DIFFERENT key first, as a previous honest session would have.
	t.Setenv("AGENTRY_CONFIG_DIR", filepath.Join(home, "config"))
	other, err := scan.NewFileSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	if perr := savePinnedKeys(reg.url(), signingKeySet{Keys: []signingKey{{
		KeyID: other.KeyID(), Algorithm: "ecdsa-p256-sha256", PublicKey: other.PublicKeyPEM(),
	}}}); perr != nil {
		t.Fatal(perr)
	}

	_, _, err = runCLI(t, home, "install", "acme/helper",
		"--registry", reg.url(), "--target", "claude-skill", "--dir", dest, "--yes")
	if err == nil {
		t.Fatal("install accepted an attestation no pinned key verifies")
	}
	if !strings.Contains(err.Error(), "attestation") {
		t.Errorf("error = %v, want an attestation failure", err)
	}
	if _, serr := os.Stat(filepath.Join(dest, "helper")); serr == nil {
		t.Error("a refused install still wrote files")
	}
}

func TestInstallUnsignedNeedsFlag(t *testing.T) {
	archive, digest := buildFixtureArchive(t, map[string]string{"SKILL.md": fixtureSkill})
	reg := newTestRegistry(t, &testRegistry{
		archive: archive, digest: digest, signed: false,
		manifestJSON: fixtureManifest("acme", "helper", nil),
	})
	home := t.TempDir()
	dest := filepath.Join(home, "skills")

	_, _, err := runCLI(t, home, "install", "acme/helper",
		"--registry", reg.url(), "--target", "claude-skill", "--dir", dest, "--yes")
	if err == nil {
		t.Fatal("unsigned install proceeded without --allow-unsigned")
	}
	if !strings.Contains(err.Error(), "unsigned — registry offers no attestation") {
		t.Errorf("error = %v, want the unsigned refusal", err)
	}

	// With the flag it installs, and says plainly what it did.
	home2 := t.TempDir()
	dest2 := filepath.Join(home2, "skills")
	_, stderr, err := runCLI(t, home2, "install", "acme/helper",
		"--registry", reg.url(), "--target", "claude-skill", "--dir", dest2, "--yes", "--allow-unsigned")
	if err != nil {
		t.Fatalf("--allow-unsigned install failed: %v", err)
	}
	if !strings.Contains(stderr, "unsigned") {
		t.Errorf("stderr did not warn about the unsigned install:\n%s", stderr)
	}
	if _, serr := os.Stat(filepath.Join(dest2, "helper", "SKILL.md")); serr != nil {
		t.Fatalf("skill not installed: %v", serr)
	}
}

// TestInstallTargetValidatedBeforeDownload: a bad --target must cost nothing.
func TestInstallTargetValidatedBeforeDownload(t *testing.T) {
	archive, digest := buildFixtureArchive(t, map[string]string{"SKILL.md": fixtureSkill})
	reg := newTestRegistry(t, &testRegistry{
		archive: archive, digest: digest, signed: true,
		manifestJSON: fixtureManifest("acme", "helper", nil),
	})

	home := t.TempDir()
	_, _, err := runCLI(t, home, "install", "acme/helper",
		"--registry", reg.url(), "--target", "clod-skill", "--dir", filepath.Join(home, "x"))
	if err == nil {
		t.Fatal("install accepted an unknown --target")
	}
	if !strings.Contains(err.Error(), "unknown --target") {
		t.Errorf("error = %v, want an unknown-target message", err)
	}
	if reg.archiveHits != 0 {
		t.Errorf("a rejected --target still downloaded the archive %d time(s)", reg.archiveHits)
	}
}

// --------------------------------------------------------- capability diff

// The registry URL changes per fixture server, and the install key includes
// it, so capability-diff tests share ONE registry across both installs.
func installTwice(t *testing.T, first, second map[string]any, secondArgs ...string) (string, error) {
	t.Helper()
	archive, digest := buildFixtureArchive(t, map[string]string{"SKILL.md": fixtureSkill})
	reg := newTestRegistry(t, &testRegistry{
		archive: archive, digest: digest, signed: true,
		manifestJSON: fixtureManifest("acme", "helper", first),
	})
	home := t.TempDir()
	dest := filepath.Join(home, "skills")

	if _, _, err := runCLI(t, home, "install", "acme/helper", "--registry", reg.url(),
		"--target", "claude-skill", "--dir", dest, "--yes"); err != nil {
		t.Fatalf("first install: %v", err)
	}

	reg.manifestJSON = fixtureManifest("acme", "helper", second)
	args := append([]string{"install", "acme/helper", "--registry", reg.url(),
		"--target", "claude-skill", "--dir", dest}, secondArgs...)
	stdout, _, err := runCLI(t, home, args...)
	return stdout, err
}

func TestCapabilityDiffWidenedPrompts(t *testing.T) {
	stdout, err := installTwice(t,
		map[string]any{"network": map[string]any{"egress": "none"}},
		map[string]any{"network": map[string]any{"egress": []string{"evil.example"}}},
	)
	// stdin is not a TTY in tests, so a required confirmation must refuse.
	if err == nil {
		t.Fatalf("a widened capability contract installed without confirmation:\n%s", stdout)
	}
	if !strings.Contains(stdout, "WIDENED") ||
		!strings.Contains(stdout, "adds network egress to evil.example") {
		t.Errorf("diff did not name the new egress host as §11 promises:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("refusal did not mention the CI escape hatch: %v", err)
	}
}

func TestCapabilityDiffWidenedProceedsWithYes(t *testing.T) {
	stdout, err := installTwice(t,
		map[string]any{"network": map[string]any{"egress": "none"}},
		map[string]any{"network": map[string]any{"egress": []string{"evil.example"}}},
		"--yes",
	)
	if err != nil {
		t.Fatalf("--yes did not accept the widened contract: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "WIDENED") {
		t.Errorf("the widening was not shown even though it was accepted:\n%s", stdout)
	}
}

func TestCapabilityDiffUnchangedDoesNotPrompt(t *testing.T) {
	caps := map[string]any{"network": map[string]any{"egress": []string{"api.example"}}}
	stdout, err := installTwice(t, caps, caps)
	// No --yes on the second run: an unchanged contract must not re-ask, even
	// though the contract itself declares egress.
	if err != nil {
		t.Fatalf("an unchanged contract prompted again: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "unchanged") {
		t.Errorf("diff did not report 'unchanged':\n%s", stdout)
	}
}

func TestCapabilityDiffNarrowedNotesAndProceeds(t *testing.T) {
	stdout, err := installTwice(t,
		map[string]any{"network": map[string]any{"egress": []string{"api.example", "cdn.example"}}},
		map[string]any{"network": map[string]any{"egress": []string{"api.example"}}},
	)
	if err != nil {
		t.Fatalf("a narrowed contract prompted: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "narrowed") ||
		!strings.Contains(stdout, "drops network egress to cdn.example") {
		t.Errorf("diff did not report the narrowing:\n%s", stdout)
	}
}

// ------------------------------------------------------- rules-update e2e

func TestValidateRulesUpdate(t *testing.T) {
	reg := newTestRegistry(t, &testRegistry{})
	home := t.TempDir()
	ws := writeValidWorkspace(t)

	stdout, stderr, err := runCLI(t, home, "validate", ws, "--rules-update", "--registry", reg.url())
	if err != nil {
		t.Fatalf("validate --rules-update: %v\n%s\n%s", err, stdout, stderr)
	}
	if !strings.Contains(stderr, "rules: cached bundle") {
		t.Fatalf("no cache confirmation:\n%s", stderr)
	}
	// The deferral is stated, not silent (DEV-024).
	if !strings.Contains(stderr, "DEV-024") {
		t.Errorf("the signing deferral was not surfaced:\n%s", stderr)
	}

	// The cache holds a loadable bundle whose digest equals the embedded one
	// (this registry serves its own embedded bundle).
	embedded, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(home, "config", "rules", embedded.Version())
	cached, err := rules.LoadBundle(os.DirFS(cacheDir), ".")
	if err != nil {
		t.Fatalf("cached bundle does not load from %s: %v", cacheDir, err)
	}
	if cached.Digest() != embedded.Digest() {
		t.Fatalf("cached digest %s != served %s", cached.Digest(), embedded.Digest())
	}

	// A subsequent validate prefers the cached bundle over the embedded one.
	stdout, _, err = runCLI(t, home, "validate", ws)
	if err != nil {
		t.Fatalf("validate after caching: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "cached via --rules-update") {
		t.Errorf("validate did not prefer the cached bundle:\n%s", stdout)
	}
}

// TestValidateRulesUpdateRejectsBadDigest: a registry whose advertised digest
// does not match the bytes it served is refused, and nothing is cached.
func TestValidateRulesUpdateRejectsBadDigest(t *testing.T) {
	mux := http.NewServeMux()
	bundle, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	data, err := bundle.Tar()
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("GET /api/v1/ruleset-releases/latest/bundle", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Agentry-Bundle-Semver", bundle.Version())
		w.Header().Set("X-Agentry-Bundle-Digest", "sha256:"+strings.Repeat("00", 32))
		w.Header().Set("Content-Type", "application/x-tar")
		_, _ = w.Write(data)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	home := t.TempDir()
	ws := writeValidWorkspace(t)
	_, _, err = runCLI(t, home, "validate", ws, "--rules-update", "--registry", srv.URL)
	if err == nil {
		t.Fatal("a digest mismatch was accepted")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("error = %v, want a digest mismatch", err)
	}
	if _, serr := os.Stat(filepath.Join(home, "config", "rules")); serr == nil {
		t.Error("a refused bundle was still cached")
	}
}

// writeValidWorkspace builds a minimal workspace `validate` passes on.
func writeValidWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("agent.yaml", `schemaVersion: "1"
name: helper
namespace: acme
kind: skill
version: 1.0.0
summary: A fixture skill for validate tests
license: MIT
entrypoints:
  skill: SKILL.md
publish:
  include:
    - agent.yaml
    - SKILL.md
    - README.md
    - LICENSE
`)
	write("README.md", "# Helper\n\nA fixture skill.\n")
	write("LICENSE", "MIT License\n\nCopyright (c) 2026\n")
	write("SKILL.md", fixtureSkill)
	return dir
}
