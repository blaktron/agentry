package gitsrv

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// archiveArgs are the `git` arguments that make `git archive` ignore every
// gitattributes source, so a pushed `export-ignore` cannot drop files from a
// release (§6.5: the manifest allowlist is the only filter).
//
// `git archive` deliberately reads attributes from the tree it is archiving
// (it unpacks that tree into an in-memory index and points the attribute
// stack at it), which is why neither `core.attributesFile` nor `attr.tree` /
// `--attr-source` displaces an in-tree `.gitattributes` — verified against
// git 2.50 and consistent with git's documented archive behaviour. Only
// `--worktree-attributes` moves the lookup off the archived tree, onto the
// working tree, which a bare repo does not have: the result is no in-tree
// attributes at all. The remaining sources are handled alongside:
//
//	core.attributesFile=/dev/null  global attributes file
//	GIT_ATTR_NOSYSTEM=1            system attributes file (archiveEnv)
//	$GIT_DIR/info/attributes       refused outright (checkNoInfoAttributes)
//
// verifyArchiveNeutralizesAttributes pins the property at startup, and every
// archive is checked against the tree it came from (verifyArchiveComplete),
// so a future git that changes this fails loudly instead of silently
// shipping a filtered tree.
var archiveArgs = []string{
	"-c", "core.attributesFile=/dev/null",
	"archive", "--worktree-attributes", "--format=tar",
}

// archiveEnv is the environment for archive invocations.
func archiveEnv() []string { return append(os.Environ(), "GIT_ATTR_NOSYSTEM=1") }

// ArchiveTag implements the tar half of §6.5 step 1: `git archive {tag}` from
// the bare repo — never a working-tree checkout, no hook execution, no
// gitattributes filtering. The tar is streamed to a temp file (a release tree
// may be as large as the repo quota; buffering it in RAM would let a push
// size the server's heap) and the returned ReadCloser removes that file on
// Close. The second return value is the peeled commit id.
func (s *RepoStore) ArchiveTag(ctx context.Context, repoID uuid.UUID, tag string) (io.ReadCloser, string, error) {
	dir := s.Path(repoID)
	if err := checkNoInfoAttributes(dir); err != nil {
		return nil, "", err
	}

	// Resolve the commit the tag points at (annotated tags peel).
	rev := exec.CommandContext(ctx, s.gitBin, "-C", dir, "rev-list", "-n1", tag)
	revOut, err := rev.Output()
	if err != nil {
		return nil, "", fmt.Errorf("gitsrv: tag %s not found: %w", tag, err)
	}
	commit := strings.TrimSpace(string(revOut))

	f, err := os.CreateTemp("", "agentry-archive-*.tar")
	if err != nil {
		return nil, "", fmt.Errorf("gitsrv: archive temp file: %w", err)
	}
	tmp := &tempFile{File: f}
	defer func() {
		if err != nil {
			_ = tmp.Close()
		}
	}()

	args := append([]string{"-C", dir}, archiveArgs...)
	cmd := exec.CommandContext(ctx, s.gitBin, append(args, tag)...) //nolint:gosec // fixed binary; tag resolved above
	cmd.Env = archiveEnv()
	var stderr strings.Builder
	cmd.Stdout, cmd.Stderr = f, &stderr
	if err = cmd.Run(); err != nil {
		return nil, "", fmt.Errorf("gitsrv: git archive %s: %v: %s", tag, err, stderr.String())
	}
	if err = s.verifyArchiveComplete(ctx, dir, commit, f); err != nil {
		return nil, "", err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, "", fmt.Errorf("gitsrv: archive rewind: %w", err)
	}
	return tmp, commit, nil
}

// tempFile deletes its backing file when the reader is closed.
type tempFile struct{ *os.File }

func (t *tempFile) Close() error {
	name := t.Name()
	err := t.File.Close()
	_ = os.Remove(name)
	return err
}

// checkNoInfoAttributes fails closed when $GIT_DIR/info/attributes exists.
// git offers no way to disable that source, and nothing in agentry writes it
// (the file is unreachable over the git wire protocol), so its presence means
// an operator placed attribute rules under the release path — rules that
// could silently filter the archive §6.5 says only the manifest may filter.
func checkNoInfoAttributes(dir string) error {
	p := filepath.Join(dir, "info", "attributes")
	st, err := os.Stat(p)
	if err != nil || st.Size() == 0 {
		return nil
	}
	return fmt.Errorf("gitsrv: %s exists; release archives must not be filtered by gitattributes (§6.5) — remove it", p)
}

// verifyArchiveComplete asserts the tar holds every blob of the archived
// commit: the §6.5 invariant ("the manifest allowlist is the only filter")
// checked against the tree itself rather than trusted from git's flags.
// Submodules are excluded — git archive never descends into a gitlink.
func (s *RepoStore) verifyArchiveComplete(ctx context.Context, dir, commit string, tarFile *os.File) error {
	want, err := s.treeBlobs(ctx, dir, commit)
	if err != nil {
		return err
	}
	if _, err := tarFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("gitsrv: archive rewind: %w", err)
	}
	tr := tar.NewReader(tarFile)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("gitsrv: archive read back: %w", err)
		}
		delete(want, strings.TrimSuffix(filepath.ToSlash(hdr.Name), "/"))
	}
	if len(want) == 0 {
		return nil
	}
	missing := make([]string, 0, len(want))
	for p := range want {
		missing = append(missing, p)
	}
	sort.Strings(missing)
	if len(missing) > 5 {
		missing = append(missing[:5], "…")
	}
	return fmt.Errorf("gitsrv: git archive dropped %d path(s) of %s (%s): gitattributes filtering is not neutralized (§6.5)",
		len(want), commit, strings.Join(missing, ", "))
}

// treeBlobs lists every blob path of a commit's tree.
func (s *RepoStore) treeBlobs(ctx context.Context, dir, commit string) (map[string]struct{}, error) {
	cmd := exec.CommandContext(ctx, s.gitBin, "-C", dir, "ls-tree", "-r", "-z", commit) //nolint:gosec // fixed binary; commit is a resolved oid
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gitsrv: ls-tree %s: %w", commit, err)
	}
	blobs := make(map[string]struct{})
	for _, entry := range strings.Split(string(out), "\x00") {
		// <mode> SP <type> SP <oid> TAB <path>
		tab := strings.IndexByte(entry, '\t')
		if tab < 0 {
			continue
		}
		if fields := strings.Fields(entry[:tab]); len(fields) < 2 || fields[1] != "blob" {
			continue
		}
		blobs[entry[tab+1:]] = struct{}{}
	}
	return blobs, nil
}

// archiveSelfTest caches the startup probe per git binary.
var archiveSelfTest sync.Map // gitBin → error

// verifyArchiveNeutralizesAttributes proves, against the git binary actually
// installed, that archiveArgs defeat `export-ignore`. It builds a throwaway
// bare repo whose tree marks a file export-ignore and asserts the file still
// lands in the tar. Called from NewRepoStore so an unsupported git stops the
// process at startup instead of silently shipping filtered releases (§6.5).
func verifyArchiveNeutralizesAttributes(gitBin string) error {
	if cached, ok := archiveSelfTest.Load(gitBin); ok {
		err, _ := cached.(error) // stored as a nil interface on success
		return err
	}
	err := probeArchiveAttributes(gitBin)
	archiveSelfTest.Store(gitBin, err)
	return err
}

func probeArchiveAttributes(gitBin string) error {
	dir, err := os.MkdirTemp("", "agentry-gitprobe-")
	if err != nil {
		return fmt.Errorf("gitsrv: archive self-test: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	repo := filepath.Join(dir, "probe.git")
	run := func(stdin string, args ...string) (string, error) {
		cmd := exec.Command(gitBin, args...) //nolint:gosec // fixed binary, fixed args
		cmd.Env = append(archiveEnv(),
			"GIT_AUTHOR_NAME=agentry", "GIT_AUTHOR_EMAIL=agentry@localhost",
			"GIT_COMMITTER_NAME=agentry", "GIT_COMMITTER_EMAIL=agentry@localhost",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	hash := func(content string) (string, error) {
		return run(content, "-C", repo, "hash-object", "-w", "--stdin")
	}
	if _, err := run("", "init", "--bare", "-q", repo); err != nil {
		return fmt.Errorf("gitsrv: archive self-test: git init: %w", err)
	}
	attrs, err := hash("kept.txt export-ignore\n")
	if err != nil {
		return fmt.Errorf("gitsrv: archive self-test: hash-object: %w", err)
	}
	kept, err := hash("kept\n")
	if err != nil {
		return fmt.Errorf("gitsrv: archive self-test: hash-object: %w", err)
	}
	tree, err := run(
		fmt.Sprintf("100644 blob %s\t.gitattributes\n100644 blob %s\tkept.txt\n", attrs, kept),
		"-C", repo, "mktree")
	if err != nil {
		return fmt.Errorf("gitsrv: archive self-test: mktree: %w", err)
	}
	commit, err := run("probe\n", "-C", repo, "commit-tree", tree)
	if err != nil {
		return fmt.Errorf("gitsrv: archive self-test: commit-tree: %w", err)
	}

	cmd := exec.Command(gitBin, append(append([]string{"-C", repo}, archiveArgs...), commit)...) //nolint:gosec // fixed binary, fixed args
	cmd.Env = archiveEnv()
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("gitsrv: archive self-test: git archive: %w", err)
	}
	tr := tar.NewReader(bytes.NewReader(out))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("gitsrv: archive self-test: tar read: %w", err)
		}
		if hdr.Name == "kept.txt" {
			return nil
		}
	}
	version, _ := run("", "--version")
	return fmt.Errorf("gitsrv: %s honours export-ignore in `git archive` (%s); §6.5 requires release archives to be filtered by the manifest allowlist only — refusing to start",
		gitBin, version)
}

// MaterializeTag implements registry.GitArchiver: extracts `git archive
// {tag}` into dst (plain tar, produced by our own git — still extracted
// defensively) and returns the peeled commit id.
func (s *RepoStore) MaterializeTag(ctx context.Context, repoID uuid.UUID, tag, dst string) (commitSHA string, err error) {
	stream, commit, err := s.ArchiveTag(ctx, repoID, tag)
	if err != nil {
		return "", err
	}
	defer func() { _ = stream.Close() }()
	if err := extractPlainTar(stream, dst); err != nil {
		return "", err
	}
	return commit, nil
}

// extractPlainTar unpacks an uncompressed tar defensively: no traversal, no
// links or devices, directories and regular files only.
func extractPlainTar(r io.Reader, dst string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("gitsrv: tar read: %w", err)
		}
		name := filepath.ToSlash(hdr.Name)
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return fmt.Errorf("gitsrv: tar path traversal: %s", name)
		}
		full := filepath.Join(dst, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(full, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644) //nolint:gosec // traversal rejected above
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil { //nolint:gosec // git-produced tar, size-bounded by repo quota
				_ = out.Close()
				return err
			}
			_ = out.Close()
		case tar.TypeXGlobalHeader:
			// git archive emits a pax global header with the commit id.
		default:
			return fmt.Errorf("gitsrv: unsupported tar entry %s (type %d)", name, hdr.Typeflag)
		}
	}
}
