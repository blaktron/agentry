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
	"strings"

	"github.com/google/uuid"
)

// ArchiveTag implements registry.GitArchiver (§6.5 step 1): `git archive
// {tag}` from the bare repo — never a working-tree checkout, no hook
// execution, export-ignore attributes disabled so the manifest allowlist is
// the only filter.
func (s *RepoStore) ArchiveTag(ctx context.Context, repoID uuid.UUID, tag string) (io.ReadCloser, string, error) {
	dir := s.Path(repoID)

	// Resolve the commit the tag points at (annotated tags peel).
	rev := exec.CommandContext(ctx, s.gitBin, "-C", dir, "rev-list", "-n1", tag)
	revOut, err := rev.Output()
	if err != nil {
		return nil, "", fmt.Errorf("gitsrv: tag %s not found: %w", tag, err)
	}
	commit := strings.TrimSpace(string(revOut))

	cmd := exec.CommandContext(ctx, s.gitBin, "-C", dir,
		"-c", "core.attributesFile=/dev/null", // export-ignore is ignored (§6.5)
		"archive", "--format=tar", tag)
	var buf bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &stderr
	if err := cmd.Run(); err != nil {
		return nil, "", fmt.Errorf("gitsrv: git archive %s: %v: %s", tag, err, stderr.String())
	}
	return io.NopCloser(&buf), commit, nil
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
