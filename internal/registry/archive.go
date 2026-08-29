package registry

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/PLACEHOLDER_ORG/agentry/pkg/manifest"
)

// Deterministic release archives (D-15): sorted entries, zeroed mtimes,
// normalized modes, fixed uid/gid, tar + zstd. The sha256 of the compressed
// stream is the release identity (§6.5).

// ArchiveInfo describes a built archive.
type ArchiveInfo struct {
	Digest string // "sha256:<hex>"
	Size   int64
	Files  []manifest.FileInfo
}

// WalkWorkspace lists regular files (and flags symlinks) under root as
// repo-relative FileInfos for validation and archiving.
func WalkWorkspace(root string) ([]manifest.FileInfo, error) {
	var files []manifest.FileInfo
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		// .git dirs never participate (bare workspaces shouldn't have one,
		// but uploaded archives might try).
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			files = append(files, manifest.FileInfo{Path: rel, Symlink: true})
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("registry: unsupported file type at %s", rel)
		}
		files = append(files, manifest.FileInfo{Path: rel, Size: info.Size()})
		return nil
	})
	return files, err
}

// BuildArchive writes the deterministic tar.zst of the include-filtered
// workspace to w and returns its identity. Callers MUST have validated the
// manifest (V4) against the same file list first.
func BuildArchive(root string, include []manifest.FileInfo, w io.Writer) (ArchiveInfo, error) {
	hasher := sha256.New()
	counter := &countingWriter{}
	mw := io.MultiWriter(w, hasher, counter)

	zw, err := zstd.NewWriter(mw,
		zstd.WithEncoderLevel(zstd.SpeedBetterCompression),
		// Determinism: single-threaded encoding keeps frame layout stable.
		zstd.WithEncoderConcurrency(1))
	if err != nil {
		return ArchiveInfo{}, fmt.Errorf("registry: zstd: %w", err)
	}
	tw := tar.NewWriter(zw)

	for _, f := range include {
		if f.Symlink {
			return ArchiveInfo{}, fmt.Errorf("registry: symlink %s in include set (V4 violation)", f.Path)
		}
		if strings.HasPrefix(f.Path, "/") || strings.Contains(f.Path, "..") {
			return ArchiveInfo{}, fmt.Errorf("registry: unsafe path %s", f.Path)
		}
		full := filepath.Join(root, filepath.FromSlash(f.Path))
		info, err := os.Lstat(full)
		if err != nil {
			return ArchiveInfo{}, fmt.Errorf("registry: stat %s: %w", f.Path, err)
		}
		mode := int64(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		hdr := &tar.Header{
			Name:     f.Path,
			Mode:     mode,
			Size:     info.Size(),
			Typeflag: tar.TypeReg,
			Uname:    "", Gname: "",
			Uid: 0, Gid: 0,
			// ModTime deliberately zero (D-15).
			Format: tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return ArchiveInfo{}, fmt.Errorf("registry: tar header %s: %w", f.Path, err)
		}
		src, err := os.Open(full) //nolint:gosec // path constrained to workspace above
		if err != nil {
			return ArchiveInfo{}, err
		}
		if _, err := io.Copy(tw, src); err != nil {
			_ = src.Close()
			return ArchiveInfo{}, fmt.Errorf("registry: tar body %s: %w", f.Path, err)
		}
		_ = src.Close()
	}
	if err := tw.Close(); err != nil {
		return ArchiveInfo{}, fmt.Errorf("registry: tar close: %w", err)
	}
	if err := zw.Close(); err != nil {
		return ArchiveInfo{}, fmt.Errorf("registry: zstd close: %w", err)
	}

	return ArchiveInfo{
		Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		Size:   counter.n,
		Files:  include,
	}, nil
}

// ExtractArchive unpacks a tar.zst release archive into dst with hardening:
// path traversal, absolute paths, links, and non-regular entries rejected;
// per-file and total size caps enforced.
//
// For UNTRUSTED input use scan.Extract instead — it adds the file-count cap,
// the compression-ratio check and the decoder memory bound, and is the single
// shared unpacker §8.2 calls for. Every server-side path that touches an
// uploaded archive now goes through it. What is left here is the client side
// (`agentry install`, unpacking an archive the registry itself built and
// signed) and the gitsrv end-to-end test.
func ExtractArchive(r io.Reader, dst string, maxFile, maxTotal int64) error {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return fmt.Errorf("registry: zstd reader: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("registry: tar read: %w", err)
		}
		name := filepath.ToSlash(hdr.Name)
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return fmt.Errorf("registry: archive path traversal: %s", name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue // directories are implied by file paths
		case tar.TypeReg:
		default:
			return fmt.Errorf("registry: archive contains non-regular entry %s (type %d)", name, hdr.Typeflag)
		}
		if hdr.Size > maxFile {
			return fmt.Errorf("registry: archive file %s exceeds per-file limit", name)
		}
		total += hdr.Size
		if total > maxTotal {
			return fmt.Errorf("registry: archive exceeds total size limit")
		}
		full := filepath.Join(dst, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644) //nolint:gosec // traversal rejected above
		if err != nil {
			return err
		}
		if _, err := io.CopyN(out, tr, hdr.Size); err != nil && err != io.EOF {
			_ = out.Close()
			return fmt.Errorf("registry: extract %s: %w", name, err)
		}
		_ = out.Close()
	}
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
