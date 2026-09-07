// Package archive is the public release-archive toolkit: the deterministic
// tar.zst builder that gives every release its content-addressed identity
// (D-15, §6.5), the hardened extractor for untrusted archives (§8.2), the
// trusted unpacker clients use on registry-built archives, and the content
// sniffers behind the S1 inventory and `agentry validate` parity (D-12).
// The server and the CLI both build on this package, which is what makes
// "the CLI runs the same checks the server runs" true by construction.
package archive

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

	"github.com/blaktron/agentry/pkg/manifest"
)

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
			return fmt.Errorf("archive: unsupported file type at %s", rel)
		}
		files = append(files, manifest.FileInfo{Path: rel, Size: info.Size(), IsText: looksTextFile(path, rel)})
		return nil
	})
	return files, err
}

// BuildArchive writes the deterministic tar.zst of the include-filtered
// workspace to w and returns its identity: sorted entries, zeroed mtimes,
// normalized modes, fixed uid/gid (D-15). Callers MUST have validated the
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
		return ArchiveInfo{}, fmt.Errorf("archive: zstd: %w", err)
	}
	tw := tar.NewWriter(zw)

	for _, f := range include {
		if f.Symlink {
			return ArchiveInfo{}, fmt.Errorf("archive: symlink %s in include set (V4 violation)", f.Path)
		}
		if strings.HasPrefix(f.Path, "/") || strings.Contains(f.Path, "..") {
			return ArchiveInfo{}, fmt.Errorf("archive: unsafe path %s", f.Path)
		}
		full := filepath.Join(root, filepath.FromSlash(f.Path))
		info, err := os.Lstat(full)
		if err != nil {
			return ArchiveInfo{}, fmt.Errorf("archive: stat %s: %w", f.Path, err)
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
			return ArchiveInfo{}, fmt.Errorf("archive: tar header %s: %w", f.Path, err)
		}
		src, err := os.Open(full) //nolint:gosec // path constrained to workspace above
		if err != nil {
			return ArchiveInfo{}, err
		}
		if _, err := io.Copy(tw, src); err != nil {
			_ = src.Close()
			return ArchiveInfo{}, fmt.Errorf("archive: tar body %s: %w", f.Path, err)
		}
		_ = src.Close()
	}
	if err := tw.Close(); err != nil {
		return ArchiveInfo{}, fmt.Errorf("archive: tar close: %w", err)
	}
	if err := zw.Close(); err != nil {
		return ArchiveInfo{}, fmt.Errorf("archive: zstd close: %w", err)
	}

	return ArchiveInfo{
		Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		Size:   counter.n,
		Files:  include,
	}, nil
}

// Unpack extracts a tar.zst release archive into dst with basic hardening:
// path traversal, absolute paths, links, and non-regular entries rejected;
// per-file and total size caps enforced.
//
// Unpack is for archives the registry itself built and signed — the client
// side of an install, after digest and signature verification. For UNTRUSTED
// input use Extract, which adds the file-count cap, the compression-ratio
// check, and the decoder memory bound (§8.2).
func Unpack(r io.Reader, dst string, maxFile, maxTotal int64) error {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return fmt.Errorf("archive: zstd reader: %w", err)
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
			return fmt.Errorf("archive: tar read: %w", err)
		}
		name := filepath.ToSlash(hdr.Name)
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return fmt.Errorf("archive: path traversal: %s", name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue // directories are implied by file paths
		case tar.TypeReg:
		default:
			return fmt.Errorf("archive: non-regular entry %s (type %d)", name, hdr.Typeflag)
		}
		if hdr.Size > maxFile {
			return fmt.Errorf("archive: file %s exceeds per-file limit", name)
		}
		total += hdr.Size
		if total > maxTotal {
			return fmt.Errorf("archive: exceeds total size limit")
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
			return fmt.Errorf("archive: extract %s: %w", name, err)
		}
		_ = out.Close()
	}
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// looksTextFile applies S1's sniff to a file on disk: an image by
// extension is not text; otherwise the first bytes decide (LooksText). A
// file that cannot be read counts as not text — V8's total is a cap, and
// an unreadable file fails elsewhere.
func looksTextFile(path, rel string) bool {
	if IsImagePath(rel) {
		return false
	}
	f, err := os.Open(path) //nolint:gosec // walking the caller's workspace
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 512)
	n, err := f.Read(head)
	if err != nil && n == 0 {
		return false
	}
	return LooksText(head[:n])
}
