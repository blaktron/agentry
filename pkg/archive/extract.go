package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/blaktron/agentry/pkg/manifest"
)

// The hardened archive extractor: the single shared unpacker for
// untrusted release archives. It rejects path traversal, absolute paths,
// symlinks/hardlinks, device nodes, and any non-regular entry; enforces
// per-file, total-size, and file-count caps; and bounds the compression
// ratio to defuse zip bombs. Fuzzed in extract_test.go.

// ExtractLimits bounds a safe extraction (the release-archive quotas plus a decompression cap).
type ExtractLimits struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFiles      int
	// MaxRatio caps decompressed/compressed; 0 disables the check.
	MaxRatio int64
}

// DefaultLimits are the release-archive quotas, raised by the most a
// release may ship in knowledge packs: the extractor bounds what any
// archive can unpack to, and the manifest's V8 holds each release to its
// own quotas and each pack to a pack's.
func DefaultLimits() ExtractLimits {
	const packs = manifest.MaxShippedPacks
	return ExtractLimits{
		MaxFileBytes:  manifest.MaxKnowledgePackBytes,                // images up to 5 MB; a pack's source up to its pack's 10 MB
		MaxTotalBytes: 10<<20 + packs*manifest.MaxKnowledgePackBytes, // 10 MB post-filter, and five packs
		MaxFiles:      2000 + packs*manifest.MaxKnowledgePackFiles,
		MaxRatio:      200,
	}
}

// ErrArchiveViolation marks a rejected archive (structural attack).
var ErrArchiveViolation = errors.New("archive: violation")

// Extract unpacks a tar.zst archive from r into dst with full hardening.
// compressedSize (bytes) enables the ratio check; pass 0 to skip it.
func Extract(r io.Reader, dst string, compressedSize int64, lim ExtractLimits) error {
	zr, err := zstd.NewReader(r, zstd.WithDecoderMaxMemory(64<<20))
	if err != nil {
		return fmt.Errorf("archive: zstd reader: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	var total int64
	var count int
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: tar read: %v", ErrArchiveViolation, err)
		}

		name := filepath.ToSlash(hdr.Name)
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return fmt.Errorf("%w: unsafe path %q", ErrArchiveViolation, name)
		}
		// Reject anything that is not a plain directory or regular file:
		// symlinks, hardlinks, char/block devices, fifos, sockets.
		switch hdr.Typeflag {
		case tar.TypeDir:
			full := filepath.Join(dst, filepath.FromSlash(name))
			if err := os.MkdirAll(full, 0o750); err != nil {
				return err
			}
			continue
		case tar.TypeReg:
		default:
			return fmt.Errorf("%w: non-regular entry %q (type %d)", ErrArchiveViolation, name, hdr.Typeflag)
		}
		if hdr.Mode&0o170000 != 0 && hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: special mode on %q", ErrArchiveViolation, name)
		}

		count++
		if count > lim.MaxFiles {
			return fmt.Errorf("%w: file count exceeds %d", ErrArchiveViolation, lim.MaxFiles)
		}
		if hdr.Size > lim.MaxFileBytes {
			return fmt.Errorf("%w: %q exceeds per-file limit", ErrArchiveViolation, name)
		}
		total += hdr.Size
		if total > lim.MaxTotalBytes {
			return fmt.Errorf("%w: total size exceeds limit", ErrArchiveViolation)
		}
		if lim.MaxRatio > 0 && compressedSize > 0 && total > compressedSize*lim.MaxRatio {
			return fmt.Errorf("%w: compression ratio exceeds %d (zip bomb?)", ErrArchiveViolation, lim.MaxRatio)
		}

		full := filepath.Join(dst, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			return err
		}
		out, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600) //nolint:gosec // traversal rejected above
		if err != nil {
			return fmt.Errorf("%w: open %q: %v", ErrArchiveViolation, name, err)
		}
		// CopyN bounds even a header that lies about Size.
		n, err := io.CopyN(out, tr, hdr.Size+1)
		_ = out.Close()
		if err != nil && err != io.EOF {
			return fmt.Errorf("archive: extract %q: %w", name, err)
		}
		if n > hdr.Size {
			return fmt.Errorf("%w: %q body exceeds declared size", ErrArchiveViolation, name)
		}
	}
}
