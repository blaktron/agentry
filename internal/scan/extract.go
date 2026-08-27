package scan

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// The hardened archive extractor (§8.2): the single shared unpacker for
// untrusted release archives. It rejects path traversal, absolute paths,
// symlinks/hardlinks, device nodes, and any non-regular entry; enforces
// per-file, total-size, and file-count caps; and bounds the compression
// ratio to defuse zip bombs. Fuzzed in extract_fuzz_test.go.

// ExtractLimits bounds a safe extraction (§19 quotas + a decompression cap).
type ExtractLimits struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFiles      int
	// MaxRatio caps decompressed/compressed; 0 disables the check.
	MaxRatio int64
}

// DefaultLimits are the §19 release-archive quotas.
func DefaultLimits() ExtractLimits {
	return ExtractLimits{
		MaxFileBytes:  5 << 20,  // images up to 5 MB
		MaxTotalBytes: 10 << 20, // 10 MB post-filter
		MaxFiles:      2000,
		MaxRatio:      200,
	}
}

// ErrArchiveViolation marks a rejected archive (structural attack).
var ErrArchiveViolation = errors.New("scan: archive violation")

// Extract unpacks a tar.zst archive from r into dst with full hardening.
// compressedSize (bytes) enables the ratio check; pass 0 to skip it.
func Extract(r io.Reader, dst string, compressedSize int64, lim ExtractLimits) error {
	zr, err := zstd.NewReader(r, zstd.WithDecoderMaxMemory(64<<20))
	if err != nil {
		return fmt.Errorf("scan: zstd reader: %w", err)
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
			return fmt.Errorf("scan: extract %q: %w", name, err)
		}
		if n > hdr.Size {
			return fmt.Errorf("%w: %q body exceeds declared size", ErrArchiveViolation, name)
		}
	}
}
