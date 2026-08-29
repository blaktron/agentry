package scan

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// ErrNoReadme means the release archive carries no README.
var ErrNoReadme = errors.New("scan: archive has no README")

// readmeCandidates are the filenames tried, in order. Only the archive root is
// searched: a README nested inside the tree describes a subdirectory, not the
// agent, and indexing it would let a vendored dependency's docs decide what an
// agent appears to be about in search.
var readmeCandidates = []string{"README.md", "readme.md", "Readme.md", "README", "README.markdown"}

// BlobGetter is the slice of registry.BlobStore this helper needs. Declared
// here rather than importing registry because registry cannot import scan —
// the pipeline dependency runs the other way.
type BlobGetter interface {
	Get(ctx context.Context, key string) (io.ReadCloser, error)
}

// ExtractREADME pulls the README out of a release archive. It reuses the
// hardened extractor (§8.2) rather than reading the tar directly, so both the
// rendering path and the search-index path get the same traversal and
// decompression-bomb protections the scanners do.
func ExtractREADME(ctx context.Context, blobs BlobGetter, archiveKey string, archiveSize *int64) ([]byte, error) {
	if blobs == nil {
		return nil, ErrNoReadme
	}
	blob, err := blobs.Get(ctx, archiveKey)
	if err != nil {
		return nil, err
	}
	defer func() { _ = blob.Close() }()

	dir, err := os.MkdirTemp("", "agentry-readme-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	var size int64
	if archiveSize != nil {
		size = *archiveSize
	}
	if err := Extract(blob, dir, size, DefaultLimits()); err != nil {
		return nil, err
	}
	for _, candidate := range readmeCandidates {
		data, err := os.ReadFile(filepath.Join(dir, candidate)) //nolint:gosec // fixed names under a temp dir
		if err == nil {
			return data, nil
		}
	}
	return nil, ErrNoReadme
}

// MaxIndexedReadmeBytes bounds the README text denormalized onto the agent row
// for the §10.4 weight-C index.
//
// to_tsvector runs inside a BEFORE trigger on every agent write, and its
// output is capped at 1 MB — past that Postgres errors, which would turn an
// oversized README into a failed publish. 64 KB is far more prose than any
// agent's README carries (§1.6.4: agents are small by design) and keeps the
// trigger's cost bounded and predictable.
const MaxIndexedReadmeBytes = 64 << 10

// ReadmeIndexText normalizes README bytes into something safe to store in the
// tsvector source column: valid UTF-8, no NUL bytes (Postgres text rejects
// them), and truncated on a rune boundary.
func ReadmeIndexText(raw []byte) string {
	s := string(raw)
	if len(s) > MaxIndexedReadmeBytes {
		s = s[:MaxIndexedReadmeBytes]
		// Truncation can split a multi-byte rune; drop the partial tail rather
		// than storing a replacement character that would index as a token.
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	s = strings.ReplaceAll(s, "\x00", "")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return s
}
