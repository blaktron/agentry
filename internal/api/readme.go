package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/PLACEHOLDER_ORG/agentry/internal/scan"
)

// errNoReadme means the release archive carries no README.
var errNoReadme = errors.New("api: archive has no README")

// readmeFromArchive extracts README.md from a release archive. It reuses the
// hardened extractor (§8.2) rather than reading the tar directly, so the
// rendering path gets the same traversal/bomb protections the scanners do.
func (s *Server) readmeFromArchive(r *http.Request, archiveKey string, archiveSize *int64) ([]byte, error) {
	blob, err := s.blobs.Get(r.Context(), archiveKey)
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
	if err := scan.Extract(blob, dir, size, scan.DefaultLimits()); err != nil {
		return nil, err
	}
	for _, candidate := range []string{"README.md", "readme.md", "Readme.md", "README", "README.markdown"} {
		data, err := os.ReadFile(filepath.Join(dir, candidate)) //nolint:gosec // fixed names under a temp dir
		if err == nil {
			return data, nil
		}
	}
	return nil, errNoReadme
}
