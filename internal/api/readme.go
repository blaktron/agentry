package api

import (
	"net/http"

	"github.com/blaktron/agentry/internal/scan"
)

// errNoReadme means the release archive carries no README. Aliased from scan,
// where the extraction now lives: the search-index path (internal/scan's
// pipeline, on publish) and this rendering path must agree on which file is
// "the README", or an agent could be indexed under text nobody is shown.
var errNoReadme = scan.ErrNoReadme

// readmeFromArchive extracts README.md from a release archive.
func (s *Server) readmeFromArchive(r *http.Request, archiveKey string, archiveSize *int64) ([]byte, error) {
	return scan.ExtractREADME(r.Context(), s.blobs, archiveKey, archiveSize)
}
