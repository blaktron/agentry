package api

// Public browsing of a release archive: the same
// under the download access gate instead of the review gate. Browsing is
// not installing: no download stat is bumped. Content is returned as JSON
// text, never served as a raw page, so nothing inside an archive can
// execute in a visitor's browser; binary files are flagged, not
// returned.

import (
	"archive/tar"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
)

// versionArchive authorizes the caller for the version and opens its release
// archive. The status gate mirrors DownloadVersion; the install stat is the
// only difference, and it stays there.
func (s *Server) versionArchive(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) (io.ReadCloser, bool) {
	a, v, ok := s.versionOrNotFound(w, r, ns, name, version, auth.ActAgentRead)
	if !ok {
		return nil, false
	}
	if a.QuarantineState == "blocked" {
		writeProblem(w, r, http.StatusGone, "blocked", "Blocked QuickAgent",
			"Trust & safety blocked this QuickAgent. This archive stays unavailable until platform staff reinstate it.")
		return nil, false
	}
	switch registry.Status(v.Status) {
	case registry.StatusPublished:
	case registry.StatusYanked:
		w.Header().Set("X-Agentry-Yanked", "true")
	case registry.StatusBlocked:
		writeProblem(w, r, http.StatusGone, "blocked", "Blocked version",
			"Trust & safety blocked this version. This archive stays unavailable until platform staff reinstate it and a reviewer decides.")
		return nil, false
	case registry.StatusQuarantined:
		problemConflict(w, r, "This version is quarantined for review. This archive stays unavailable until a reviewer decides.")
		return nil, false
	default:
		problemNotFound(w, r)
		return nil, false
	}
	if v.ArchiveKey == nil || v.ArchiveDigest == nil {
		problemInternal(w, r)
		return nil, false
	}
	blob, err := s.blobs.Get(r.Context(), *v.ArchiveKey)
	if err != nil {
		s.log.ErrorContext(r.Context(), "version archive fetch", "err", err)
		problemInternal(w, r)
		return nil, false
	}
	return blob, true
}

// ListVersionFiles implements GET .../versions/{version}/files.
func (s *Server) ListVersionFiles(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	blob, ok := s.versionArchive(w, r, ns, name, version)
	if !ok {
		return
	}
	defer func() { _ = blob.Close() }()

	files := []ReviewFileEntry{}
	err := walkReviewArchive(blob, func(hdr *tar.Header, _ *tar.Reader) (bool, error) {
		files = append(files, ReviewFileEntry{Path: path.Clean(hdr.Name), Size: hdr.Size})
		return true, nil
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "version archive walk", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, ReviewFileList{Files: files})
}

// GetVersionFile implements GET .../versions/{version}/file?path=.
func (s *Server) GetVersionFile(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString, params GetVersionFileParams) {
	if !s.requireDB(w, r) {
		return
	}
	want := path.Clean(strings.TrimPrefix(params.Path, "./"))
	if want == "" || want == "." || strings.HasPrefix(want, "/") || strings.HasPrefix(want, "..") {
		problemValidation(w, r, "The path must be relative and stay inside the archive.")
		return
	}
	blob, ok := s.versionArchive(w, r, ns, name, version)
	if !ok {
		return
	}
	defer func() { _ = blob.Close() }()

	var out *ReviewFileContent
	err := walkReviewArchive(blob, func(hdr *tar.Header, tr *tar.Reader) (bool, error) {
		if path.Clean(hdr.Name) != want {
			return true, nil
		}
		buf, err := io.ReadAll(io.LimitReader(tr, reviewFileDisplayCap))
		if err != nil {
			return false, err
		}
		truncated := hdr.Size > int64(len(buf))
		fc := ReviewFileContent{Path: want, Size: hdr.Size, Truncated: truncated}
		if isDisplayableText(buf, truncated) {
			content := string(buf)
			fc.Content = &content
		} else {
			fc.Binary = true
		}
		out = &fc
		return false, nil
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "version archive read", "err", err)
		problemInternal(w, r)
		return
	}
	if out == nil {
		problemNotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, *out)
}
