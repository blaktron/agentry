package api

// Review-archive browsing (§10.1 reviewer detail): the file inventory and
// per-file content of the release archive under review. Access is the same
// reviewItemAccess gate as the rest of the review bundle. Content is returned
// as JSON text — never served as a raw page — so nothing inside an archive
// can execute in a reviewer's browser (§10.3); binary files are flagged, not
// returned. The web app renders text with invisible-Unicode placeholders so
// the reviewer sees exactly what the scanner saw.

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

const (
	// reviewFileDisplayCap bounds how much of one file the viewer returns;
	// larger files are truncated with a flag (§19 caps single files at 2 MB,
	// so most text files arrive whole).
	reviewFileDisplayCap = 512 << 10
	// reviewArchiveReadCap bounds total decompressed bytes walked per request
	// (defense in depth on top of the submission-time §19/§8.2 caps).
	reviewArchiveReadCap = 64 << 20
	// reviewMaxEntries bounds the listing (archives are capped at 2,000 files
	// at submission; anything past this is hostile).
	reviewMaxEntries = 4000
)

// reviewArchive authorizes the caller for review item id and opens the
// version's release archive.
func (s *Server) reviewArchive(w http.ResponseWriter, r *http.Request, id uuid.UUID) (io.ReadCloser, bool) {
	ri, ok := s.reviewItemAccess(w, r, id)
	if !ok {
		return nil, false
	}
	v, err := s.q().GetVersionByID(r.Context(), ri.VersionID)
	if err != nil {
		problemInternal(w, r)
		return nil, false
	}
	if v.ArchiveKey == nil {
		problemConflict(w, r, "This version has no archive yet.")
		return nil, false
	}
	blob, err := s.blobs.Get(r.Context(), *v.ArchiveKey)
	if err != nil {
		s.log.Error("review archive fetch", "err", err)
		problemInternal(w, r)
		return nil, false
	}
	return blob, true
}

// walkReviewArchive iterates regular-file entries of a tar.zst stream with
// hardening caps, calling fn for each safe entry until fn returns false.
func walkReviewArchive(blob io.Reader, fn func(hdr *tar.Header, tr *tar.Reader) (bool, error)) error {
	zr, err := zstd.NewReader(blob, zstd.WithDecoderMaxMemory(64<<20))
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(io.LimitReader(zr, reviewArchiveReadCap))
	count := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(hdr.Name)
		if name == "" || name == "." || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "..") {
			continue // unsafe names never listed (mirrors the §8.2 extractor)
		}
		count++
		if count > reviewMaxEntries {
			return nil
		}
		cont, err := fn(hdr, tr)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}
}

// ListReviewFiles implements GET /review-items/{id}/files.
func (s *Server) ListReviewFiles(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	blob, ok := s.reviewArchive(w, r, id)
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
		s.log.Error("review archive walk", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, ReviewFileList{Files: files})
}

// GetReviewFile implements GET /review-items/{id}/file?path=.
func (s *Server) GetReviewFile(w http.ResponseWriter, r *http.Request, id openapi_types.UUID, params GetReviewFileParams) {
	if !s.requireDB(w, r) {
		return
	}
	want := path.Clean(strings.TrimPrefix(params.Path, "./"))
	if want == "" || want == "." || strings.HasPrefix(want, "/") || strings.HasPrefix(want, "..") {
		problemValidation(w, r, "The path must be relative and stay inside the archive.")
		return
	}
	blob, ok := s.reviewArchive(w, r, id)
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
		s.log.Error("review archive read", "err", err)
		problemInternal(w, r)
		return
	}
	if out == nil {
		problemNotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, *out)
}

// isDisplayableText reports whether buf is valid UTF-8 without NUL bytes.
// This checks content, not file names, so a mislabeled binary cannot smuggle
// raw bytes into the viewer. When the read was truncated at the display cap,
// a multi-byte rune split at the very end is tolerated.
func isDisplayableText(buf []byte, truncated bool) bool {
	if bytes.IndexByte(buf, 0) >= 0 {
		return false
	}
	b := buf
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			return truncated && len(b) < utf8.UTFMax
		}
		b = b[size:]
	}
	return true
}
