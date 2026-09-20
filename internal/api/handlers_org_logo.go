package api

// The organization's logo (agentry#367, M17 of plan
// organization-subscriptions.md §5.9; D17): a raster an admin uploads,
// which the core decodes and encodes again through the image proxy's own
// path before it is stored, so the bytes a browser ever receives were
// written by this process (§10.3). PNG and JPEG only, at most 256 KB;
// never SVG — this repository has no sanitiser for it, and the refusal
// is what stands in for one. Stored in the deployment's object store
// under the organization, keyed by the digest of what is served, so the
// URL a client renders changes when the logo does and a cache may hold
// it as immutable. Behind Features.Branding to set, public to read.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// logoMaxBytes bounds an upload before it is decoded: a logo is small,
// and the decoder's own pixel cap (imgMaxPixels) is the other bound.
const logoMaxBytes = 256 << 10

// logoKey is where an organization's logo lives in the object store:
// under the organization, named by the digest of the re-encoded bytes.
func logoKey(orgID uuid.UUID, digest, ext string) string {
	return "orgs/" + orgID.String() + "/logo/" + digest + ext
}

// logoURL is the path a client renders for an organization's logo, or ""
// for none. The version is the served object's digest, taken from its
// key, so the URL changes with the content and a cache that holds the
// old one as immutable is never wrong for longer than the old URL is
// linked. GetOrgLogo ignores the query: it serves what the row names.
func logoURL(handle string, key *string) string {
	if key == nil || *key == "" {
		return ""
	}
	v := *key
	if i := strings.LastIndex(v, "/"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.Index(v, "."); i >= 0 {
		v = v[:i]
	}
	if len(v) > 16 {
		v = v[:16]
	}
	return "/api/v1/orgs/" + handle + "/logo?v=" + v
}

// GetOrgLogo implements GET /orgs/{org}/logo.
func (s *Server) GetOrgLogo(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.authorize(w, r, auth.ActPublicRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	row, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if row.LogoObjectKey == nil || *row.LogoObjectKey == "" || s.blobs == nil {
		problemNotFound(w, r)
		return
	}
	rc, err := s.blobs.Get(r.Context(), *row.LogoObjectKey)
	if err != nil {
		// A row naming an object that is gone is a logo the registry
		// cannot serve, which to a reader is the same as none — and a
		// line in the log, since it is not a state this code writes.
		s.log.ErrorContext(r.Context(), "org logo: read", "org", row.ID, "key", *row.LogoObjectKey, "err", err)
		problemNotFound(w, r)
		return
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(io.LimitReader(rc, logoMaxBytes*4))
	if err != nil {
		s.log.ErrorContext(r.Context(), "org logo: read", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	// The type is pinned from the key's extension, which this process
	// wrote when it encoded the object, never sniffed from the bytes.
	ctype := "image/png"
	if strings.HasSuffix(*row.LogoObjectKey, ".jpg") {
		ctype = "image/jpeg"
	}
	// A year, immutable: the URL carries the content's digest, so a new
	// logo is a new URL, and nothing served under an old one changes.
	writeRaster(w, body, ctype, "public, max-age=31536000, immutable")
}

// PutOrgLogo implements PUT /orgs/{org}/logo.
func (s *Server) PutOrgLogo(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	row, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgBrandingManage, row.ID) {
		return
	}
	if s.blobs == nil {
		problemInternal(w, r)
		return
	}
	// The tier decides whether this organization may carry a logo at all
	// (D17). Unknown refuses, as every entitlement gate on an act does.
	f, err := s.entitlements().Features(r.Context(), entitlements.ForOrg(row.ID))
	if err != nil {
		s.log.ErrorContext(r.Context(), "org logo: entitlements", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	if !f.Branding {
		problemFeatureNotIncluded(w, r, "A logo is not included in this organization's subscription.")
		return
	}
	upload, err := readLogoUpload(w, r)
	if err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			writeProblem(w, r, http.StatusRequestEntityTooLarge, "too-large", "Logo too large", "A logo is at most 256 KB.")
		default:
			problemBadRequest(w, r, "Send the logo as one multipart part named file.")
		}
		return
	}
	// Decoded and encoded again from the pixels: PNG or JPEG, never the
	// upload's bytes, never SVG.
	out, ctype, err := reencodeRaster(upload, rasterPNG|rasterJPEG)
	switch {
	case errors.Is(err, errRasterUnsupported):
		writeProblem(w, r, http.StatusUnsupportedMediaType, "unsupported-image", "Not a PNG or JPEG",
			"A logo is a PNG or a JPEG. SVG is not accepted: the registry has no way to make one safe to serve, so it does not serve any.")
		return
	case errors.Is(err, errRasterTooLarge):
		writeProblem(w, r, http.StatusRequestEntityTooLarge, "too-large", "Logo too large", "A logo has at most 16 million pixels.")
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "org logo: encode", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	ext := ".png"
	if ctype == "image/jpeg" {
		ext = ".jpg"
	}
	sum := sha256.Sum256(out)
	key := logoKey(row.ID, hex.EncodeToString(sum[:]), ext)
	// The object first, the row second: a row that names an object which
	// is not there would serve a 404 for a logo the admin was told is set.
	if err := s.blobs.Put(r.Context(), key, bytes.NewReader(out)); err != nil {
		s.log.ErrorContext(r.Context(), "org logo: store", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	var previous *string
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		prev, err := q.SetOrgLogo(r.Context(), storegen.SetOrgLogoParams{ID: row.ID, LogoObjectKey: &key})
		if err != nil {
			return err
		}
		previous = prev
		e := auditEvent(r, audit.ActionOrgLogoSet)
		e.OrgID = row.ID
		e.TargetKind, e.TargetID = "org", row.ID
		e.Detail = map[string]any{"key": key, "bytes": len(out), "type": ctype}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "org logo: record", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	// The replaced object goes last, and its loss is not the request's
	// failure: the row already names the new one, and a sweep can remove
	// a stray object; a request that failed here after succeeding would
	// tell the admin the logo is not set when it is.
	if previous != nil && *previous != "" && *previous != key {
		if err := s.blobs.Delete(r.Context(), *previous); err != nil {
			s.log.WarnContext(r.Context(), "org logo: remove replaced object", "org", row.ID, "key", *previous, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logoUrl": logoURL(row.Handle, &key)})
}

// DeleteOrgLogo implements DELETE /orgs/{org}/logo.
func (s *Server) DeleteOrgLogo(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	row, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgBrandingManage, row.ID) {
		return
	}
	var previous *string
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		prev, err := q.ClearOrgLogo(r.Context(), row.ID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // there was none: removing nothing is done
			}
			return err
		}
		previous = prev
		e := auditEvent(r, audit.ActionOrgLogoRemoved)
		e.OrgID = row.ID
		e.TargetKind, e.TargetID = "org", row.ID
		if prev != nil {
			e.Detail = map[string]any{"key": *prev}
		}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "org logo: clear", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	if previous != nil && *previous != "" && s.blobs != nil {
		if err := s.blobs.Delete(r.Context(), *previous); err != nil {
			s.log.WarnContext(r.Context(), "org logo: remove object", "org", row.ID, "key", *previous, "err", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// readLogoUpload reads the one multipart part a logo upload carries,
// bounded before a byte of it is decoded. The part's own declared type
// and file name are not consulted: what the bytes are is decided by the
// decoder, not by the sender.
func readLogoUpload(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, logoMaxBytes+1024)
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, err
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return nil, errors.New("no file part")
		}
		if err != nil {
			return nil, err
		}
		if part.FormName() != "file" {
			_ = part.Close()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(part, logoMaxBytes+1))
		_ = part.Close()
		if err != nil {
			return nil, err
		}
		if len(body) > logoMaxBytes {
			return nil, &http.MaxBytesError{Limit: logoMaxBytes}
		}
		if len(body) == 0 {
			return nil, errors.New("empty file part")
		}
		return body, nil
	}
}
