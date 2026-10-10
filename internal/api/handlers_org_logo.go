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
// that URL as immutable. Behind Features.Branding to set, public to read.
//
// M18 (the site) renders `logoUrl` as the resource carries it and never
// builds the path: the version in it is what makes the caching honest.

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
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

const (
	// logoMaxBytes bounds an upload before a byte of it is decoded; the
	// decoder's own pixel cap (imgMaxPixels) is the other bound.
	logoMaxBytes = 256 << 10
	// logoMaxServedBytes bounds what the re-encode may produce, and so
	// what GetOrgLogo will read: a PNG encoder can expand a well-chosen
	// input several times over, and an object the read would truncate
	// would be served not matching the digest in its URL.
	logoMaxServedBytes = logoMaxBytes * 4
	// logoMultipartSlack is what the multipart framing around one 256 KB
	// part may take — the boundary lines and the part's headers — before
	// the body is refused as a whole. A very long file name eats into it,
	// and a full-size file then gets an honest 413.
	logoMultipartSlack = 1024
	// logoVersionLen is how much of the served object's digest the URL
	// carries: a cache key, not a security boundary.
	logoVersionLen = 16
)

// errLogoTooLarge is an upload over logoMaxBytes, or a re-encode over
// logoMaxServedBytes.
var errLogoTooLarge = errors.New("logo too large")

// logoObject is one stored logo: the digest of the bytes served and the
// format they are in. It is the one place the format's extension and
// content type meet, so the key this process writes and the type it
// pins when serving cannot disagree.
type logoObject struct {
	digest string // hex sha256 of the served bytes
	ctype  string // image/png or image/jpeg
}

func (l logoObject) ext() string {
	if l.ctype == "image/jpeg" {
		return ".jpg"
	}
	return ".png"
}

// key is where the object lives in the store: under the organization,
// named by its content.
func (l logoObject) key(orgID uuid.UUID) string {
	return "orgs/" + orgID.String() + "/logo/" + l.digest + l.ext()
}

// version is the part of the digest a URL carries.
func (l logoObject) version() string {
	if len(l.digest) > logoVersionLen {
		return l.digest[:logoVersionLen]
	}
	return l.digest
}

// parseLogoKey reads a key back into the object it names, or false for
// a key this code did not write.
func parseLogoKey(key string) (logoObject, bool) {
	i := strings.LastIndex(key, "/")
	if i < 0 || !strings.HasPrefix(key, "orgs/") {
		return logoObject{}, false
	}
	name := key[i+1:]
	switch {
	case strings.HasSuffix(name, ".jpg"):
		return logoObject{digest: strings.TrimSuffix(name, ".jpg"), ctype: "image/jpeg"}, true
	case strings.HasSuffix(name, ".png"):
		return logoObject{digest: strings.TrimSuffix(name, ".png"), ctype: "image/png"}, true
	}
	return logoObject{}, false
}

// logoURL is the path a client renders for an organization's logo, or ""
// for none: versioned by the served object's digest, so the URL changes
// with the content, and a cache that holds one URL as immutable is never
// wrong for longer than that URL is linked.
func logoURL(handle string, key *string) string {
	if key == nil {
		return ""
	}
	l, ok := parseLogoKey(*key)
	if !ok {
		return ""
	}
	return "/api/v1/orgs/" + handle + "/logo?v=" + l.version()
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
	if row.LogoObjectKey == nil || s.blobs == nil {
		problemNotFound(w, r)
		return
	}
	l, ok := parseLogoKey(*row.LogoObjectKey)
	if !ok {
		s.log.ErrorContext(r.Context(), "org logo: key not this code's", "org", row.ID, "key", *row.LogoObjectKey)
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
	body, err := io.ReadAll(io.LimitReader(rc, logoMaxServedBytes+1))
	if err != nil {
		s.log.ErrorContext(r.Context(), "org logo: read", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	if len(body) > logoMaxServedBytes {
		// Truncating would serve bytes that do not match the digest in
		// the URL; an object this size is not one PutOrgLogo wrote.
		s.log.ErrorContext(r.Context(), "org logo: object over the served bound", "org", row.ID, "key", *row.LogoObjectKey)
		problemInternal(w, r)
		return
	}
	// A year, immutable — but only for the URL that names this content.
	// The bare path, or one carrying a version that is no longer served,
	// is answered with the current logo and told not to keep it: nothing
	// enforces that a link carried the version, and a browser that cached
	// the bare path as immutable would show a replaced or removed logo
	// for a year.
	cache := "no-cache"
	if r.URL.Query().Get("v") == l.version() {
		cache = "public, max-age=31536000, immutable"
	}
	writeRaster(w, body, l.ctype, cache)
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
		problemUnavailable(w, r, "This deployment has no object storage configured, so a logo cannot be stored.")
		return
	}
	// The tier decides whether this organization may carry a logo at all
	// (D17). Unknown refuses, as every entitlement gate on an act does.
	f, err := s.orgFeatures(r.Context(), row.ID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "org logo: entitlements", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	if !f.Branding {
		problemFeatureNotIncluded(w, r, "A logo is not included in this organization's subscription.")
		return
	}
	upload, err := readUploadPart(w, r, logoMaxBytes)
	if err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.Is(err, errLogoTooLarge), errors.As(err, &mbe):
			problemUploadTooLarge(w, r, "A logo is at most 256 KB.")
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
		problemUnsupportedImage(w, r, "A logo is a PNG or a JPEG. SVG is not accepted: the registry has no way to make one safe to serve, so it does not serve any.")
		return
	case errors.Is(err, errRasterTooLarge):
		problemUploadTooLarge(w, r, "A logo has at most 16 million pixels.")
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "org logo: encode", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	if len(out) > logoMaxServedBytes {
		problemUploadTooLarge(w, r, "This image is larger encoded than a logo may be; a smaller one is needed.")
		return
	}
	sum := sha256.Sum256(out)
	l := logoObject{digest: hex.EncodeToString(sum[:]), ctype: ctype}
	key := l.key(row.ID)
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
	if previous != nil && *previous != key {
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
	if previous != nil && s.blobs != nil {
		if err := s.blobs.Delete(r.Context(), *previous); err != nil {
			s.log.WarnContext(r.Context(), "org logo: remove object", "org", row.ID, "key", *previous, "err", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// readUploadPart reads the one multipart part named file that a logo
// upload carries (the organization's, and the report design's since
// agentry#1025), at most maxBytes, bounded before a byte of it is decoded.
// It streams the parts rather than calling ParseMultipartForm, which would
// spool anything over its memory limit to disk: a logo is small and never
// touches one. The part's own declared type and file name are not
// consulted — what the bytes are is decided by the decoder, not by the
// sender. Over maxBytes is errLogoTooLarge.
func readUploadPart(w http.ResponseWriter, r *http.Request, maxBytes int) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes)+logoMultipartSlack)
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
		body, err := io.ReadAll(io.LimitReader(part, int64(maxBytes)+1))
		_ = part.Close()
		if err != nil {
			return nil, err
		}
		if len(body) > maxBytes {
			return nil, errLogoTooLarge
		}
		if len(body) == 0 {
			return nil, errors.New("empty file part")
		}
		return body, nil
	}
}
