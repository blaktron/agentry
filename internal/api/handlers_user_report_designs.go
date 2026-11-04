package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/reportdesign"
)

// The report design library: up to reportdesign.MaxLibrary designs per
// account, each a theme document version 3 that pkg/reportdesign validated,
// with its images beside it, and one of them the default a run takes when
// the person picks none. Every route reaches only the caller's own rows, on
// the profile scope. What is stored and answered is the canonical document;
// the images (the logo, the cover image, the custom cover) are answered only
// on include=assets, so a client that does not draw them reads the document
// whole and small.

// ErrReportDesignsFull is a create past the library's bound.
var ErrReportDesignsFull = errors.New("report designs: the library holds ten designs")

// ReportDesignEntry is one design as the server reads it, with its images,
// for the extension seam.
type ReportDesignEntry struct {
	ID      uuid.UUID
	Default bool
	// Design is the design with every image it has.
	Design               reportdesign.Design
	CreatedAt, UpdatedAt time.Time
}

// reportDesignBody is a design on the wire, with the document as the
// canonical form pkg/reportdesign wrote rather than the generated type, so
// what the server answers is exactly what it validated.
type reportDesignBody struct {
	ID             uuid.UUID       `json:"id"`
	Default        bool            `json:"default"`
	HasLogo        bool            `json:"hasLogo"`
	HasCoverImage  bool            `json:"hasCoverImage"`
	HasCustomCover bool            `json:"hasCustomCover"`
	CreatedAt      time.Time       `json:"createdAt"`
	UpdatedAt      time.Time       `json:"updatedAt"`
	Design         json.RawMessage `json:"design"`
}

type reportDesignSummary struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	BasedOn        string    `json:"basedOn"`
	Version        int       `json:"version"`
	Default        bool      `json:"default"`
	HasLogo        bool      `json:"hasLogo"`
	HasCoverImage  bool      `json:"hasCoverImage"`
	HasCustomCover bool      `json:"hasCustomCover"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type reportDesignList struct {
	Designs []reportDesignSummary `json:"designs"`
	Default *uuid.UUID            `json:"default,omitempty"`
}

// reportDesignRequestBytes is the most a design's body may be: the document
// with every image at its largest, and the keys around it.
const reportDesignRequestSlack = 1 << 10

// includeAssets reads the include parameter, absent or "assets", into
// whether the answer carries the images; ok is false once a bad value was
// answered.
func includeAssets(w http.ResponseWriter, r *http.Request, include *ReportDesignInclude) (withAssets, ok bool) {
	switch {
	case include == nil:
		return false, true
	case *include == ReportDesignIncludeAssets:
		return true, true
	}
	problemBadRequest(w, r, "include takes only assets.")
	return false, false
}

// fieldMessage is a design refusal's message without the field, which the
// problem names on its own.
func fieldMessage(err error) string {
	var fe *reportdesign.FieldError
	if errors.As(err, &fe) {
		return fe.Message
	}
	return err.Error()
}

// problemDesign answers a design's refusal: 422 naming design.<path>.
func problemDesign(w http.ResponseWriter, r *http.Request, err error) {
	var fe *reportdesign.FieldError
	if !errors.As(err, &fe) {
		fe = &reportdesign.FieldError{Message: err.Error()}
	}
	field := "design"
	if fe.Field != "" {
		field += "." + fe.Field
	}
	problemValidation(w, r, "The report design is not valid.", FieldError{Field: field, Message: fe.Message})
}

// ListUserReportDesigns implements GET /user/report-designs.
func (s *Server) ListUserReportDesigns(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	list, err := s.reportDesignList(r.Context(), s.q(), p.UserID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "report designs: list", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// reportDesignList is the account's library as the API answers it. A
// stored document that no longer parses is still listed, by what its JSON
// says, so a design is never invisible while it counts toward the bound.
func (s *Server) reportDesignList(ctx context.Context, q *storegen.Queries, user uuid.UUID) (reportDesignList, error) {
	rows, err := q.ListUserReportDesigns(ctx, user)
	if err != nil {
		return reportDesignList{}, err
	}
	out := reportDesignList{Designs: make([]reportDesignSummary, 0, len(rows))}
	for _, row := range rows {
		var head struct {
			Name    string `json:"name"`
			BasedOn string `json:"basedOn"`
			Version int    `json:"version"`
		}
		_ = json.Unmarshal(row.Document, &head)
		out.Designs = append(out.Designs, reportDesignSummary{
			ID: row.ID, Name: head.Name, BasedOn: head.BasedOn, Version: head.Version, Default: row.IsDefault,
			HasLogo: row.HasLogo, HasCoverImage: row.HasCoverImage, HasCustomCover: row.HasCustomCover,
			CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		})
		if row.IsDefault {
			id := row.ID
			out.Default = &id
		}
	}
	return out, nil
}

// readDesign reads a design document from a request body, validated.
func (s *Server) readDesign(w http.ResponseWriter, r *http.Request, raw json.RawMessage) (reportdesign.Design, bool) {
	if len(raw) == 0 {
		problemValidation(w, r, "The report design is not valid.", FieldError{Field: "design", Message: "is required"})
		return reportdesign.Design{}, false
	}
	d, err := reportdesign.Parse(raw)
	if err != nil {
		problemDesign(w, r, err)
		return reportdesign.Design{}, false
	}
	return d, true
}

// storedAssets is a design's images as the rows keep them: each one encoded
// again by pkg/reportdesign from the pixels the document carried, so what is
// stored is this process's own encoding.
type storedAssets struct {
	logo             []byte
	coverImage       []byte
	coverImageFormat *string
	customCover      []byte
}

// assetsOf encodes a design's images again for storage. A refusal is a
// *reportdesign.FieldError on the image's field.
func assetsOf(d reportdesign.Design) (storedAssets, error) {
	var out storedAssets
	if d.Logo != (reportdesign.Logo{}) {
		png, err := normalizedLogo(d.Logo)
		if err != nil {
			return out, &reportdesign.FieldError{Field: "logo.png", Message: fieldMessage(err)}
		}
		out.logo = png
	}
	if d.CoverImage != (reportdesign.Image{}) {
		data, format, err := normalizedImage(d.CoverImage, reportdesign.NormalizeCoverImage)
		if err != nil {
			return out, &reportdesign.FieldError{Field: "coverImage", Message: fieldMessage(err)}
		}
		out.coverImage, out.coverImageFormat = data, &format
	}
	if !d.CustomCover.IsZero() {
		cc, err := normalizedCustomCover(d.CustomCover)
		if err != nil {
			return out, err
		}
		out.customCover = cc
	}
	return out, nil
}

// normalizedLogo is a design's logo encoded again by NormalizeLogo, as the
// PNG bytes to store.
func normalizedLogo(l reportdesign.Logo) ([]byte, error) {
	raw, err := l.Decode()
	if err != nil {
		return nil, err
	}
	n, err := reportdesign.NormalizeLogo(raw)
	if err != nil {
		return nil, err
	}
	return n.Decode()
}

// normalizedImage is an image encoded again by normalize, as the bytes to
// store and their format.
func normalizedImage(img reportdesign.Image, normalize func([]byte) (reportdesign.Image, error)) ([]byte, string, error) {
	raw, _, err := img.Decode()
	if err != nil {
		return nil, "", err
	}
	n, err := normalize(raw)
	if err != nil {
		return nil, "", err
	}
	return n.Decode()
}

// normalizedCustomCover is a custom cover with each image and the thumbnail
// encoded again, as the JSON to store: the custom cover's own canonical
// form. A refusal is a *reportdesign.FieldError.
func normalizedCustomCover(cc reportdesign.CustomCover) ([]byte, error) {
	out := reportdesign.CustomCover{Source: cc.Source, Images: make([]reportdesign.Image, 0, len(cc.Images))}
	total := 0
	for i, img := range cc.Images {
		data, format, err := normalizedImage(img, reportdesign.NormalizeCustomCoverImage)
		if err != nil {
			return nil, &reportdesign.FieldError{Field: "customCover.images." + itoa(i), Message: fieldMessage(err)}
		}
		total += len(data)
		out.Images = append(out.Images, reportdesign.ImageOf(data, format))
	}
	if total > reportdesign.MaxCoverImagesBytes {
		return nil, &reportdesign.FieldError{Field: "customCover.images", Message: "are over 2 MB in all once encoded again"}
	}
	if cc.Thumbnail != (reportdesign.Image{}) {
		data, format, err := normalizedImage(cc.Thumbnail, reportdesign.NormalizeThumbnail)
		if err != nil {
			return nil, &reportdesign.FieldError{Field: "customCover.thumbnail", Message: fieldMessage(err)}
		}
		out.Thumbnail = reportdesign.ImageOf(data, format)
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return customCoverJSON(out), nil
}

func customCoverJSON(cc reportdesign.CustomCover) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cc); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func itoa(i int) string {
	return string(rune('0' + i))
}

// CreateUserReportDesign implements POST /user/report-designs.
func (s *Server) CreateUserReportDesign(w http.ResponseWriter, r *http.Request, params CreateUserReportDesignParams) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	withAssets, ok := includeAssets(w, r, params.Include)
	if !ok {
		return
	}
	var req struct {
		Design  json.RawMessage `json:"design"`
		Default *bool           `json:"default"`
	}
	if !readJSONUpTo(w, r, &req, int64(reportdesign.MaxDocumentWithAssets)+reportDesignRequestSlack) {
		return
	}
	d, ok := s.readDesign(w, r, req.Design)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	row, err := s.createReportDesign(r.Context(), p.UserID, d, req.Default != nil && *req.Default)
	if err != nil {
		var fe *reportdesign.FieldError
		switch {
		case errors.Is(err, ErrReportDesignsFull):
			problemConflict(w, r, "The library holds ten designs. Remove one to add another.")
		case errors.As(err, &fe):
			problemDesign(w, r, err)
		default:
			s.log.ErrorContext(r.Context(), "report designs: create", "user", p.UserID, "err", err)
			problemInternal(w, r)
		}
		return
	}
	s.answerReportDesign(w, r, http.StatusCreated, row, withAssets)
}

// createReportDesign adds a design to the account's library, as the
// default when asked, under the library's bound. The images the document
// carries are encoded again and stored beside it.
func (s *Server) createReportDesign(ctx context.Context, user uuid.UUID, d reportdesign.Design, asDefault bool) (storegen.UserReportDesign, error) {
	assets, err := assetsOf(d)
	if err != nil {
		return storegen.UserReportDesign{}, err
	}
	var row storegen.UserReportDesign
	err = s.st.WithPgxTx(ctx, func(tx pgx.Tx, tq *storegen.Queries) error {
		if err := tq.LockUserForReportDesigns(ctx, user); err != nil {
			return err
		}
		n, err := tq.CountUserReportDesigns(ctx, user)
		if err != nil {
			return err
		}
		if n >= reportdesign.MaxLibrary {
			return ErrReportDesignsFull
		}
		if asDefault {
			if _, err := tq.ClearUserReportDesignDefault(ctx, user); err != nil {
				return err
			}
		}
		row, err = tq.CreateUserReportDesign(ctx, storegen.CreateUserReportDesignParams{
			UserID: user, Document: d.WithoutAssets().Canonical(),
			Logo: assets.logo, CoverImage: assets.coverImage, CoverImageFormat: assets.coverImageFormat, CustomCover: assets.customCover,
			IsDefault: asDefault,
		})
		return err
	})
	return row, err
}

// GetUserReportDesign implements GET /user/report-designs/{designId}.
func (s *Server) GetUserReportDesign(w http.ResponseWriter, r *http.Request, designId ReportDesignId, params GetUserReportDesignParams) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	withAssets, ok := includeAssets(w, r, params.Include)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().GetUserReportDesign(r.Context(), storegen.GetUserReportDesignParams{UserID: p.UserID, ID: designId})
	if errors.Is(err, pgx.ErrNoRows) {
		problemNotFound(w, r)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "report designs: read", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	s.answerReportDesign(w, r, http.StatusOK, row, withAssets)
}

// UpdateUserReportDesign implements PUT /user/report-designs/{designId}.
func (s *Server) UpdateUserReportDesign(w http.ResponseWriter, r *http.Request, designId ReportDesignId, params UpdateUserReportDesignParams) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	withAssets, ok := includeAssets(w, r, params.Include)
	if !ok {
		return
	}
	var req struct {
		Design json.RawMessage `json:"design"`
	}
	if !readJSONUpTo(w, r, &req, int64(reportdesign.MaxDocumentWithAssets)+reportDesignRequestSlack) {
		return
	}
	d, ok := s.readDesign(w, r, req.Design)
	if !ok {
		return
	}
	assets, err := assetsOf(d)
	if err != nil {
		problemDesign(w, r, err)
		return
	}
	p := principalFrom(r.Context())
	var row storegen.UserReportDesign
	err = s.st.WithPgxTx(r.Context(), func(tx pgx.Tx, tq *storegen.Queries) error {
		var err error
		row, err = tq.UpdateUserReportDesignDocument(r.Context(), storegen.UpdateUserReportDesignDocumentParams{
			UserID: p.UserID, ID: designId, Document: d.WithoutAssets().Canonical(),
		})
		if err != nil {
			return err
		}
		if assets.logo != nil {
			if row, err = tq.SetUserReportDesignLogo(r.Context(), storegen.SetUserReportDesignLogoParams{UserID: p.UserID, ID: designId, Logo: assets.logo}); err != nil {
				return err
			}
		}
		if assets.coverImage != nil {
			if row, err = tq.SetUserReportDesignCoverImage(r.Context(), storegen.SetUserReportDesignCoverImageParams{
				UserID: p.UserID, ID: designId, CoverImage: assets.coverImage, CoverImageFormat: assets.coverImageFormat,
			}); err != nil {
				return err
			}
		}
		if assets.customCover != nil {
			if row, err = tq.SetUserReportDesignCustomCover(r.Context(), storegen.SetUserReportDesignCustomCoverParams{UserID: p.UserID, ID: designId, CustomCover: assets.customCover}); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		problemNotFound(w, r)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "report designs: update", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	s.answerReportDesign(w, r, http.StatusOK, row, withAssets)
}

// DeleteUserReportDesign implements DELETE /user/report-designs/{designId}.
func (s *Server) DeleteUserReportDesign(w http.ResponseWriter, r *http.Request, designId ReportDesignId) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	n, err := s.q().DeleteUserReportDesign(r.Context(), storegen.DeleteUserReportDesignParams{UserID: p.UserID, ID: designId})
	if err != nil {
		s.log.ErrorContext(r.Context(), "report designs: delete", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	if n == 0 {
		problemNotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetUserReportDesignDefault implements PUT /user/report-designs/default.
func (s *Server) SetUserReportDesignDefault(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req struct {
		ID *uuid.UUID `json:"id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r.Context())
	var list reportDesignList
	err := s.st.WithPgxTx(r.Context(), func(tx pgx.Tx, tq *storegen.Queries) error {
		if _, err := tq.ClearUserReportDesignDefault(r.Context(), p.UserID); err != nil {
			return err
		}
		if req.ID != nil {
			n, err := tq.SetUserReportDesignDefault(r.Context(), storegen.SetUserReportDesignDefaultParams{UserID: p.UserID, ID: *req.ID})
			if err != nil {
				return err
			}
			if n == 0 {
				return pgx.ErrNoRows
			}
		}
		var err error
		list, err = s.reportDesignList(r.Context(), tq, p.UserID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		problemNotFound(w, r)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "report designs: set default", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// PutUserReportDesignLogo implements PUT /user/report-designs/{designId}/logo:
// one multipart part named file, PNG or JPEG, at most 512 KB, decoded,
// scaled down and encoded again as PNG by pkg/reportdesign, so only its
// pixels are kept. Read the same way as the organization's logo
// (readUploadPart), at this image's own bound.
func (s *Server) PutUserReportDesignLogo(w http.ResponseWriter, r *http.Request, designId ReportDesignId) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	upload, ok := s.readImageUpload(w, r, reportdesign.MaxLogoUploadBytes, "A logo is at most 512 KB.")
	if !ok {
		return
	}
	logo, err := reportdesign.NormalizeLogo(upload)
	if err != nil {
		s.refuseImage(w, r, err, "logo")
		return
	}
	png, err := logo.Decode()
	if err != nil {
		s.log.ErrorContext(r.Context(), "report logo: encode", "err", err)
		problemInternal(w, r)
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().SetUserReportDesignLogo(r.Context(), storegen.SetUserReportDesignLogoParams{UserID: p.UserID, ID: designId, Logo: png})
	s.answerAssetChange(w, r, row, err, "logo: write")
}

// readImageUpload reads the one multipart part of an image upload, held to
// maxBytes; ok is false once a refusal was answered.
func (s *Server) readImageUpload(w http.ResponseWriter, r *http.Request, maxBytes int, tooLarge string) ([]byte, bool) {
	upload, err := readUploadPart(w, r, maxBytes)
	if err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.Is(err, errLogoTooLarge), errors.As(err, &mbe):
			problemUploadTooLarge(w, r, tooLarge)
		default:
			problemBadRequest(w, r, "Send the image as one multipart part named file.")
		}
		return nil, false
	}
	return upload, true
}

// refuseImage answers an image the package would not take: 413 over a
// bound, 415 in no format it reads.
func (s *Server) refuseImage(w http.ResponseWriter, r *http.Request, err error, what string) {
	switch {
	case errors.Is(err, reportdesign.ErrImageTooLarge):
		problemUploadTooLarge(w, r, "This image is too large for a "+what+": "+fieldMessage(err)+".")
	default:
		problemUnsupportedImage(w, r, "A "+what+" is a PNG or a JPEG. SVG is not accepted: the registry has no way to make one safe, so it takes none.")
	}
}

// answerAssetChange answers a row an image route changed, with its images;
// no row is not the caller's design.
func (s *Server) answerAssetChange(w http.ResponseWriter, r *http.Request, row storegen.UserReportDesign, err error, what string) {
	if errors.Is(err, pgx.ErrNoRows) {
		problemNotFound(w, r)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "report designs: "+what, "err", err)
		problemInternal(w, r)
		return
	}
	s.answerReportDesign(w, r, http.StatusOK, row, true)
}

// DeleteUserReportDesignLogo implements DELETE
// /user/report-designs/{designId}/logo: the design stays; removing no logo
// is done.
func (s *Server) DeleteUserReportDesignLogo(w http.ResponseWriter, r *http.Request, designId ReportDesignId) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().ClearUserReportDesignLogo(r.Context(), storegen.ClearUserReportDesignLogoParams{UserID: p.UserID, ID: designId})
	s.answerAssetChange(w, r, row, err, "logo: clear")
}

// PutUserReportDesignCoverImage implements PUT
// /user/report-designs/{designId}/cover-image: one multipart part named
// file, PNG or JPEG, at most 2 MB, decoded, scaled down and encoded again in
// its own format by pkg/reportdesign, so only its pixels are kept.
func (s *Server) PutUserReportDesignCoverImage(w http.ResponseWriter, r *http.Request, designId ReportDesignId) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	upload, ok := s.readImageUpload(w, r, reportdesign.MaxCoverImageUploadBytes, "A cover image is at most 2 MB.")
	if !ok {
		return
	}
	img, err := reportdesign.NormalizeCoverImage(upload)
	if err != nil {
		s.refuseImage(w, r, err, "cover image")
		return
	}
	data, format, err := img.Decode()
	if err != nil {
		s.log.ErrorContext(r.Context(), "report cover image: encode", "err", err)
		problemInternal(w, r)
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().SetUserReportDesignCoverImage(r.Context(), storegen.SetUserReportDesignCoverImageParams{
		UserID: p.UserID, ID: designId, CoverImage: data, CoverImageFormat: &format,
	})
	s.answerAssetChange(w, r, row, err, "cover image: write")
}

// DeleteUserReportDesignCoverImage implements DELETE
// /user/report-designs/{designId}/cover-image.
func (s *Server) DeleteUserReportDesignCoverImage(w http.ResponseWriter, r *http.Request, designId ReportDesignId) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().ClearUserReportDesignCoverImage(r.Context(), storegen.ClearUserReportDesignCoverImageParams{UserID: p.UserID, ID: designId})
	s.answerAssetChange(w, r, row, err, "cover image: clear")
}

// PutUserReportDesignCustomCover implements PUT
// /user/report-designs/{designId}/custom-cover: the custom cover whole as
// JSON, its source held to its bounds and never read, each image and the
// thumbnail decoded and encoded again by pkg/reportdesign.
func (s *Server) PutUserReportDesignCustomCover(w http.ResponseWriter, r *http.Request, designId ReportDesignId) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var cc reportdesign.CustomCover
	if !readJSONUpTo(w, r, &cc, int64(reportdesign.MaxDocumentWithAssets)) {
		return
	}
	if err := cc.Validate(); err != nil {
		s.refuseCustomCover(w, r, err)
		return
	}
	stored, err := normalizedCustomCover(cc)
	if err != nil {
		s.refuseCustomCover(w, r, err)
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().SetUserReportDesignCustomCover(r.Context(), storegen.SetUserReportDesignCustomCoverParams{UserID: p.UserID, ID: designId, CustomCover: stored})
	s.answerAssetChange(w, r, row, err, "custom cover: write")
}

// refuseCustomCover answers a custom cover the package would not take: 415
// for an image in no format it reads, 422 naming the field otherwise.
func (s *Server) refuseCustomCover(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, reportdesign.ErrImageFormat) {
		var fe *reportdesign.FieldError
		field := "an image"
		if errors.As(err, &fe) {
			field = fe.Field
		}
		problemUnsupportedImage(w, r, "A custom cover's images are PNG or JPEG ("+field+"). SVG is not accepted: the registry has no way to make one safe, so it takes none.")
		return
	}
	var fe *reportdesign.FieldError
	if !errors.As(err, &fe) {
		fe = &reportdesign.FieldError{Field: "customCover", Message: err.Error()}
	}
	problemValidation(w, r, "The custom cover is not valid.", FieldError{Field: fe.Field, Message: fe.Message})
}

// DeleteUserReportDesignCustomCover implements DELETE
// /user/report-designs/{designId}/custom-cover.
func (s *Server) DeleteUserReportDesignCustomCover(w http.ResponseWriter, r *http.Request, designId ReportDesignId) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().ClearUserReportDesignCustomCover(r.Context(), storegen.ClearUserReportDesignCustomCoverParams{UserID: p.UserID, ID: designId})
	s.answerAssetChange(w, r, row, err, "custom cover: clear")
}

// answerReportDesign answers a row as the API's record, with its images
// when asked.
func (s *Server) answerReportDesign(w http.ResponseWriter, r *http.Request, status int, row storegen.UserReportDesign, withAssets bool) {
	rec, err := s.reportDesignOf(r.Context(), row)
	if err != nil {
		s.log.ErrorContext(r.Context(), "report designs: read", "user", row.UserID, "design", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	d := rec.Design
	if !withAssets {
		d = d.WithoutAssets()
	}
	writeJSON(w, status, reportDesignBody{
		ID: row.ID, Default: row.IsDefault,
		HasLogo: row.Logo != nil, HasCoverImage: row.CoverImage != nil, HasCustomCover: row.CustomCover != nil,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		Design: d.Canonical(),
	})
}

// reportDesignOf reads a row into its design with every image it has. A
// stored document that no longer validates (a rule tightened since it was
// saved) is an error; a stored image that no longer validates is left out
// and logged, and the design still stands.
func (s *Server) reportDesignOf(ctx context.Context, row storegen.UserReportDesign) (ReportDesignEntry, error) {
	d, err := reportdesign.Parse(row.Document)
	if err != nil {
		return ReportDesignEntry{}, err
	}
	try := func(what string, with reportdesign.Design) {
		if err := with.Validate(); err != nil {
			s.log.WarnContext(ctx, "report designs: the stored "+what+" no longer validates; left out", "user", row.UserID, "design", row.ID, "err", err)
			return
		}
		d = with
	}
	if row.Logo != nil {
		with := d
		with.Logo = reportdesign.Logo{PNG: base64.StdEncoding.EncodeToString(row.Logo)}
		try("logo", with)
	}
	if row.CoverImage != nil && row.CoverImageFormat != nil {
		with := d
		with.CoverImage = reportdesign.ImageOf(row.CoverImage, *row.CoverImageFormat)
		try("cover image", with)
	}
	if row.CustomCover != nil {
		with := d
		if err := json.Unmarshal(row.CustomCover, &with.CustomCover); err != nil {
			s.log.WarnContext(ctx, "report designs: the stored custom cover does not decode; left out", "user", row.UserID, "design", row.ID, "err", err)
		} else {
			try("custom cover", with)
		}
	}
	return ReportDesignEntry{ID: row.ID, Default: row.IsDefault, Design: d, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}

// ReportDesignDefault is a person's default design with its images, or nil
// when they have none, which is not Plain: the reader decides what nothing
// means. It is the read behind the extension seam. A stored design that no
// longer validates reads as none, and is logged.
func (s *Server) ReportDesignDefault(ctx context.Context, user uuid.UUID) (*ReportDesignEntry, error) {
	row, err := s.q().GetUserReportDesignDefault(ctx, user)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.reportDesignRecord(ctx, row)
}

// ReportDesignByID is one of a person's designs with its images, or nil
// when the id is not one of theirs.
func (s *Server) ReportDesignByID(ctx context.Context, user, id uuid.UUID) (*ReportDesignEntry, error) {
	row, err := s.q().GetUserReportDesign(ctx, storegen.GetUserReportDesignParams{UserID: user, ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.reportDesignRecord(ctx, row)
}

func (s *Server) reportDesignRecord(ctx context.Context, row storegen.UserReportDesign) (*ReportDesignEntry, error) {
	rec, err := s.reportDesignOf(ctx, row)
	if err != nil {
		s.log.WarnContext(ctx, "report designs: the stored design no longer validates; read as none", "user", row.UserID, "design", row.ID, "err", err)
		return nil, nil
	}
	return &rec, nil
}

// CreateReportDesign adds a design to a person's library on their behalf,
// never as the default: the write behind the extension seam, for a design
// the hosted Report Designer made. The document is validated as a create
// is, its images encoded again; a refusal is a *reportdesign.FieldError,
// and ErrReportDesignsFull past the library's bound.
func (s *Server) CreateReportDesign(ctx context.Context, user uuid.UUID, document []byte) (*ReportDesignEntry, error) {
	d, err := reportdesign.Parse(document)
	if err != nil {
		return nil, err
	}
	row, err := s.createReportDesign(ctx, user, d, false)
	if err != nil {
		return nil, err
	}
	rec, err := s.reportDesignOf(ctx, row)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}
