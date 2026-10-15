package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/reportdesign"
)

// GetUserReportSettings implements GET /user/report-settings: the report
// design the caller's PDF reports take, a profile
// setting. No row reads back with no design,
// which a client tells apart from Plain. The logo comes only with
// include=logo: a client built before logos refuses a design
// with a key it does not know, and would then run without the design at all.
func (s *Server) GetUserReportSettings(w http.ResponseWriter, r *http.Request, params GetUserReportSettingsParams) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	withLogo, ok := includeLogo(w, r, params.Include)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	design, err := s.reportDesign(r.Context(), p.UserID, withLogo)
	if err != nil {
		s.log.ErrorContext(r.Context(), "report settings: read", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, reportSettingsBody{Design: design})
}

// reportSettingsBody is ReportSettings on the wire, with the design as the
// canonical document pkg/reportdesign wrote rather than the generated type,
// so what the server answers is exactly what it validated.
type reportSettingsBody struct {
	Design json.RawMessage `json:"design,omitempty"`
}

// includeLogo reads the include parameter, absent or "logo", into whether
// the answer carries the logo; ok is false once a bad value was answered.
func includeLogo(w http.ResponseWriter, r *http.Request, include *ReportSettingsInclude) (withLogo, ok bool) {
	switch {
	case include == nil:
		return false, true
	case *include == ReportSettingsIncludeLogo:
		return true, true
	}
	problemBadRequest(w, r, "include takes only logo.")
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

// UpdateUserReportSettings implements PUT /user/report-settings: a full
// replace, so a body with no design (or a null one) clears the choice. The
// design is parsed by pkg/reportdesign, which refuses an unknown key, a
// missing field, a name off a closed list, a colour that fails the contrast
// rule and an over-size document; the field it
// names comes back as design.<path>. The canonical document is what is
// stored and answered. The logo is stored beside the design:
// a design that carries one replaces the stored logo with NormalizeLogo's
// encoding of it, and a design that carries none leaves a stored logo as it
// is, so a client that does not know logos cannot drop one by saving.
func (s *Server) UpdateUserReportSettings(w http.ResponseWriter, r *http.Request, params UpdateUserReportSettingsParams) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	withLogo, ok := includeLogo(w, r, params.Include)
	if !ok {
		return
	}
	var req reportSettingsBody
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r.Context())
	if len(req.Design) == 0 || string(req.Design) == "null" {
		if _, err := s.q().DeleteUserReportSettings(r.Context(), p.UserID); err != nil {
			s.log.ErrorContext(r.Context(), "report settings: clear", "user", p.UserID, "err", err)
			problemInternal(w, r)
			return
		}
		writeJSON(w, http.StatusOK, reportSettingsBody{})
		return
	}
	d, err := reportdesign.Parse(req.Design)
	if err != nil {
		var fe *reportdesign.FieldError
		if !errors.As(err, &fe) {
			fe = &reportdesign.FieldError{Message: err.Error()}
		}
		field := "design"
		if fe.Field != "" {
			field += "." + fe.Field
		}
		problemValidation(w, r, "The report design is not valid.", FieldError{Field: field, Message: fe.Message})
		return
	}
	logo := d.Logo
	d.Logo = reportdesign.Logo{}
	if logo == (reportdesign.Logo{}) {
		_, err = s.q().UpsertUserReportSettings(r.Context(), storegen.UpsertUserReportSettingsParams{
			UserID: p.UserID, Design: d.Canonical(),
		})
	} else {
		// Parse held it to a PNG within the bounds; what is stored is
		// still this process's own encoding of its pixels.
		var png []byte
		png, err = normalizedLogo(logo)
		if err != nil {
			problemValidation(w, r, "The report design is not valid.", FieldError{Field: "design.logo.png", Message: fieldMessage(err)})
			return
		}
		_, err = s.q().UpsertUserReportSettingsWithLogo(r.Context(), storegen.UpsertUserReportSettingsWithLogoParams{
			UserID: p.UserID, Design: d.Canonical(), Logo: png,
		})
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "report settings: write", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	s.answerReportSettings(w, r, p.UserID, withLogo)
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

// answerReportSettings answers the caller's settings as they now are.
func (s *Server) answerReportSettings(w http.ResponseWriter, r *http.Request, user uuid.UUID, withLogo bool) {
	design, err := s.reportDesign(r.Context(), user, withLogo)
	if err != nil {
		s.log.ErrorContext(r.Context(), "report settings: read", "user", user, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, reportSettingsBody{Design: design})
}

// PutUserReportLogo implements PUT /user/report-settings/logo: one
// multipart part named file, PNG or JPEG, at
// most 512 KB, decoded, scaled down and encoded again as PNG by
// pkg/reportdesign, so only its pixels are kept. A logo travels with a
// design, so with no design saved it is 409. Read the same way as the
// organization's logo (readUploadPart), at this setting's own bound.
func (s *Server) PutUserReportLogo(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	upload, err := readUploadPart(w, r, reportdesign.MaxLogoUploadBytes)
	if err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.Is(err, errLogoTooLarge), errors.As(err, &mbe):
			problemUploadTooLarge(w, r, "A logo is at most 512 KB.")
		default:
			problemBadRequest(w, r, "Send the logo as one multipart part named file.")
		}
		return
	}
	logo, err := reportdesign.NormalizeLogo(upload)
	if err != nil {
		switch {
		case errors.Is(err, reportdesign.ErrLogoTooLarge):
			problemUploadTooLarge(w, r, "This image is too large for a logo: "+fieldMessage(err)+".")
		default:
			problemUnsupportedImage(w, r, "A logo is a PNG or a JPEG. SVG is not accepted: the registry has no way to make one safe, so it takes none.")
		}
		return
	}
	png, err := logo.Decode()
	if err != nil {
		s.log.ErrorContext(r.Context(), "report logo: encode", "err", err)
		problemInternal(w, r)
		return
	}
	p := principalFrom(r.Context())
	if _, err := s.q().SetUserReportLogo(r.Context(), storegen.SetUserReportLogoParams{UserID: p.UserID, Logo: png}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemConflict(w, r, "Save a report design first: a logo is part of one.")
			return
		}
		s.log.ErrorContext(r.Context(), "report logo: write", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	s.answerReportSettings(w, r, p.UserID, true)
}

// DeleteUserReportLogo implements DELETE /user/report-settings/logo:
// the design stays; removing no logo is done.
func (s *Server) DeleteUserReportLogo(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if _, err := s.q().ClearUserReportLogo(r.Context(), p.UserID); err != nil {
		s.log.ErrorContext(r.Context(), "report logo: clear", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	s.answerReportSettings(w, r, p.UserID, true)
}

// ReportDesign is a person's report design as its canonical document,
// without its logo, or nil when they never chose one, which is not Plain:
// the reader decides what nothing means. It is the read behind GET
// /user/report-settings and the extension seam (pkg/extension
// ReportSettings). A stored design that no longer validates (a
// rule tightened since it was saved) reads as never chosen, and is logged.
func (s *Server) ReportDesign(ctx context.Context, user uuid.UUID) ([]byte, error) {
	return s.reportDesign(ctx, user, false)
}

// ReportDesignWithLogo is ReportDesign with the person's logo in it, when
// they have one, for a reader that draws it.
func (s *Server) ReportDesignWithLogo(ctx context.Context, user uuid.UUID) ([]byte, error) {
	return s.reportDesign(ctx, user, true)
}

// reportDesign reads the design, and with withLogo its logo into it. A
// stored logo that no longer validates is left out and logged; the design
// still stands.
func (s *Server) reportDesign(ctx context.Context, user uuid.UUID, withLogo bool) ([]byte, error) {
	row, err := s.q().GetUserReportSettings(ctx, user)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d, err := reportdesign.Parse(row.Design)
	if err != nil {
		s.log.WarnContext(ctx, "report settings: the stored design no longer validates; read as never chosen", "user", user, "err", err)
		return nil, nil
	}
	if withLogo && row.Logo != nil {
		with := d
		with.Logo = reportdesign.Logo{PNG: base64.StdEncoding.EncodeToString(row.Logo)}
		if err := with.Validate(); err != nil {
			s.log.WarnContext(ctx, "report settings: the stored logo no longer validates; left out", "user", user, "err", err)
		} else {
			d = with
		}
	}
	return d.Canonical(), nil
}

// ReportTheme is the built-in theme a person's design started from (its
// basedOn), or "" when they never chose one. The hosted job carries a
// theme's name to a sandbox host whose CLI knows theme names, and drops a
// name it does not have.
func (s *Server) ReportTheme(ctx context.Context, user uuid.UUID) (string, error) {
	design, err := s.ReportDesign(ctx, user)
	if err != nil || design == nil {
		return "", err
	}
	d, err := reportdesign.Parse(design)
	if err != nil {
		return "", err
	}
	return d.BasedOn, nil
}
