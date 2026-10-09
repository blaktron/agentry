package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/reportdesign"
)

// GetUserReportSettings implements GET /user/report-settings (agentry#989,
// agentry#1024): the report design the caller's PDF reports take, a profile
// setting (plan report-designs.md D11). No row reads back with no design,
// which a client tells apart from Plain (DEV-227).
func (s *Server) GetUserReportSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	design, err := s.ReportDesign(r.Context(), p.UserID)
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

// UpdateUserReportSettings implements PUT /user/report-settings: a full
// replace, so a body with no design (or a null one) clears the choice. The
// design is parsed by pkg/reportdesign, which refuses an unknown key, a
// missing field, a name off a closed list, a colour that fails the contrast
// rule and an over-size document (plan invariants 2, 3, 7); the field it
// names comes back as design.<path>. The canonical document is what is
// stored and answered.
func (s *Server) UpdateUserReportSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
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
	canonical := d.Canonical()
	if _, err := s.q().UpsertUserReportSettings(r.Context(), storegen.UpsertUserReportSettingsParams{
		UserID: p.UserID, Design: canonical,
	}); err != nil {
		s.log.ErrorContext(r.Context(), "report settings: write", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, reportSettingsBody{Design: canonical})
}

// ReportDesign is a person's report design as its canonical document, or nil
// when they never chose one, which is not Plain: the reader decides what
// nothing means (DEV-227). It is the read behind GET /user/report-settings
// and the extension seam (pkg/extension ReportSettings, agentry#1015). A
// stored design that no longer validates (a rule tightened since it was
// saved) reads as never chosen, and is logged.
func (s *Server) ReportDesign(ctx context.Context, user uuid.UUID) ([]byte, error) {
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
	return d.Canonical(), nil
}

// ReportTheme is the built-in theme a person's design started from (its
// basedOn), or "" when they never chose one. It is transitional: the hosted
// job still carries a theme's name to a sandbox host whose CLI knows the
// names of the plan this one replaced (agentry-enterprise#470), and drops a
// name it does not have. agentry-enterprise#479 (M6) moves the job to the
// design and removes this read.
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
