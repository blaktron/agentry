package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// GetUserReportSettings implements GET /user/report-settings (agentry#989):
// the theme the caller's PDF reports take, a profile setting (plan
// scratch-and-pdf-reports.md D18). No row reads back with no theme, which
// the CLI tells apart from Plain (D21).
func (s *Server) GetUserReportSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().GetUserReportSettings(r.Context(), p.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, ReportSettings{})
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "report settings: read", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, reportSettingsToAPI(row))
}

// UpdateUserReportSettings implements PUT /user/report-settings: a full
// replace, so a body with no theme clears the choice. Only a built-in
// theme's name is accepted; a design standard, when there is one, is one
// more value of ReportTheme.
func (s *Server) UpdateUserReportSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req ReportSettings
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r.Context())
	if req.Theme == nil {
		if _, err := s.q().DeleteUserReportSettings(r.Context(), p.UserID); err != nil {
			s.log.ErrorContext(r.Context(), "report settings: clear", "user", p.UserID, "err", err)
			problemInternal(w, r)
			return
		}
		writeJSON(w, http.StatusOK, ReportSettings{})
		return
	}
	if !req.Theme.Valid() {
		problemValidation(w, r, "Unknown report theme.", FieldError{
			Field: "theme", Message: "must be one of plain, formal, brief, technical, letter",
		})
		return
	}
	row, err := s.q().UpsertUserReportSettings(r.Context(), storegen.UpsertUserReportSettingsParams{
		UserID: p.UserID, Theme: string(*req.Theme),
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "report settings: write", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, reportSettingsToAPI(row))
}

func reportSettingsToAPI(row storegen.UserReportSetting) ReportSettings {
	theme := ReportTheme(row.Theme)
	return ReportSettings{Theme: &theme}
}
