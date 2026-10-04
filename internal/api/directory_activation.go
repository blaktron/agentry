package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth/social"
)

// The directory reads activation from the registry (agentry#869). The
// subject binds the answer to the signed-in identity, and the address must
// still match: confirmation of an old address never confirms a replacement.
func (s *Server) directoryEmailVerification(w http.ResponseWriter, r *http.Request) {
	if !s.allowDirectoryCheck(w, r) {
		return
	}
	var req struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, directoryTrustBodyLimit)).Decode(&req); err != nil || req.Sub == "" || req.Email == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.st == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	ident, err := s.q().GetSocialIdentity(r.Context(), social.ProviderAuthentik+":"+req.Sub)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, map[string]bool{"verified": false})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	u, err := s.q().GetUserByID(r.Context(), ident.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, map[string]bool{"verified": false})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	verified := u.State == "active" && u.EmailVerifiedAt != nil && strings.EqualFold(u.Email, req.Email)
	writeJSON(w, http.StatusOK, map[string]bool{"verified": verified})
}
