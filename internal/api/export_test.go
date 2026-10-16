package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// SealTOTPChallengeAt mints a 2FA challenge with the given expiry, for a
// test of the expiry refusal.
func (s *Server) SealTOTPChallengeAt(userID uuid.UUID, provider string, expiresAt time.Time) (string, error) {
	return s.sealTOTPChallengeAt(userID, provider, expiresAt)
}

// MintRememberedBrowser is mintRememberedBrowser, for the tests of its
// evidence rules.
func (s *Server) MintRememberedBrowser(r *http.Request, userID uuid.UUID, amr []string, authTime time.Time, detail map[string]any) (string, time.Duration, error) {
	return s.mintRememberedBrowser(r, userID, amr, authTime, detail)
}
