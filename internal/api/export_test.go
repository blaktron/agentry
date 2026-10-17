package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// MintRememberedBrowser is mintRememberedBrowser, for the tests of its
// evidence rules.
func (s *Server) MintRememberedBrowser(r *http.Request, userID uuid.UUID, amr []string, authTime time.Time, detail map[string]any) (string, time.Duration, error) {
	return s.mintRememberedBrowser(r, userID, amr, authTime, detail)
}
