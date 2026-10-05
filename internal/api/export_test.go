package api

import (
	"time"

	"github.com/google/uuid"
)

// SealTOTPChallengeAt mints a 2FA challenge with the given expiry, for a
// test of the expiry refusal.
func (s *Server) SealTOTPChallengeAt(userID uuid.UUID, provider string, expiresAt time.Time) (string, error) {
	return s.sealTOTPChallengeAt(userID, provider, expiresAt)
}
