package auth

import (
	"strings"
	"time"
)

// SyntheticAddressSuffix ends the address a social sign-in with no email
// is given (handlers_social_login.go): a placeholder that keeps the users
// table's NOT NULL/UNIQUE contract and was never anybody's mailbox.
const SyntheticAddressSuffix = ".social.local"

// Unactivated reports whether an account is unactivated: its address is unconfirmed and
// is a real address a link can be sent to. An account with only a
// synthetic placeholder has nothing to activate, so it is never locked
// into read-only by a mail it cannot receive; the gates that need a
// verified address (publishing, organizations) still refuse it.
func Unactivated(emailVerifiedAt *time.Time, email string) bool {
	return emailVerifiedAt == nil && !SyntheticAddress(email)
}

// SyntheticAddress reports the placeholder address of an account that
// signed in without one.
func SyntheticAddress(email string) bool {
	return strings.HasSuffix(strings.ToLower(email), SyntheticAddressSuffix)
}
