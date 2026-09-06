package notify

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Notification settings (agentry#190): which of the registry's mails a
// person wants. A user with no row has never changed anything, and gets
// every mail — what every account received before the setting existed.

// Kind names one class of notification a person can switch off.
type Kind string

const (
	KindDependencyAlert Kind = "dependencyAlerts"
	KindQuarantine      Kind = "quarantine"
	KindReviewDecision  Kind = "reviewDecisions"
	KindAdvisory        Kind = "advisories"
	KindOrgInvite       Kind = "orgInvites"
)

// Defaults is the settings row a user without one is treated as having.
func Defaults(userID uuid.UUID) storegen.UserNotificationSetting {
	return storegen.UserNotificationSetting{
		UserID: userID, EmailDependencyAlerts: true, EmailQuarantine: true, EmailReviewDecisions: true,
		EmailAdvisories: true, EmailOrgInvites: true, WebDependencyAlerts: true,
	}
}

// EmailAllowed reports whether the row permits a mail of the given kind.
// Unknown kinds are allowed: a new mail class is opt-out, never lost.
func EmailAllowed(row storegen.UserNotificationSetting, kind Kind) bool {
	switch kind {
	case KindDependencyAlert:
		return row.EmailDependencyAlerts
	case KindQuarantine:
		return row.EmailQuarantine
	case KindReviewDecision:
		return row.EmailReviewDecisions
	case KindAdvisory:
		return row.EmailAdvisories
	case KindOrgInvite:
		return row.EmailOrgInvites
	}
	return true
}

// Settings loads a user's row, or the defaults when there is none.
func Settings(ctx context.Context, q *storegen.Queries, userID uuid.UUID) (storegen.UserNotificationSetting, error) {
	row, err := q.GetUserNotificationSettings(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Defaults(userID), nil
		}
		return Defaults(userID), err
	}
	return row, nil
}

// AllowsEmail is Settings + EmailAllowed with the fail-open a lookup error
// deserves: a broken settings read must not silence a security mail.
func AllowsEmail(ctx context.Context, q *storegen.Queries, userID uuid.UUID, kind Kind) bool {
	row, err := Settings(ctx, q, userID)
	if err != nil {
		return true
	}
	return EmailAllowed(row, kind)
}
