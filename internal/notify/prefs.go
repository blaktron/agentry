package notify

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/logevent"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Notification settings (agentry#190): which of the registry's mails a
// person wants. A user with no row has never changed anything, and gets
// every mail — what every account received before the setting existed.
//
// Before any setting is read, the address itself has to be one the registry
// confirmed (agentry#299): users.email_verified_at is set by the verify-email
// link, by an IdP's email_verified claim on SSO/social JIT, and by SCIM, and
// an address without it gets no mail of any kind. The verification mail is
// the one exception — it is the mail that does the confirming — and it does
// not pass through here. Bounces from test accounts with invented addresses
// are what this rule exists to stop.

// Kind names one class of notification a person can switch off.
type Kind string

const (
	KindDependencyAlert Kind = "dependencyAlerts"
	KindQuarantine      Kind = "quarantine"
	KindReviewDecision  Kind = "reviewDecisions"
	KindAdvisory        Kind = "advisories"
	KindOrgInvite       Kind = "orgInvites"
	// KindBilling is the closed build's billing mail, sent through the
	// extension seam (agentry#366): a checkout confirmed, a payment
	// failed, an organization restricted, seats reached, "your
	// organization covers you". The core sends none itself; the kind is
	// here so the switch, the default and the rule are the core's.
	KindBilling Kind = "billing"
)

// Defaults is the settings row a user without one is treated as having.
func Defaults(userID uuid.UUID) storegen.UserNotificationSetting {
	return storegen.UserNotificationSetting{
		UserID: userID, EmailDependencyAlerts: true, EmailQuarantine: true, EmailReviewDecisions: true,
		EmailAdvisories: true, EmailOrgInvites: true, EmailBilling: true, WebDependencyAlerts: true,
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
	case KindBilling:
		return row.EmailBilling
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

// EmailPermitted is the whole decision for one mail: the address must be
// verified and the kind switched on. It is pure so the rule is testable
// without a database; AllowsEmail supplies the two facts.
func EmailPermitted(verified bool, row storegen.UserNotificationSetting, kind Kind) bool {
	return verified && EmailAllowed(row, kind)
}

// AllowsEmail reports whether a mail of the given kind may go to the user.
// The two halves fail in opposite directions on purpose: a user row that
// cannot be read is treated as unverified (no mail — the address is the
// thing in doubt), while a settings row that cannot be read is treated as
// the defaults (mail — a broken preference read must not silence a security
// notice). A suppression for an unverified address is logged with the user
// id and the kind, never the address; a nil log means the default logger,
// as for the notifiers themselves.
func AllowsEmail(ctx context.Context, q *storegen.Queries, log *slog.Logger, userID uuid.UUID, kind Kind) bool {
	if log == nil {
		log = slog.Default()
	}
	u, err := q.GetUserByID(ctx, userID)
	if err != nil {
		log.WarnContext(ctx, "notify: suppressed, user row unreadable", logevent.MailSuppressed.Attr(), "user", userID, "kind", kind, "err", err)
		return false
	}
	if u.EmailVerifiedAt == nil {
		log.InfoContext(ctx, "notify: suppressed, address not verified", logevent.MailSuppressed.Attr(), "user", userID, "kind", kind)
		return false
	}
	row, err := Settings(ctx, q, userID)
	if err != nil {
		row = Defaults(userID)
	}
	return EmailPermitted(true, row, kind)
}
