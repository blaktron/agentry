// Package notify sends user-facing notifications (email in v1). M1 ships the
// interface plus a log-based dev implementation; SMTP (mailpit/SES) lands
// with the flows that need real delivery (M6/M8).
package notify

import (
	"context"
	"log/slog"
)

// Notifier delivers transactional notifications.
type Notifier interface {
	// EmailVerification sends the address-confirmation message. token is the
	// one-time secret the user posts back to /auth/verify-email.
	EmailVerification(ctx context.Context, toEmail, token string) error
}

// LogNotifier writes notifications to the log (dev/self-host default until
// SMTP is configured). Tokens intentionally appear ONLY at debug level.
type LogNotifier struct {
	Log *slog.Logger
}

// EmailVerification implements Notifier.
func (n LogNotifier) EmailVerification(_ context.Context, toEmail, token string) error {
	log := n.Log
	if log == nil {
		log = slog.Default()
	}
	log.Info("notify: email verification queued", "to", toEmail)
	log.Debug("notify: email verification token (dev only)", "to", toEmail, "token", token)
	return nil
}
