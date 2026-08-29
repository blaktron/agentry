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
	// AgentQuarantined tells an author that a version they published has been
	// pulled by a rescan (§8.7: author notification is one of the three
	// notification paths, alongside the org webhook and the advisory).
	AgentQuarantined(ctx context.Context, n QuarantineNotice) error
}

// QuarantineNotice is what an author is told when a published version is
// quarantined. It deliberately carries no finding excerpts: the reason is a
// summary, and the detail lives on the report where it can be authorized.
type QuarantineNotice struct {
	ToEmail string
	// Agent is "namespace/name".
	Agent    string
	Version  string
	Severity string
	Reason   string
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

// AgentQuarantined implements Notifier. Logged at warn: on a self-host
// instance without SMTP this line is the only trace that an author was
// supposed to hear about a quarantine.
func (n LogNotifier) AgentQuarantined(_ context.Context, notice QuarantineNotice) error {
	log := n.Log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("notify: agent quarantined (author notification)",
		"to", notice.ToEmail, "agent", notice.Agent, "version", notice.Version,
		"severity", notice.Severity, "reason", notice.Reason)
	return nil
}
