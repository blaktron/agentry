// Package logevent is the vocabulary of the log contract (docs/logging.md,
// plan log-stack.md §5.2): the `event` names a line carries when it is a
// signal rather than narration. A dashboard or an alert keys on these
// names, never on message text, so every name is a constant here, every
// constant is documented, and a test keeps the code, this catalog and the
// docs page in step.
package logevent

import "log/slog"

// Key is the attribute the name is written under.
const Key = "event"

// Event is one catalogued signal name: dotted, lowercase, stable.
type Event string

const (
	// HTTPRequest is the access line: one per request the server handled.
	HTTPRequest Event = "http.request"
	// HTTPRateLimited is a request refused by a rate class.
	HTTPRateLimited Event = "http.rate_limited"
	// AuthLoginFailed is a native sign-in that failed.
	AuthLoginFailed Event = "auth.login_failed"
	// AuthSocialRejected is a social or directory sign-in the server rejected.
	AuthSocialRejected Event = "auth.social_rejected"
	// SAMLStateUnavailable is a SAML login refused because the shared state
	// behind it could not be read or written (agentry#414).
	SAMLStateUnavailable Event = "saml.state_unavailable"
	// TOTPChallengeUnavailable is a 2FA social login's second leg refused
	// because its challenge could not be recorded as consumed (agentry#457).
	TOTPChallengeUnavailable Event = "auth.totp_challenge_unavailable"
	// SSRFRefused is an outbound target the private-range guard refused.
	SSRFRefused Event = "ssrf.refused"
	// GateVerdict is the gate deciding a version: published, rejected or
	// routed to review.
	GateVerdict Event = "gate.verdict"
	// GateError is a version routed to review because the platform's own
	// machinery failed — a stage error, an unusable policy, the watchdog.
	GateError Event = "gate.error"
	// ScanStage is one scanner stage finishing, with its outcome.
	ScanStage Event = "scan.stage"
	// FailOpenAuditStreamDrop is an audit archive record dropped on a full
	// buffer (DEV-020).
	FailOpenAuditStreamDrop Event = "failopen.audit_stream_drop"
	// FailOpenHistoryNotScanned is a git history the S2 stage could not
	// scan (DEV-026.3).
	FailOpenHistoryNotScanned Event = "failopen.history_not_scanned"
	// FailOpenOSVNotChecked is a dependency set S7 did not check against OSV.
	FailOpenOSVNotChecked Event = "failopen.osv_not_checked"
	// FailOpenOSVError is an OSV lookup that errored (DEV-026.3).
	FailOpenOSVError Event = "failopen.osv_error"
	// FailOpenDirectoryErasure is an account erasure whose directory half
	// did not happen after its retries (agentry#499).
	FailOpenDirectoryErasure Event = "failopen.directory_erasure"
	// GitPushRefused is a submission the git door refused after a tag push
	// (agentry#322).
	GitPushRefused Event = "git.push_refused"
	// MailSuppressed is a notification withheld from an unverified address.
	MailSuppressed Event = "mail.suppressed"
	// WebhookDelivered is one webhook delivery attempt finishing, with its
	// outcome.
	WebhookDelivered Event = "webhook.delivered"
	// ModelInput is one call to a model-input route finishing: a scan of
	// text a model is about to read, or a brokered web search, with its
	// verdict and counts, never the text, the query or an address.
	ModelInput Event = "model_input.call"
)

// AuditPrefix is what an audit action's mirror line is named under: the
// audit action catalog (internal/audit) supplies the rest.
const AuditPrefix = "audit."

// Audit is the mirror line's event for one audit action.
func Audit(action string) Event { return Event(AuditPrefix + action) }

// All lists every catalogued name, for the completeness test and the docs.
var All = []Event{
	HTTPRequest, HTTPRateLimited, AuthLoginFailed, AuthSocialRejected, SAMLStateUnavailable, TOTPChallengeUnavailable, SSRFRefused,
	GateVerdict, GateError, ScanStage,
	FailOpenAuditStreamDrop, FailOpenHistoryNotScanned, FailOpenOSVNotChecked, FailOpenOSVError, FailOpenDirectoryErasure,
	GitPushRefused, MailSuppressed, WebhookDelivered, ModelInput,
}

// Attr is the attribute to pass to a slog call.
func (e Event) Attr() slog.Attr { return slog.String(Key, string(e)) }

// String implements fmt.Stringer.
func (e Event) String() string { return string(e) }
