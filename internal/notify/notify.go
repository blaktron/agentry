// Package notify sends user-facing notifications (email in v1).
//
// Two implementations: LogNotifier (the default — a fresh install says what it
// would have sent rather than pretending to send it) and SMTPNotifier, which
// speaks to mailpit on :1025 in the compose dev stack and to SES's SMTP
// endpoint on AWS (§13.4).
//
// Message bodies follow §1.6.3: they say what was found and what happens next.
// Nothing here calls an agent safe, secure, or verified — scanning reduces
// risk, it does not prove absence of it, and a notification is exactly where
// that overclaim would be most tempting and most damaging.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Notifier delivers transactional notifications. Every method returns an error
// only for a delivery failure the caller could act on; callers treat
// notification failure as non-fatal to the state change that triggered it.
type Notifier interface {
	// EmailVerification sends the address-confirmation message. token is the
	// one-time secret the user posts back to /auth/verify-email.
	EmailVerification(ctx context.Context, toEmail, token string) error
	// AgentQuarantined tells an author that a version they published has been
	// pulled by a rescan (§8.7: author notification is one of the three
	// notification paths, alongside the org webhook and the advisory).
	AgentQuarantined(ctx context.Context, n QuarantineNotice) error
	// ReviewDecided tells an author the outcome of a review (§7, §8.7).
	ReviewDecided(ctx context.Context, n ReviewNotice) error
	// AdvisoryPublished tells an author that an advisory naming their agent
	// is now public (§8.7).
	AdvisoryPublished(ctx context.Context, n AdvisoryNotice) error
	// OrgInvite tells someone they have been added to an organisation
	// (§13.4 lists invites among the transactional mails).
	OrgInvite(ctx context.Context, n InviteNotice) error
	// MCPDependencyAlert tells an author that a published version of theirs
	// declares an MCP server version with a newly known high or critical
	// vulnerability, and that the fix is a new version (agentry#177).
	MCPDependencyAlert(ctx context.Context, n MCPDependencyAlertNotice) error
}

// MCPDependencyAlertNotice is a dependency alert delivered to the version's
// author.
type MCPDependencyAlertNotice struct {
	ToEmail string
	// Agent is "namespace/name"; Version the affected published version.
	Agent   string
	Version string
	// Server is the declared server, "npm:pkg@1.2.3" / "pypi:pkg@1.2.3".
	Server   string
	Severity string
	// Advisories are the advisory ids (GHSA/CVE) behind the alert.
	Advisories []string
	// FixedIn lists the server versions the advisories name as fixed.
	FixedIn []string
	// AgentURL points at the agent page.
	AgentURL string
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
	// ReportURL points at the full report, where the findings are shown to
	// someone the authorization check has already passed.
	ReportURL string
}

// ReviewNotice is a review verdict delivered to the version's author.
type ReviewNotice struct {
	ToEmail string
	Agent   string
	Version string
	// Decision is the §7 outcome the version reached: published | rejected |
	// yanked | needs_review. `yanked` arrives when a reviewer rejects an
	// already-quarantined version, which cannot go to `rejected` because that
	// edge does not exist (internal/api/handlers_reviews.go).
	Decision string
	// Reviewer is the deciding reviewer's handle, when the decision was made
	// by a human rather than by the automated gate.
	Reviewer string
	// Rationale is the reviewer's stated reason (§1.6.2 transparency).
	Rationale string
	ReportURL string
}

// AdvisoryNotice announces a published advisory.
type AdvisoryNotice struct {
	ToEmail  string
	Agent    string
	Severity string
	Summary  string
	// AdvisoryURL is the public advisory page.
	AdvisoryURL string
}

// InviteNotice announces org membership.
type InviteNotice struct {
	ToEmail string
	Org     string
	// Role is the granted org role.
	Role string
	// InvitedBy is the acting admin's handle.
	InvitedBy string
	// URL is where the recipient goes to see the org.
	URL string
}

// Options selects and configures the notifier.
type Options struct {
	// Kind is log | smtp. Empty means log.
	Kind string
	// BaseURL is the public origin, used to build links in message bodies.
	BaseURL string
	// Registry is the deployment's display name in message subjects.
	Registry string
	SMTP     SMTPOptions
	Log      *slog.Logger
	// Links are the browser destinations this deployment resolved (DEV-091):
	// Dashboard is where "see your dashboard" points; VerifyEmail builds the
	// address-verification link for a token. Unset falls back to the legacy
	// site paths under BaseURL.
	Links Links
}

// Links carries the resolved browser destinations for the renderer.
type Links struct {
	Dashboard   string
	VerifyEmail func(token string) string
}

// New builds the configured notifier.
func New(opt Options) (Notifier, error) {
	reg := opt.Registry
	if reg == "" {
		reg = "Agentry"
	}
	switch opt.Kind {
	case "", "log":
		return LogNotifier{Log: opt.Log}, nil
	case "smtp":
		n, err := NewSMTP(opt.SMTP, reg, opt.BaseURL, opt.Log)
		if err != nil {
			return nil, err
		}
		n.render.dashboard = opt.Links.Dashboard
		n.render.verifyEmail = opt.Links.VerifyEmail
		return n, nil
	default:
		return nil, fmt.Errorf("notify: unknown kind %q (want log|smtp)", opt.Kind)
	}
}

// LogNotifier writes notifications to the log (dev/self-host default until
// SMTP is configured). Tokens intentionally appear ONLY at debug level.
type LogNotifier struct {
	Log *slog.Logger
}

func (n LogNotifier) logger() *slog.Logger {
	if n.Log == nil {
		return slog.Default()
	}
	return n.Log
}

// EmailVerification implements Notifier.
func (n LogNotifier) EmailVerification(_ context.Context, toEmail, token string) error {
	log := n.logger()
	log.Info("notify: email verification queued", "to", toEmail)
	log.Debug("notify: email verification token (dev only)", "to", toEmail, "token", token)
	return nil
}

// AgentQuarantined implements Notifier. Logged at warn: on a self-host
// instance without SMTP this line is the only trace that an author was
// supposed to hear about a quarantine.
func (n LogNotifier) AgentQuarantined(_ context.Context, notice QuarantineNotice) error {
	n.logger().Warn("notify: agent quarantined (author notification)",
		"to", notice.ToEmail, "agent", notice.Agent, "version", notice.Version,
		"severity", notice.Severity, "reason", notice.Reason)
	return nil
}

// ReviewDecided implements Notifier.
func (n LogNotifier) ReviewDecided(_ context.Context, notice ReviewNotice) error {
	n.logger().Info("notify: review decided (author notification)",
		"to", notice.ToEmail, "agent", notice.Agent, "version", notice.Version,
		"decision", notice.Decision, "reviewer", notice.Reviewer)
	return nil
}

// AdvisoryPublished implements Notifier.
func (n LogNotifier) AdvisoryPublished(_ context.Context, notice AdvisoryNotice) error {
	n.logger().Warn("notify: advisory published (author notification)",
		"to", notice.ToEmail, "agent", notice.Agent, "severity", notice.Severity)
	return nil
}

// MCPDependencyAlert implements Notifier.
func (n LogNotifier) MCPDependencyAlert(_ context.Context, notice MCPDependencyAlertNotice) error {
	n.logger().Warn("notify: MCP dependency alert (author notification)",
		"to", notice.ToEmail, "agent", notice.Agent, "version", notice.Version,
		"server", notice.Server, "severity", notice.Severity, "advisories", notice.Advisories)
	return nil
}

// OrgInvite implements Notifier.
func (n LogNotifier) OrgInvite(_ context.Context, notice InviteNotice) error {
	n.logger().Info("notify: org invite",
		"to", notice.ToEmail, "org", notice.Org, "role", notice.Role)
	return nil
}

// message is a rendered plain-text email.
type message struct {
	Subject string
	Body    string
}

// renderer builds message bodies. Held apart from the transport so the
// templates are testable without a socket, and so LogNotifier could adopt them
// later without moving code.
type renderer struct {
	registry string
	baseURL  string
	// dashboard and verifyEmail are the browser destinations the server
	// resolved for this deployment (a site in front of it, or its own /ui/
	// pages — DEV-091); when unset the legacy site paths under baseURL are
	// used, so a bare renderer still produces the same links as before.
	dashboard   string
	verifyEmail func(token string) string
}

func (r renderer) link(path string) string {
	if r.baseURL == "" {
		return ""
	}
	return strings.TrimSuffix(r.baseURL, "/") + path
}

// footer closes every message the same way: who sent it, why it arrived and
// that a reply goes nowhere. Kept short — a wall of legal boilerplate on a
// security notice buries the part that matters. "the account it concerns" is
// as far as one line can honestly go for seven different mails: the address
// on the account is the only thing every one of them has in common.
func (r renderer) footer() string {
	return "\n--\n" + r.registry + " sent this automatically to the address\n" +
		"on the account it concerns. Do not reply to this message.\n"
}

func (r renderer) verification(token string) message {
	url := r.link("/auth/verify-email?token=" + token)
	if r.verifyEmail != nil {
		url = r.verifyEmail(token)
	}
	body := "Confirm this address to finish setting up your " + r.registry + " account.\n\n"
	// The old close promised "the address will not be used", which nothing in
	// the server keeps: no job deletes an unconfirmed account, the row keeps
	// the address, and a later membership grant mails it. What IS true is the
	// gate — registry.CreateAgent refuses an unverified principal (§19) — so
	// say that instead, and say it once rather than reassure.
	once := "The link works once."
	if url != "" {
		body += url + "\n\n"
	} else {
		body += "Verification code: " + token + "\n\n"
		once = "The code works once."
	}
	body += once + " Until this address is confirmed, the account cannot\n" +
		"create a BriefAgent or publish a version.\n\n" +
		"If you did not create this account, ignore this message.\n"
	return message{Subject: r.registry + ": confirm your email address", Body: body + r.footer()}
}

func (r renderer) quarantine(n QuarantineNotice) message {
	// §8.7: a rescan under a newer ruleset found something in an already
	// published version. Say what happened and what it means for installs;
	// do not editorialise about severity beyond the label the scan assigned.
	body := "A rescan of " + n.Agent + " " + n.Version + " under a newer ruleset produced a\n" +
		"finding at " + severityLine(n.Severity) + " severity. The version is now quarantined.\n\n" +
		// The mechanisms, not a description of a page: a quarantined version
		// is absent from the resolution set (versions.sql ListResolvableVersions
		// selects published and yanked only), so an exact pin fails too —
		// which is the difference from a yank — and a download answers 409
		// (handlers_version_files.go).
		"What that means: the version no longer resolves for new installs, not\n" +
		"even by exact version, and a download of it answers 409. Copies already\n" +
		"installed elsewhere are not reached by this change. Your other\n" +
		"published versions still resolve.\n\n"
	if n.Reason != "" {
		body += "Reason recorded: " + n.Reason + "\n\n"
	}
	if u := firstNonEmpty(n.ReportURL, r.link("/agents/"+n.Agent+"/versions/"+n.Version+"/report")); u != "" {
		body += "Report card (findings, ruleset version, scan date):\n" + u + "\n\n"
	}
	// The old close told the author to "reply through the report page", a path
	// that does not exist: there is no appeal endpoint, and the platform
	// review queue is staff-only (handlers_reviews.go reviewItemAccess), so
	// the author cannot even read the item. State the two outcomes a reviewer
	// can reach from quarantined instead, and state the missing path plainly.
	body += "A platform reviewer now has the version and can restore it to\n" +
		"published or yank it. Their rationale is recorded with the version,\n" +
		"and there is no way to contest a finding from the report card today.\n"
	return message{
		Subject: r.registry + ": " + n.Agent + " " + n.Version + " quarantined after rescan",
		Body:    body + r.footer(),
	}
}

func (r renderer) review(n ReviewNotice) message {
	var headline, detail string
	switch n.Decision {
	case "published":
		// §1.6.3: "scanned, N findings, signed" — never "safe".
		headline = "published"
		detail = "The version is now resolvable and its attestation is signed. The full\n" +
			"scan report stays public: publication records what was found, it does\n" +
			"not certify that nothing was missed.\n"
	case "rejected":
		headline = "rejected"
		// `rejected` is terminal: registry.allowedTransitions gives it no
		// outgoing edge, so "submit again" would be misleading about this
		// version. A new version starts at submitted and walks the pipeline.
		detail = "The version will not be published, and that decision is final for\n" +
			"these bytes. A new version with the findings addressed goes through\n" +
			"the pipeline from the start.\n"
	case "yanked":
		// Reachable: rejecting a review on a QUARANTINED version cannot go to
		// `rejected` (the edge does not exist), so the API yanks instead and
		// passes "yanked" here. Without this branch the author's only
		// explanation was the headline.
		headline = "yanked"
		detail = "A yanked version still resolves for an exact pin, with a warning, so\n" +
			"copies pinned to it keep working. It no longer resolves for a range,\n" +
			"and a yank is permanent: the fix is a new version.\n"
	case "needs_review":
		headline = "held for review"
		detail = "The gate could not decide, so a human reviewer has the version.\n" +
			"Nothing is needed from you until they decide.\n"
	default:
		headline = n.Decision
		detail = ""
	}
	body := n.Agent + " " + n.Version + " was " + headline + ".\n\n" + detail
	if n.Reviewer != "" {
		body += "\nReviewer: " + n.Reviewer + "\n"
	}
	if n.Rationale != "" {
		body += "Rationale: " + n.Rationale + "\n"
	}
	if u := firstNonEmpty(n.ReportURL, r.link("/agents/"+n.Agent+"/versions/"+n.Version+"/report")); u != "" {
		body += "\nReport card:\n" + u + "\n"
	}
	return message{
		Subject: r.registry + ": " + n.Agent + " " + n.Version + " " + headline,
		Body:    body + r.footer(),
	}
}

func (r renderer) advisory(n AdvisoryNotice) message {
	body := "An advisory naming " + n.Agent + " is now public.\n\n" +
		"Severity: " + severityLine(n.Severity) + "\n"
	if n.Summary != "" {
		body += "Summary: " + n.Summary + "\n"
	}
	if u := firstNonEmpty(n.AdvisoryURL, r.link("/advisories")); u != "" {
		body += "\n" + u + "\n"
	}
	body += "\nAdvisories are how installed copies learn about this: there is no\n" +
		"mechanism that reaches them directly.\n"
	return message{
		Subject: r.registry + ": advisory published for " + n.Agent,
		Body:    body + r.footer(),
	}
}

func (r renderer) mcpAlert(n MCPDependencyAlertNotice) message {
	body := n.Agent + "@" + n.Version + " declares the MCP server " + n.Server +
		", which now has a known vulnerability.\n\n" +
		"Severity: " + severityLine(n.Severity) + "\n"
	if len(n.Advisories) > 0 {
		body += "Advisories: " + strings.Join(n.Advisories, ", ") + "\n"
	}
	if len(n.FixedIn) > 0 {
		body += "Fixed in: " + strings.Join(n.FixedIn, ", ") + "\n"
	}
	body += "\nThe published version stays installable, and its page and your\n" +
		"dashboard now carry this alert. To clear it, publish a new version\n" +
		"that pins a fixed server version, then yank the affected one.\n"
	if u := firstNonEmpty(n.AgentURL, r.dashboard, r.link("/dashboard")); u != "" {
		body += "\n" + u + "\n"
	}
	return message{
		Subject: r.registry + ": " + n.Agent + "@" + n.Version + " uses a vulnerable MCP server (" + n.Severity + ")",
		Body:    body + r.footer(),
	}
}

func (r renderer) invite(n InviteNotice) message {
	body := "You were added to the " + n.Org + " organisation on " + r.registry + "."
	if n.InvitedBy != "" {
		body += "\nAdded by: " + n.InvitedBy
	}
	if n.Role != "" {
		body += "\nRole: " + n.Role
	}
	body += "\n"
	if u := firstNonEmpty(n.URL, r.link("/orgs/"+n.Org)); u != "" {
		body += "\n" + u + "\n"
	}
	body += "\nIf you did not expect this, tell the organisation's owners: org\n" +
		"membership is granted by an admin, not accepted by you.\n"
	return message{Subject: r.registry + ": you were added to " + n.Org, Body: body + r.footer()}
}

// severityLine renders a severity label, defaulting to something honest when
// the caller did not set one. The default is a word rather than the old
// "unspecified-severity" slug so it reads in both places it appears: after
// "Severity: " and inside "a finding at … severity".
func severityLine(s string) string {
	if s == "" {
		return "unspecified"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// rfc5322Date formats a Date header.
func rfc5322Date(t time.Time) string { return t.Format(time.RFC1123Z) }
