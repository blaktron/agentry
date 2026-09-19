// Package notify sends user-facing notifications (email in v1).
//
// Two implementations: LogNotifier (the default — a fresh install says what it
// would have sent rather than pretending to send it) and SMTPNotifier, which
// speaks to mailpit on :1025 in the compose dev stack and to SES's SMTP
// endpoint on AWS (§13.4).
//
// No notification goes to an address the registry has not verified: every
// sender asks AllowsEmail (prefs.go) first, which refuses a user without
// users.email_verified_at before it reads a single preference (agentry#299).
// The verification mail is the one mail that does not ask, because it is
// how an address becomes verified.
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

	"github.com/blaktron/agentry/internal/logx"
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
	// OrgInvite offers someone a place in an organisation (§13.4 lists
	// invites among the transactional mails). Since agentry#361 it is a
	// real offer with a link to accept, not a notice that a membership
	// already exists: nobody joins an organisation uninvited.
	OrgInvite(ctx context.Context, n InviteOffer) error
	// MCPDependencyAlert tells an author that a published version of theirs
	// declares an MCP server version with a newly known high or critical
	// vulnerability, and that the fix is a new version (agentry#177).
	MCPDependencyAlert(ctx context.Context, n MCPDependencyAlertNotice) error
	// OrgAccessRequest tells an organisation's admin that a person whose
	// verified address is at the organisation's domain asks to be added
	// (agentry#363, D13, D21). One mail per admin, once a day per person.
	OrgAccessRequest(ctx context.Context, n AccessRequestNotice) error
	// OrgPendingMembers tells an organisation's admin who is waiting to be
	// approved (agentry#364, D25): the people the domain folded in, and
	// the IdP provisioned, that no digest has named yet. One mail per
	// admin per organisation, batched daily; a person is named once.
	OrgPendingMembers(ctx context.Context, n PendingMembersNotice) error
}

// PendingMembersNotice is the daily digest delivered to one of the
// organisation's admins.
type PendingMembersNotice struct {
	ToEmail string
	Org     string
	// OrgDisplayName is the organisation's name, for the sentence.
	OrgDisplayName string
	// Members are the people waiting, in the order they arrived.
	Members []PendingMember
	// ConsoleURL is where the admin approves or declines them; empty when
	// the server knows no absolute origin.
	ConsoleURL string
}

// PendingMember is one person in the digest.
type PendingMember struct {
	Handle string
	// Email is their verified address.
	Email string
	// Via is the door: "domain" (their address is at the organisation's
	// domain) or "scim" (the organisation's IdP provisioned them).
	Via string
	// Since is when they became pending.
	Since time.Time
}

// AccessRequestNotice is a request for access delivered to one of the
// organisation's admins.
type AccessRequestNotice struct {
	ToEmail string
	Org     string
	// OrgDisplayName is the organisation's name, for the sentence.
	OrgDisplayName string
	// Requester is the handle of the person asking; RequesterEmail their
	// verified address, which is at the organisation's domain.
	Requester      string
	RequesterEmail string
	// ConsoleURL is where the admin invites them; empty when the server
	// knows no absolute origin.
	ConsoleURL string
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
	// AffectedVersions is the range the advisory names, as stored — the
	// fact a consumer needs first (agentry#274).
	AffectedVersions string
	// AdvisoryURL is the public advisory page.
	AdvisoryURL string
}

// InviteOffer offers a place in an organisation. It replaced InviteNotice
// with agentry#361: an organisation's membership is offered and accepted,
// not granted, so the mail carries a link the person acts on and the role
// it names is not yet in force.
type InviteOffer struct {
	ToEmail string
	Org     string
	// OrgDisplayName is the organisation's name, for the sentence.
	OrgDisplayName string
	// Role is the org role the invitation offers.
	Role string
	// InvitedBy is the inviting admin's handle.
	InvitedBy string
	// AcceptURL is where the recipient accepts it; empty when the server
	// knows no absolute origin, in which case the admin conveys the token.
	AcceptURL string
	// ExpiresAt is when the invitation stops working.
	ExpiresAt time.Time
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
	// address-verification link for a token; ReportCard builds the link to a
	// version's report card for "namespace/name" and a version (agentry#270).
	// Unset falls back to the site's own paths under BaseURL.
	Links Links
}

// Links carries the resolved browser destinations for the renderer.
type Links struct {
	Dashboard   string
	VerifyEmail func(token string) string
	ReportCard  func(agent, version string) string
	// Settings is the page where a person switches these mails on and off
	// (agentry#274): the footer names it, so a reader knows where to go.
	Settings string
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
		n.render.reportCard = opt.Links.ReportCard
		n.render.settings = opt.Links.Settings
		return n, nil
	default:
		return nil, fmt.Errorf("notify: unknown kind %q (want log|smtp)", opt.Kind)
	}
}

// LogNotifier writes notifications to the log (dev/self-host default until
// SMTP is configured): that a mail would have gone, to which mailbox (the
// address masked, docs/logging.md), about what. Never the verification
// token — the log contract keeps every token out of every line, so an
// address cannot be verified through this notifier; that takes a sender.
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
	_ = token // never logged (docs/logging.md)
	n.logger().Info("notify: email verification not sent (no sender configured)", "to", logx.MaskEmail(toEmail))
	return nil
}

// AgentQuarantined implements Notifier. Logged at warn: on a self-host
// instance without SMTP this line is the only trace that an author was
// supposed to hear about a quarantine.
func (n LogNotifier) AgentQuarantined(_ context.Context, notice QuarantineNotice) error {
	n.logger().Warn("notify: agent quarantined (author notification)",
		"to", logx.MaskEmail(notice.ToEmail), "agent", notice.Agent, "version", notice.Version,
		"severity", notice.Severity, "reason", notice.Reason)
	return nil
}

// ReviewDecided implements Notifier.
func (n LogNotifier) ReviewDecided(_ context.Context, notice ReviewNotice) error {
	n.logger().Info("notify: review decided (author notification)",
		"to", logx.MaskEmail(notice.ToEmail), "agent", notice.Agent, "version", notice.Version,
		"decision", notice.Decision, "reviewer", notice.Reviewer)
	return nil
}

// AdvisoryPublished implements Notifier.
func (n LogNotifier) AdvisoryPublished(_ context.Context, notice AdvisoryNotice) error {
	n.logger().Warn("notify: advisory published (author notification)",
		"to", logx.MaskEmail(notice.ToEmail), "agent", notice.Agent, "severity", notice.Severity)
	return nil
}

// MCPDependencyAlert implements Notifier.
func (n LogNotifier) MCPDependencyAlert(_ context.Context, notice MCPDependencyAlertNotice) error {
	n.logger().Warn("notify: MCP dependency alert (author notification)",
		"to", logx.MaskEmail(notice.ToEmail), "agent", notice.Agent, "version", notice.Version,
		"server", notice.Server, "severity", notice.Severity, "advisories", notice.Advisories)
	return nil
}

// OrgInvite implements Notifier.
func (n LogNotifier) OrgInvite(_ context.Context, notice InviteOffer) error {
	n.logger().Info("notify: org invite",
		"to", logx.MaskEmail(notice.ToEmail), "org", notice.Org, "role", notice.Role)
	return nil
}

// OrgAccessRequest implements Notifier.
func (n LogNotifier) OrgAccessRequest(_ context.Context, notice AccessRequestNotice) error {
	n.logger().Info("notify: org access request",
		"to", logx.MaskEmail(notice.ToEmail), "org", notice.Org, "requester", notice.Requester)
	return nil
}

// OrgPendingMembers implements Notifier.
func (n LogNotifier) OrgPendingMembers(_ context.Context, notice PendingMembersNotice) error {
	n.logger().Info("notify: org pending members",
		"to", logx.MaskEmail(notice.ToEmail), "org", notice.Org, "pending", len(notice.Members))
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
	// dashboard, verifyEmail and reportCard are the browser destinations the
	// server resolved for this deployment (a site in front of it, or its own
	// /ui/ pages — DEV-091); when unset the site's paths under baseURL are
	// used, so a bare renderer still produces links of the same shape.
	dashboard   string
	verifyEmail func(token string) string
	reportCard  func(agent, version string) string
	settings    string
}

// reportLink is the report-card link for a version: the caller's explicit
// URL, else the deployment's resolved one, else the site's route shape under
// baseURL — the path the site serves, which the old "/agents/…" fallback was
// not (agentry#270).
func (r renderer) reportLink(explicit, agent, version string) string {
	if explicit != "" {
		return explicit
	}
	if r.reportCard != nil {
		if u := r.reportCard(agent, version); u != "" {
			return u
		}
	}
	return r.link("/" + agent + "/versions/" + version)
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
	f := "\n--\n" + r.registry + " sent this automatically to the address\n" +
		"on the account it concerns. Do not reply to this message.\n"
	// Most of these mails can be switched off; the page that does it is
	// named on every one, since the reader of a mail they did not want is
	// the reader who needs the line (agentry#274).
	if u := firstNonEmpty(r.settings, r.link("/settings")); u != "" {
		f += "Which of these mails you receive is set in your settings:\n" + u + "\n"
	}
	return f
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
		// One sweep can quarantine several versions of the same BriefAgent and
		// send one of these for each, so "your other published versions still
		// resolve" was a promise this mail cannot keep. Name the mechanism
		// that would have taken the others instead.
		"installed elsewhere are not reached by this change. Your other\n" +
		"published versions resolve unless a rescan quarantined them too.\n\n"
	if n.Reason != "" {
		body += "Reason recorded: " + n.Reason + "\n\n"
	}
	if u := r.reportLink(n.ReportURL, n.Agent, n.Version); u != "" {
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
		// Reachable: the pipeline sends this when its gate holds a fresh
		// submission for a human (internal/scan/pipeline.go, agentry#274) —
		// the one outcome an author would otherwise learn only by looking.
		headline = "held for review"
		detail = "The gate did not clear it, so a human reviewer has the version.\n" +
			"Nothing is needed from you until they decide; you will get a mail\n" +
			"when they do.\n"
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
	if u := r.reportLink(n.ReportURL, n.Agent, n.Version); u != "" {
		body += "\nReport card:\n" + u + "\n"
	}
	return message{
		Subject: r.registry + ": " + n.Agent + " " + n.Version + " " + headline,
		Body:    body + r.footer(),
	}
}

func (r renderer) advisory(n AdvisoryNotice) message {
	// Say it, then name it (plan §4.3): this mail is where an author meets
	// the word "advisory" first.
	body := "The registry published an advisory naming " + n.Agent + ". An advisory is\n" +
		"the public record of a security problem in a published BriefAgent.\n\n" +
		"Severity: " + severityLine(n.Severity) + "\n"
	if n.AffectedVersions != "" {
		body += "Affected versions: " + n.AffectedVersions + "\n"
	}
	if n.Summary != "" {
		body += "Summary: " + n.Summary + "\n"
	}
	if u := firstNonEmpty(n.AdvisoryURL, r.link("/advisories")); u != "" {
		body += "\n" + u + "\n"
	}
	// Same §7 fact as before, load-bearing half first.
	body += "\nNothing in the registry reaches copies that are already installed.\n" +
		"This advisory and its page are how a consumer finds out.\n"
	return message{
		Subject: r.registry + ": advisory published for " + n.Agent,
		Body:    body + r.footer(),
	}
}

func (r renderer) mcpAlert(n MCPDependencyAlertNotice) message {
	// The server ref runs to fifty characters or more, so it goes on a label
	// line with the rest of the facts rather than inside a sentence that no
	// wrap can keep readable.
	body := n.Agent + "@" + n.Version + " declares an MCP server that now has a known\n" +
		"vulnerability.\n\n" +
		"Server: " + n.Server + "\n" +
		"Severity: " + severityLine(n.Severity) + "\n"
	if len(n.Advisories) > 0 {
		body += "Advisories: " + strings.Join(n.Advisories, ", ") + "\n"
	}
	if len(n.FixedIn) > 0 {
		body += "Fixed in: " + strings.Join(n.FixedIn, ", ") + "\n"
	}
	body += "\nThe version stays published and installable. The BriefAgent's page\n" +
		"and your dashboard list this alert.\n\n" +
		"To clear it, publish a new version that pins a fixed server version,\n" +
		"then yank the affected one. The alert closes when the version leaves\n" +
		"published.\n"
	if u := firstNonEmpty(n.AgentURL, r.dashboard, r.link("/dashboard")); u != "" {
		body += "\n" + u + "\n"
	}
	return message{
		Subject: r.registry + ": " + n.Agent + "@" + n.Version + " uses a vulnerable MCP server (" + severityLine(n.Severity) + ")",
		Body:    body + r.footer(),
	}
}

// orgLabel names an organisation for a sentence: its display name with the
// handle in brackets, or the handle alone.
func orgLabel(handle, displayName string) string {
	if displayName != "" && displayName != handle {
		return displayName + " (" + handle + ")"
	}
	return handle
}

func (r renderer) invite(n InviteOffer) message {
	who := orgLabel(n.Org, n.OrgDisplayName)
	body := "You have been invited to join the " + who + " organization on " + r.registry + "."
	if n.InvitedBy != "" {
		body += "\nInvited by: " + n.InvitedBy
	}
	if n.Role != "" {
		body += "\nRole: " + n.Role
	}
	body += "\n"
	if n.AcceptURL != "" {
		body += "\nAccept it here:\n" + n.AcceptURL + "\n"
	}
	if !n.ExpiresAt.IsZero() {
		body += "\nThe invitation expires " + n.ExpiresAt.UTC().Format("2 January 2006") + ".\n"
	}
	// Nothing is in force until the person accepts, and accepting is bound
	// to this address: saying both is what tells a reader who did not
	// expect this that ignoring it is enough.
	body += "\nNothing changes until you accept, and only an account signed in with\n" +
		"this address can. If you did not expect this invitation, ignore it and\n" +
		"it will expire.\n"
	return message{
		Subject: r.registry + ": you are invited to the " + n.Org + " organization",
		Body:    body + r.footer(),
	}
}

func (r renderer) accessRequest(n AccessRequestNotice) message {
	who := orgLabel(n.Org, n.OrgDisplayName)
	body := n.Requester + " <" + n.RequesterEmail + "> asks to join the " + who +
		" organization on " + r.registry + ".\n\n" +
		"Their address is at the domain registered to your organization, which is\n" +
		"why this reached you. Nobody joins uninvited: to add them, send them an\n" +
		"invitation from the organization's console"
	if n.ConsoleURL != "" {
		body += ":\n" + n.ConsoleURL + "\n"
	} else {
		body += ".\n"
	}
	body += "\nIf you do not know them, there is nothing to do: they hold nothing of the\n" +
		"organization, and they can ask again at most once a day.\n"
	return message{
		Subject: r.registry + ": " + n.Requester + " asks to join the " + n.Org + " organization",
		Body:    body + r.footer(),
	}
}

func (r renderer) pendingMembers(n PendingMembersNotice) message {
	who := orgLabel(n.Org, n.OrgDisplayName)
	body := ""
	if len(n.Members) == 1 {
		body = "One person is waiting to join the " + who + " organization on " + r.registry + ":\n\n"
	} else {
		body = fmt.Sprintf("%d people are waiting to join the %s organization on %s:\n\n", len(n.Members), who, r.registry)
	}
	for _, m := range n.Members {
		how := "their address is at the domain registered to your organization"
		if m.Via == "scim" {
			how = "your organization's identity provider provisioned them"
		}
		body += "  " + m.Handle + " <" + m.Email + "> — " + how + "\n"
	}
	body += "\nEach of them holds nothing of the organization until an admin approves\n" +
		"them, which is also where their seat is taken; declining removes them and\n" +
		"is remembered. Approve or decline from the organization's console"
	if n.ConsoleURL != "" {
		body += ":\n" + n.ConsoleURL + "\n"
	} else {
		body += ".\n"
	}
	body += "\nYou are told about each person once.\n"
	subject := r.registry + ": " + n.Members[0].Handle + " is waiting to join the " + n.Org + " organization"
	if len(n.Members) != 1 {
		subject = fmt.Sprintf("%s: %d people are waiting to join the %s organization", r.registry, len(n.Members), n.Org)
	}
	return message{Subject: subject, Body: body + r.footer()}
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
