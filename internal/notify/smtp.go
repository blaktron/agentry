package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTPOptions configures the SMTP transport.
type SMTPOptions struct {
	Host     string
	Port     int
	Username string
	Password string
	// From is the envelope sender; it may be a bare address or a
	// "Name <addr>" form.
	From string
	// StartTLS upgrades the connection before AUTH.
	StartTLS bool
	// Timeout bounds one send end to end.
	Timeout time.Duration
}

// sendFunc is the seam the tests substitute: everything above it — address
// parsing, message construction, §1.6.3 wording — is exercised without a
// socket, and the socket code below it is one small function.
type sendFunc func(ctx context.Context, from string, to []string, msg []byte) error

// SMTPNotifier delivers notifications over SMTP. Point it at mailpit (:1025,
// no TLS, no auth) in dev, or at SES's SMTP endpoint on AWS — see
// docs/ops/deployment.md.
type SMTPNotifier struct {
	opt      SMTPOptions
	from     *mail.Address
	render   renderer
	log      *slog.Logger
	send     sendFunc
	nowFn    func() time.Time
	hostname string
}

// NewSMTP validates the configuration and builds the notifier. Address parsing
// happens here so a malformed From is a startup error rather than a delivery
// failure discovered the first time something goes wrong in production.
func NewSMTP(opt SMTPOptions, registry, baseURL string, log *slog.Logger) (*SMTPNotifier, error) {
	if opt.Host == "" {
		return nil, errors.New("notify: smtp host is required")
	}
	if opt.Port <= 0 {
		return nil, errors.New("notify: smtp port is required")
	}
	if opt.From == "" {
		return nil, errors.New("notify: smtp from address is required")
	}
	from, err := mail.ParseAddress(opt.From)
	if err != nil {
		return nil, fmt.Errorf("notify: smtp from address %q: %w", opt.From, err)
	}
	if log == nil {
		log = slog.Default()
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 15 * time.Second
	}
	n := &SMTPNotifier{
		opt:      opt,
		from:     from,
		render:   renderer{registry: registry, baseURL: baseURL},
		log:      log,
		nowFn:    time.Now,
		hostname: "localhost",
	}
	n.send = n.dialAndSend
	return n, nil
}

// EmailVerification implements Notifier.
func (n *SMTPNotifier) EmailVerification(ctx context.Context, toEmail, token string) error {
	// The token is a bearer secret: it goes in the body and NOWHERE else.
	// §16.2's "never tokens/secrets" lint rule is why the log line below
	// records only the recipient.
	return n.deliver(ctx, toEmail, n.render.verification(token), "email_verification")
}

// AgentQuarantined implements Notifier.
func (n *SMTPNotifier) AgentQuarantined(ctx context.Context, notice QuarantineNotice) error {
	return n.deliver(ctx, notice.ToEmail, n.render.quarantine(notice), "agent_quarantined")
}

// ReviewDecided implements Notifier.
func (n *SMTPNotifier) ReviewDecided(ctx context.Context, notice ReviewNotice) error {
	return n.deliver(ctx, notice.ToEmail, n.render.review(notice), "review_decided")
}

// AdvisoryPublished implements Notifier.
func (n *SMTPNotifier) AdvisoryPublished(ctx context.Context, notice AdvisoryNotice) error {
	return n.deliver(ctx, notice.ToEmail, n.render.advisory(notice), "advisory_published")
}

// MCPDependencyAlert implements Notifier.
func (n *SMTPNotifier) MCPDependencyAlert(ctx context.Context, notice MCPDependencyAlertNotice) error {
	return n.deliver(ctx, notice.ToEmail, n.render.mcpAlert(notice), "mcp_dependency_alert")
}

// OrgInvite implements Notifier.
func (n *SMTPNotifier) OrgInvite(ctx context.Context, notice InviteOffer) error {
	return n.deliver(ctx, notice.ToEmail, n.render.invite(notice), "org_invite")
}

// OrgAccessRequest implements Notifier.
func (n *SMTPNotifier) OrgAccessRequest(ctx context.Context, notice AccessRequestNotice) error {
	return n.deliver(ctx, notice.ToEmail, n.render.accessRequest(notice), "org_access_request")
}

// OrgPendingMembers implements Notifier. A digest with nobody in it is
// not a mail; the caller never sends one, and this refuses it anyway.
func (n *SMTPNotifier) OrgPendingMembers(ctx context.Context, notice PendingMembersNotice) error {
	if len(notice.Members) == 0 {
		return nil
	}
	return n.deliver(ctx, notice.ToEmail, n.render.pendingMembers(notice), "org_pending_members")
}

// Rendered implements Notifier. The subject and the address are checked
// for header injection in compose like every other message's; the body is
// text and cannot carry a header.
func (n *SMTPNotifier) Rendered(ctx context.Context, notice RenderedNotice) error {
	return n.deliver(ctx, notice.ToEmail, n.render.rendered(notice), string(notice.Kind))
}

// deliver renders and sends one message.
func (n *SMTPNotifier) deliver(ctx context.Context, to string, m message, kind string) error {
	addr, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("notify: recipient %q: %w", to, err)
	}
	raw, err := n.compose(addr.Address, m)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, n.opt.Timeout)
	defer cancel()
	if err := n.send(ctx, n.from.Address, []string{addr.Address}, raw); err != nil {
		n.log.Error("notify: smtp send failed", "kind", kind, "to", addr.Address, "err", err)
		return fmt.Errorf("notify: send %s: %w", kind, err)
	}
	n.log.Info("notify: sent", "kind", kind, "to", addr.Address)
	return nil
}

// compose builds an RFC 5322 message. Header values are checked for CR/LF
// before they are written: a subject or address carrying a newline would let
// the caller inject headers — a Bcc, a different From — into a message the
// server sends on its own authority.
func (n *SMTPNotifier) compose(to string, m message) ([]byte, error) {
	subject := strings.TrimSpace(m.Subject)
	for _, v := range []string{subject, to, n.opt.From} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("notify: header value contains a line break")
		}
	}
	var b strings.Builder
	b.WriteString("From: " + n.from.String() + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + encodeHeader(subject) + "\r\n")
	b.WriteString("Date: " + rfc5322Date(n.nowFn()) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	// Transactional mail: keep it out of bulk-unsubscribe handling and out of
	// auto-responder loops.
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("\r\n")
	b.WriteString(normalizeBody(m.Body))
	return []byte(b.String()), nil
}

// encodeHeader RFC 2047-encodes a subject. QEncoding leaves plain ASCII
// untouched, so this is a no-op for the common case and correct for an agent
// name with non-ASCII characters in it.
func encodeHeader(s string) string {
	return mime.QEncoding.Encode("utf-8", s)
}

// normalizeBody converts to CRLF line endings and dot-stuffs, as SMTP DATA
// requires. Without the stuffing a body line that is a single "." ends the
// message early and truncates everything after it.
func normalizeBody(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, ".") {
			lines[i] = "." + l
		}
	}
	return strings.Join(lines, "\r\n")
}

// dialAndSend performs the SMTP conversation.
func (n *SMTPNotifier) dialAndSend(ctx context.Context, from string, to []string, msg []byte) error {
	addr := net.JoinHostPort(n.opt.Host, strconv.Itoa(n.opt.Port))
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	c, err := smtp.NewClient(conn, n.opt.Host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()

	if err := c.Hello(n.hostname); err != nil {
		return err
	}
	if n.opt.StartTLS {
		ok, _ := c.Extension("STARTTLS")
		if !ok {
			// Configured for TLS and the server does not offer it: refuse
			// rather than silently continue in the clear with a password in
			// hand.
			return errors.New("server does not advertise STARTTLS")
		}
		if err := c.StartTLS(&tls.Config{ServerName: n.opt.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if n.opt.Username != "" {
		auth := smtp.PlainAuth("", n.opt.Username, n.opt.Password, n.opt.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt to: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}
	return c.Quit()
}
