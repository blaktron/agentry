package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var _ Notifier = LogNotifier{}
var _ Notifier = (*SMTPNotifier)(nil)

// capture builds an SMTPNotifier whose transport records instead of dialling.
func capture(t *testing.T) (*SMTPNotifier, *[]string) {
	t.Helper()
	n, err := NewSMTP(SMTPOptions{
		Host: "mail.example", Port: 1025,
		From: "Agentry <no-reply@example.test>",
	}, "registry.example", "https://registry.example", nil)
	if err != nil {
		t.Fatalf("NewSMTP: %v", err)
	}
	var sent []string
	n.nowFn = func() time.Time { return time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC) }
	n.send = func(_ context.Context, _ string, _ []string, msg []byte) error {
		sent = append(sent, string(msg))
		return nil
	}
	return n, &sent
}

func TestNewSelectsImplementation(t *testing.T) {
	logN, err := New(Options{})
	if err != nil {
		t.Fatalf("New(log): %v", err)
	}
	if _, ok := logN.(LogNotifier); !ok {
		t.Errorf("default notifier is %T, want LogNotifier", logN)
	}

	smtpN, err := New(Options{Kind: "smtp", SMTP: SMTPOptions{
		Host: "h", Port: 25, From: "a@b.test",
	}})
	if err != nil {
		t.Fatalf("New(smtp): %v", err)
	}
	if _, ok := smtpN.(*SMTPNotifier); !ok {
		t.Errorf("smtp notifier is %T", smtpN)
	}

	if _, err := New(Options{Kind: "carrier-pigeon"}); err == nil {
		t.Error("New accepted an unknown kind")
	}
}

func TestNewSMTPValidatesConfig(t *testing.T) {
	for name, opt := range map[string]SMTPOptions{
		"no host":  {Port: 25, From: "a@b.test"},
		"no port":  {Host: "h", From: "a@b.test"},
		"no from":  {Host: "h", Port: 25},
		"bad from": {Host: "h", Port: 25, From: "not an address"},
	} {
		if _, err := NewSMTP(opt, "r", "", nil); err == nil {
			t.Errorf("%s: NewSMTP accepted it", name)
		}
	}
}

// §1.6.3: the product must never call an agent safe, secure, or verified.
// Notifications are where that claim would be most tempting.
func TestNoMessageOverclaimsSafety(t *testing.T) {
	n, sent := capture(t)
	ctx := t.Context()

	if err := n.EmailVerification(ctx, "user@example.test", "chris", "tok"); err != nil {
		t.Fatal(err)
	}
	if err := n.AgentQuarantined(ctx, QuarantineNotice{
		ToEmail: "user@example.test", Agent: "acme/widget", Version: "1.0.0",
		Severity: "high", Reason: "obfuscated payload in a prompt file",
	}); err != nil {
		t.Fatal(err)
	}
	// Every decision the API passes here, `yanked` included: that branch is
	// the one that describes a version staying installable, so it is the one
	// most at risk of reassuring the author.
	for _, d := range []string{"published", "rejected", "yanked", "needs_review"} {
		if err := n.ReviewDecided(ctx, ReviewNotice{
			ToEmail: "user@example.test", Agent: "acme/widget", Version: "1.0.0", Decision: d,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.AdvisoryPublished(ctx, AdvisoryNotice{
		ToEmail: "user@example.test", Agent: "acme/widget", Severity: "critical",
	}); err != nil {
		t.Fatal(err)
	}
	if err := n.OrgInvite(ctx, InviteOffer{
		ToEmail: "user@example.test", Org: "acme", Role: "member",
	}); err != nil {
		t.Fatal(err)
	}
	// The dependency alert is a rendered email like the rest and was outside
	// this sweep until now: it is the one that talks about a vulnerability
	// staying installable, which is the sentence most likely to drift.
	if err := n.MCPDependencyAlert(ctx, MCPDependencyAlertNotice{
		ToEmail: "user@example.test", Agent: "acme/widget", Version: "1.0.0",
		Server: "npm:server-filesystem@1.2.3", Severity: "high",
		Advisories: []string{"GHSA-1234-abcd-5678"}, FixedIn: []string{"1.2.4"},
	}); err != nil {
		t.Fatal(err)
	}

	banned := []string{"is safe", "safe to", "verified secure", "guaranteed", "no risk", "malware-free"}
	for _, msg := range *sent {
		lower := strings.ToLower(msg)
		for _, phrase := range banned {
			if strings.Contains(lower, phrase) {
				t.Errorf("message claims %q:\n%s", phrase, msg)
			}
		}
	}
	if len(*sent) != 9 {
		t.Fatalf("sent %d messages, want 9", len(*sent))
	}
}

// A publish notice is the highest-risk place to overclaim; it must describe
// what was done, not what was proven.
func TestPublishNoticeSaysScannedNotSafe(t *testing.T) {
	n, sent := capture(t)
	if err := n.ReviewDecided(t.Context(), ReviewNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Version: "2.0.0",
		Decision: "published", Reviewer: "rev", Rationale: "finding dismissed as a test fixture",
	}); err != nil {
		t.Fatal(err)
	}
	body := (*sent)[0]
	// Assert on the wording, not on where the template happens to wrap.
	if !strings.Contains(flatten(body), "does not certify that nothing was missed") {
		t.Errorf("publish notice does not qualify its claim:\n%s", body)
	}
	if !strings.Contains(body, "rev") || !strings.Contains(body, "test fixture") {
		t.Errorf("reviewer rationale missing (§1.6.2 transparency):\n%s", body)
	}
}

// flatten collapses runs of whitespace so assertions survive line wrapping.
func flatten(s string) string { return strings.Join(strings.Fields(s), " ") }

// A reviewer rejecting an already-quarantined version yanks it, and the mail
// that carries that word must say what a yank does — a yanked version is
// still pinnable, which is the difference from the quarantine the author was
// told about first.
func TestYankNoticeSaysExactPinsStillResolve(t *testing.T) {
	n, sent := capture(t)
	if err := n.ReviewDecided(t.Context(), ReviewNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0",
		Decision: "yanked", Reviewer: "rev", Rationale: "finding confirmed",
	}); err != nil {
		t.Fatal(err)
	}
	body := flatten((*sent)[0])
	for _, want := range []string{
		"was yanked",
		"still resolves for an exact pin",
		"no longer resolves for a range",
		"a yank is permanent",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("yank notice does not say %q:\n%s", want, (*sent)[0])
		}
	}
}

func TestQuarantineNoticeIsHonestAboutInstalledCopies(t *testing.T) {
	n, sent := capture(t)
	if err := n.AgentQuarantined(t.Context(), QuarantineNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0", Severity: "high",
	}); err != nil {
		t.Fatal(err)
	}
	body := (*sent)[0]
	// §7: quarantine does not reach installed copies. Saying otherwise would
	// leave an author believing a problem was contained when it was not.
	if !strings.Contains(flatten(body), "are not reached by this change") {
		t.Errorf("quarantine notice does not say installed copies are unaffected:\n%s", body)
	}
	// agentry#270: the bare fallback is the site's route shape; the old
	// "/agents/…/report" path existed nowhere.
	if !strings.Contains(body, "https://registry.example/acme/widget/versions/1.0.0") {
		t.Errorf("report link missing or wrong:\n%s", body)
	}
	if strings.Contains(body, "/agents/acme/widget") {
		t.Errorf("report link still uses the dead /agents/… path:\n%s", body)
	}
}

// With the deployment's resolved link (Options.Links.ReportCard, the DEV-091
// seam) the quarantine and review mails carry it, and an explicit ReportURL
// on the notice still wins.
func TestReportCardLinkComesFromLinks(t *testing.T) {
	n, sent := capture(t)
	n.render.reportCard = func(agent, version string) string {
		return "https://site.example/" + agent + "/versions/" + version
	}
	if err := n.AgentQuarantined(t.Context(), QuarantineNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0", Severity: "high",
	}); err != nil {
		t.Fatal(err)
	}
	if err := n.ReviewDecided(t.Context(), ReviewNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0", Decision: "rejected",
	}); err != nil {
		t.Fatal(err)
	}
	if err := n.ReviewDecided(t.Context(), ReviewNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0", Decision: "published",
		ReportURL: "https://elsewhere.example/r",
	}); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{
		"https://site.example/acme/widget/versions/1.0.0",
		"https://site.example/acme/widget/versions/1.0.0",
		"https://elsewhere.example/r",
	} {
		if !strings.Contains((*sent)[i], want) {
			t.Errorf("mail %d lacks %q:\n%s", i, want, (*sent)[i])
		}
	}
}

func TestVerificationLinkUsesBaseURL(t *testing.T) {
	n, sent := capture(t)
	if err := n.EmailVerification(t.Context(), "u@example.test", "chris", "secret-token"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains((*sent)[0], "https://registry.example/auth/verify-email?token=secret-token") {
		t.Errorf("verification link missing:\n%s", (*sent)[0])
	}
}

// Header injection: a newline in a subject would let a caller add headers to
// a message the server sends on its own authority.
func TestComposeRejectsHeaderInjection(t *testing.T) {
	n, _ := capture(t)
	_, err := n.compose("u@example.test", message{
		Subject: "ok\r\nBcc: attacker@example.test",
		Body:    "body",
	})
	if err == nil {
		t.Fatal("compose accepted a subject containing CRLF")
	}
}

func TestDeliverRejectsMalformedRecipient(t *testing.T) {
	n, sent := capture(t)
	if err := n.EmailVerification(t.Context(), "not an address", "chris", "tok"); err == nil {
		t.Error("delivery to a malformed address was attempted")
	}
	if len(*sent) != 0 {
		t.Error("a message was sent to a malformed address")
	}
}

// SMTP DATA ends at a lone "."; without dot-stuffing a body could truncate
// itself, or worse, terminate early and leave the rest interpreted as commands.
func TestBodyIsDotStuffedAndCRLF(t *testing.T) {
	got := normalizeBody("first\n.\n.hidden\nlast\n")
	want := "first\r\n..\r\n..hidden\r\nlast\r\n"
	if got != want {
		t.Errorf("normalizeBody = %q, want %q", got, want)
	}
}

func TestComposeSetsTransactionalHeaders(t *testing.T) {
	n, _ := capture(t)
	raw, err := n.compose("u@example.test", message{Subject: "hello", Body: "body\n"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, h := range []string{
		"From: \"Agentry\" <no-reply@example.test>",
		"To: u@example.test",
		"Subject: hello",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Auto-Submitted: auto-generated",
	} {
		if !strings.Contains(s, h) {
			t.Errorf("missing header %q in:\n%s", h, s)
		}
	}
	if !strings.Contains(s, "\r\n\r\n") {
		t.Error("no blank line between headers and body")
	}
}

func TestNonASCIISubjectIsEncoded(t *testing.T) {
	n, _ := capture(t)
	raw, err := n.compose("u@example.test", message{Subject: "café findings", Body: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "=?utf-8?q?") {
		t.Errorf("non-ASCII subject was not RFC 2047 encoded:\n%s", raw)
	}
}

func TestSendFailureIsReported(t *testing.T) {
	n, _ := capture(t)
	n.send = func(context.Context, string, []string, []byte) error {
		return errors.New("connection refused")
	}
	err := n.OrgInvite(t.Context(), InviteOffer{ToEmail: "u@example.test", Org: "acme"})
	if err == nil {
		t.Fatal("a failed send reported success")
	}
	if !strings.Contains(err.Error(), "org_invite") {
		t.Errorf("error does not name the notification kind: %v", err)
	}
}

// The log notifier is the default; every method must stay non-fatal.
func TestLogNotifierNeverFails(t *testing.T) {
	n := LogNotifier{}
	ctx := t.Context()
	for _, err := range []error{
		n.EmailVerification(ctx, "u@example.test", "chris", "t"),
		n.AgentQuarantined(ctx, QuarantineNotice{}),
		n.ReviewDecided(ctx, ReviewNotice{}),
		n.AdvisoryPublished(ctx, AdvisoryNotice{}),
		n.OrgInvite(ctx, InviteOffer{}),
	} {
		if err != nil {
			t.Errorf("LogNotifier returned %v", err)
		}
	}
}

// With no BaseURL the verification message must still be actionable, and it
// must describe what the recipient has: a code, not a link.
func TestVerificationFallsBackToACodeWithoutABaseURL(t *testing.T) {
	r := renderer{registry: "Agentry"}
	m := r.verification("chris", "tok123")
	if !strings.Contains(m.Body, "Verification code: tok123") {
		t.Errorf("no usable token without a base URL:\n%s", m.Body)
	}
	if !strings.Contains(m.Body, "The code works once.") {
		t.Errorf("code branch describes a link it did not send:\n%s", m.Body)
	}
	// The old copy promised "the address will not be used", which nothing in
	// the server keeps: no job deletes an unconfirmed account, and a later
	// org grant mails the address anyway. The mail states the gate instead.
	if strings.Contains(m.Body, "will not be used") {
		t.Errorf("verification mail promises the address goes unused:\n%s", m.Body)
	}
}

// TestAdvisoryNamesItsRangeAndTheFooterNamesTheSettingsPage (agentry#274):
// the advisory mail carries the range the advisory names, and every mail's
// footer names the page where these mails are switched on and off.
func TestAdvisoryNamesItsRangeAndTheFooterNamesTheSettingsPage(t *testing.T) {
	n, sent := capture(t)
	n.render.settings = "https://site.example/settings"
	if err := n.AdvisoryPublished(t.Context(), AdvisoryNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Severity: "high",
		Summary: "leaks the token", AffectedVersions: "<1.0.1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := n.ReviewDecided(t.Context(), ReviewNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0", Decision: "needs_review",
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains((*sent)[0], "Affected versions: <1.0.1") {
		t.Errorf("advisory mail lacks the range:\n%s", (*sent)[0])
	}
	for i, m := range *sent {
		if !strings.Contains(m, "set in your settings:\r\nhttps://site.example/settings") {
			t.Errorf("mail %d's footer does not name the settings page:\n%s", i, m)
		}
	}
	if !strings.Contains((*sent)[1], "held for review") || !strings.Contains((*sent)[1], "you will get a mail") {
		t.Errorf("held-for-review mail:\n%s", (*sent)[1])
	}
}
