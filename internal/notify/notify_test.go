package notify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

// bodyOf returns the body of a raw message with LF line ends.
func bodyOf(raw string) string {
	_, b, _ := strings.Cut(raw, "\r\n\r\n")
	return strings.ReplaceAll(b, "\r\n", "\n")
}

// headerOf returns the value of the named header of a raw message.
func headerOf(raw, name string) string {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	for _, l := range strings.Split(head, "\r\n") {
		if v, ok := strings.CutPrefix(l, name+": "); ok {
			return v
		}
	}
	return ""
}

// wantFooter is the closing every message carries; settings is the page the
// footer names, empty when the deployment has none.
func wantFooter(registry, settings string) string {
	f := "\n--\n" + registry + " sent this automatically to the address\n" +
		"on the account it concerns. Do not reply to this message.\n"
	if settings != "" {
		f += "Which of these mails you receive is set in your settings:\n" + settings + "\n"
	}
	return f
}

// logSink returns a logger that writes text lines into the returned buffer.
func logSink() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
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
	} else if !strings.Contains(err.Error(), `unknown kind "carrier-pigeon" (want log|smtp)`) {
		t.Errorf("unknown-kind error does not name the kind and the choices: %v", err)
	}

	// "log" spelled out is the log notifier too, and it keeps the caller's
	// logger.
	l, _ := logSink()
	namedLog, err := New(Options{Kind: "log", Log: l})
	if err != nil {
		t.Fatalf("New(log, Log): %v", err)
	}
	if ln, ok := namedLog.(LogNotifier); !ok || ln.Log != l {
		t.Errorf("log notifier = %#v, want one holding the caller's logger", namedLog)
	}

	// A bad SMTP configuration is an error from New, not a notifier that
	// fails on first use.
	if n, err := New(Options{Kind: "smtp", SMTP: SMTPOptions{Port: 25, From: "a@b.test"}}); err == nil || n != nil {
		t.Errorf("New(smtp, no host) = %v, %v; want a startup error", n, err)
	} else if !strings.Contains(err.Error(), "smtp host is required") {
		t.Errorf("New(smtp, no host) error = %v", err)
	}

	// Everything Options carries reaches the SMTP notifier's renderer: the
	// registry name (defaulting to Agentry), the origin, the logger and the
	// four resolved destinations.
	sl, _ := logSink()
	opt := Options{
		Kind: "smtp", BaseURL: "https://site.example", Log: sl,
		SMTP: SMTPOptions{Host: "h", Port: 25, From: "a@b.test"},
		Links: Links{
			Dashboard:   "https://site.example/dash",
			VerifyEmail: func(tok string) string { return "https://site.example/v/" + tok },
			ReportCard:  func(a, v string) string { return "https://site.example/r/" + a + "/" + v },
			Settings:    "https://site.example/settings",
		},
	}
	built, err := New(opt)
	if err != nil {
		t.Fatalf("New(smtp, links): %v", err)
	}
	sn := built.(*SMTPNotifier)
	if sn.render.registry != "Agentry" {
		t.Errorf("registry defaults to %q, want Agentry", sn.render.registry)
	}
	if sn.render.baseURL != "https://site.example" {
		t.Errorf("baseURL = %q", sn.render.baseURL)
	}
	if sn.log != sl {
		t.Error("the notifier does not use the logger it was given")
	}
	if sn.render.dashboard != "https://site.example/dash" || sn.render.settings != "https://site.example/settings" {
		t.Errorf("dashboard/settings = %q, %q", sn.render.dashboard, sn.render.settings)
	}
	if sn.render.verifyEmail == nil || sn.render.verifyEmail("t1") != "https://site.example/v/t1" {
		t.Error("the resolved verification link is not wired")
	}
	if sn.render.reportCard == nil || sn.render.reportCard("a/b", "1") != "https://site.example/r/a/b/1" {
		t.Error("the resolved report-card link is not wired")
	}
	opt.Registry = "Acme Registry"
	named, err := New(opt)
	if err != nil {
		t.Fatalf("New(smtp, registry): %v", err)
	}
	if got := named.(*SMTPNotifier).render.registry; got != "Acme Registry" {
		t.Errorf("registry = %q, want the configured name", got)
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

	// Each refusal names what is wrong, and a negative port is as unusable
	// as an absent one.
	for _, c := range []struct {
		name string
		opt  SMTPOptions
		want string
	}{
		{"no host", SMTPOptions{Port: 25, From: "a@b.test"}, "notify: smtp host is required"},
		{"no port", SMTPOptions{Host: "h", From: "a@b.test"}, "notify: smtp port is required"},
		{"negative port", SMTPOptions{Host: "h", Port: -1, From: "a@b.test"}, "notify: smtp port is required"},
		{"no from", SMTPOptions{Host: "h", Port: 25}, "notify: smtp from address is required"},
		{"bad from", SMTPOptions{Host: "h", Port: 25, From: "not an address"}, `notify: smtp from address "not an address"`},
	} {
		n, err := NewSMTP(c.opt, "r", "", nil)
		if err == nil || n != nil {
			t.Errorf("%s: NewSMTP = %v, %v; want a refusal", c.name, n, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error = %q, want it to contain %q", c.name, err, c.want)
		}
	}

	// What a valid configuration becomes: the sender split into name and
	// address, the 15 s default bound for a zero or negative timeout, the
	// caller's bound kept, the process logger for a nil one, the real clock,
	// the greeting name, and the origin and registry handed to the renderer.
	before := time.Now()
	n, err := NewSMTP(SMTPOptions{Host: "h", Port: 25, From: "Agentry <no-reply@example.test>"}, "Reg", "https://x.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if n.from.Name != "Agentry" || n.from.Address != "no-reply@example.test" {
		t.Errorf("from = %+v", n.from)
	}
	if n.opt.Timeout != 15*time.Second {
		t.Errorf("default timeout = %v, want 15s", n.opt.Timeout)
	}
	if n.log != slog.Default() {
		t.Error("a nil logger is not the process logger")
	}
	if now := n.nowFn(); now.Before(before) || now.After(time.Now()) {
		t.Errorf("clock reads %v, not the current time", now)
	}
	if n.hostname != "localhost" {
		t.Errorf("greeting name = %q", n.hostname)
	}
	if n.render.registry != "Reg" || n.render.baseURL != "https://x.example" {
		t.Errorf("renderer = %+v", n.render)
	}
	if n.opt.Host != "h" || n.opt.Port != 25 {
		t.Errorf("options not kept: %+v", n.opt)
	}
	if n.send == nil {
		t.Error("no transport")
	}
	for _, d := range []time.Duration{-time.Second, 3 * time.Second} {
		kept, err := NewSMTP(SMTPOptions{Host: "h", Port: 25, From: "a@b.test", Timeout: d}, "r", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		want := d
		if d < 0 {
			want = 15 * time.Second
		}
		if kept.opt.Timeout != want {
			t.Errorf("timeout %v became %v, want %v", d, kept.opt.Timeout, want)
		}
	}
}

// The product must never call an agent safe, secure, or verified.
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
	// The dependency alert is a rendered email like the rest: it is the one
	// that talks about a vulnerability staying installable, which is the
	// sentence most likely to drift.
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
		t.Errorf("reviewer rationale missing:\n%s", body)
	}

	// The exact mail for every decision the API can pass, and the fallback
	// for one it cannot: the headline, the sentence about what happens next,
	// the optional reviewer and rationale lines, the report-card link and
	// the footer.
	const link = "\nReport card:\nhttps://registry.example/acme/widget/versions/2.0.0\n"
	const (
		published = "The version is now resolvable and its attestation is signed. The full\n" +
			"scan report stays public: publication records what was found, it does\n" +
			"not certify that nothing was missed.\n"
		approved = "A reviewer approved it, and it is published as soon as the registry\n" +
			"has signed its attestation, which takes moments. The full scan report\n" +
			"stays public: publication records what was found, it does not certify\n" +
			"that nothing was missed.\n"
		rejected = "The version will not be published, and that decision is final for\n" +
			"these bytes. A new version with the findings addressed goes through\n" +
			"the pipeline from the start.\n"
		yanked = "A yanked version still resolves for an exact pin, with a warning, so\n" +
			"copies pinned to it keep working. It no longer resolves for a range,\n" +
			"and a yank is permanent: the fix is a new version.\n"
		held = "The gate did not clear it, so a human reviewer has the version.\n" +
			"Nothing is needed from you until they decide; you will get a mail\n" +
			"when they do.\n"
	)
	for _, c := range []struct {
		name, decision, reviewer, rationale string
		headline, detail, extra             string
	}{
		{"published", "published", "", "", "published", published, ""},
		{"approved", "approved", "", "", "approved", approved, ""},
		{"rejected", "rejected", "", "", "rejected", rejected, ""},
		{"yanked", "yanked", "", "", "yanked", yanked, ""},
		{"needs_review", "needs_review", "", "", "held for review", held, ""},
		{"an unknown decision is named as given", "reopened", "", "", "reopened", "", ""},
		{"reviewer and rationale", "rejected", "rev", "finding confirmed", "rejected", rejected,
			"\nReviewer: rev\nRationale: finding confirmed\n"},
		{"reviewer alone", "published", "rev", "", "published", published, "\nReviewer: rev\n"},
		{"rationale alone", "published", "", "benign fixture", "published", published, "Rationale: benign fixture\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			n, sent := capture(t)
			if err := n.ReviewDecided(t.Context(), ReviewNotice{
				ToEmail: "u@example.test", Agent: "acme/widget", Version: "2.0.0",
				Decision: c.decision, Reviewer: c.reviewer, Rationale: c.rationale,
			}); err != nil {
				t.Fatal(err)
			}
			raw := (*sent)[0]
			want := "acme/widget 2.0.0 was " + c.headline + ".\n\n" + c.detail + c.extra + link + wantFooter("registry.example", "")
			if got := bodyOf(raw); got != want {
				t.Errorf("body:\n%q\nwant:\n%q", got, want)
			}
			if got, want := headerOf(raw, "Subject"), "registry.example: acme/widget 2.0.0 "+c.headline; got != want {
				t.Errorf("subject = %q, want %q", got, want)
			}
		})
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
	// Quarantine does not reach installed copies. Saying otherwise would
	// leave an author believing a problem was contained when it was not.
	if !strings.Contains(flatten(body), "are not reached by this change") {
		t.Errorf("quarantine notice does not say installed copies are unaffected:\n%s", body)
	}
	// The bare fallback is the site's route shape.
	if !strings.Contains(body, "https://registry.example/acme/widget/versions/1.0.0") {
		t.Errorf("report link missing or wrong:\n%s", body)
	}
	if strings.Contains(body, "/agents/acme/widget") {
		t.Errorf("report link still uses the dead /agents/… path:\n%s", body)
	}

	// The whole mail, with the recorded reason and an explicit report URL,
	// and again with neither, a severity unset and no origin to build a
	// link from.
	const (
		head = "A rescan of acme/widget 1.0.0 under a newer ruleset produced a\n" +
			"finding at %s severity. The version is now quarantined.\n\n" +
			"What that means: the version no longer resolves for new installs, not\n" +
			"even by exact version, and a download of it answers 409. Copies already\n" +
			"installed elsewhere are not reached by this change. Your other\n" +
			"published versions resolve unless a rescan quarantined them too.\n\n"
		tail = "A platform reviewer now has the version and can restore it to\n" +
			"published or yank it. Their rationale is recorded with the version,\n" +
			"and there is no way to contest a finding from the report card today.\n"
	)
	n2, sent2 := capture(t)
	if err := n2.AgentQuarantined(t.Context(), QuarantineNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0", Severity: "high",
		Reason: "obfuscated payload in a prompt file", ReportURL: "https://elsewhere.example/r/1",
	}); err != nil {
		t.Fatal(err)
	}
	wantFull := strings.Replace(head, "%s", "high", 1) +
		"Reason recorded: obfuscated payload in a prompt file\n\n" +
		"Report card (findings, ruleset version, scan date):\nhttps://elsewhere.example/r/1\n\n" +
		tail + wantFooter("registry.example", "")
	if got := bodyOf((*sent2)[0]); got != wantFull {
		t.Errorf("quarantine body:\n%q\nwant:\n%q", got, wantFull)
	}
	if got, want := headerOf((*sent2)[0], "Subject"), "registry.example: acme/widget 1.0.0 quarantined after rescan"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}
	bare := renderer{registry: "Agentry"}.quarantine(QuarantineNotice{Agent: "acme/widget", Version: "1.0.0"})
	if want := strings.Replace(head, "%s", "unspecified", 1) + tail + wantFooter("Agentry", ""); bare.Body != want {
		t.Errorf("bare quarantine body:\n%q\nwant:\n%q", bare.Body, want)
	}
}

// With the deployment's resolved link (Options.Links.ReportCard) the
// quarantine and review mails carry it, and an explicit ReportURL on the
// notice still wins.
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

	// A resolver with nothing to say falls back to the site's route shape,
	// the origin's trailing slash is not doubled, the caller's URL beats
	// both, and with no origin and no resolver the mail names no link.
	silent := renderer{registry: "R", baseURL: "https://site.example/", reportCard: func(string, string) string { return "" }}
	if got, want := silent.reportLink("", "acme/widget", "1.0.0"), "https://site.example/acme/widget/versions/1.0.0"; got != want {
		t.Errorf("fallback report link = %q, want %q", got, want)
	}
	if got := silent.reportLink("https://elsewhere.example/r", "acme/widget", "1.0.0"); got != "https://elsewhere.example/r" {
		t.Errorf("explicit report link = %q", got)
	}
	if got := (renderer{registry: "R"}).reportLink("", "acme/widget", "1.0.0"); got != "" {
		t.Errorf("report link with no origin = %q, want none", got)
	}
	if m := (renderer{registry: "R"}).review(ReviewNotice{Agent: "acme/widget", Version: "1.0.0", Decision: "rejected"}); strings.Contains(m.Body, "Report card") {
		t.Errorf("review mail names a report card it has no link for:\n%s", m.Body)
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

	// The whole mail: it names the account, says what the link does and does
	// not unlock, and tells someone who did not sign up to ignore it.
	wantBody := "Follow this link to confirm this address and activate the registry.example account chris.\n\n" +
		"https://registry.example/auth/verify-email?token=secret-token\n\n" +
		"The link works once. Until this address is confirmed, the account can\n" +
		"browse but not publish.\n\n" +
		"If you did not create an account named chris, do not follow the\n" +
		"link: someone may have signed up with your address. Ignore this message.\n" +
		wantFooter("registry.example", "")
	if got := bodyOf((*sent)[0]); got != wantBody {
		t.Errorf("verification body:\n%q\nwant:\n%q", got, wantBody)
	}
	if got, want := headerOf((*sent)[0], "Subject"), "registry.example: activate your account"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}

	// The deployment's resolved link replaces the built one, token included.
	n.render.verifyEmail = func(tok string) string { return "https://site.example/verify/" + tok }
	if err := n.EmailVerification(t.Context(), "u@example.test", "chris", "t2"); err != nil {
		t.Fatal(err)
	}
	got := bodyOf((*sent)[1])
	if !strings.Contains(got, "\nhttps://site.example/verify/t2\n") || strings.Contains(got, "registry.example/auth/verify-email") {
		t.Errorf("resolved verification link not used:\n%s", got)
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

	// Every header value is checked for a bare CR and a bare LF as well as
	// the pair: the subject, the recipient and the configured sender.
	for _, c := range []struct {
		name, to, subject, from string
	}{
		{"subject LF", "u@example.test", "ok\nBcc: attacker@example.test", ""},
		{"subject CR", "u@example.test", "ok\rBcc: attacker@example.test", ""},
		{"subject CRLF mid-line", "u@example.test", "ok\r\nBcc: a@example.test\r\nx", ""},
		{"recipient LF", "u@example.test\nBcc: attacker@example.test", "ok", ""},
		{"recipient CR", "u@example.test\rBcc: attacker@example.test", "ok", ""},
		{"sender CRLF", "u@example.test", "ok", "Agentry <no-reply@example.test>\r\nBcc: attacker@example.test"},
		{"sender LF", "u@example.test", "ok", "no-reply@example.test\nBcc: attacker@example.test"},
	} {
		n, _ := capture(t)
		if c.from != "" {
			n.opt.From = c.from
		}
		raw, err := n.compose(c.to, message{Subject: c.subject, Body: "body"})
		if err == nil {
			t.Errorf("%s: compose accepted it:\n%s", c.name, raw)
			continue
		}
		if err.Error() != "notify: header value contains a line break" || raw != nil {
			t.Errorf("%s: compose = %q, %v", c.name, raw, err)
		}
	}

	// The same refusal reaches the caller of a delivery, and nothing is
	// sent: a subject composed elsewhere is the realistic carrier.
	n2, sent := capture(t)
	if err := n2.Rendered(t.Context(), RenderedNotice{
		ToEmail: "u@example.test", Subject: "hello\r\nBcc: attacker@example.test", Text: "body", Kind: KindBilling,
	}); err == nil || !strings.Contains(err.Error(), "line break") {
		t.Errorf("Rendered with an injected subject = %v", err)
	}
	if len(*sent) != 0 {
		t.Errorf("a message with an injected header was sent:\n%s", (*sent)[0])
	}

	// Padding around a subject is trimmed, not refused and not kept.
	n3, _ := capture(t)
	raw3, err := n3.compose("u@example.test", message{Subject: "  padded  ", Body: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if got := headerOf(string(raw3), "Subject"); got != "padded" {
		t.Errorf("subject = %q, want %q", got, "padded")
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
	err := n.EmailVerification(t.Context(), "not an address", "chris", "tok")
	if err == nil || !strings.Contains(err.Error(), `notify: recipient "not an address"`) {
		t.Errorf("malformed-recipient error = %v", err)
	}

	// A recipient given as "Name <address>" is delivered to the bare address,
	// from the configured sender's address, under the configured bound, and
	// the log line names the kind and the address but never the token.
	logger, logs := logSink()
	n2, _ := capture(t)
	n2.log = logger
	n2.opt.Timeout = 20 * time.Second
	var gotFrom string
	var gotTo []string
	var gotMsg string
	var gotDeadline time.Time
	var hasDeadline bool
	n2.send = func(ctx context.Context, from string, to []string, msg []byte) error {
		gotFrom, gotTo, gotMsg = from, to, string(msg)
		gotDeadline, hasDeadline = ctx.Deadline()
		return nil
	}
	start := time.Now()
	if err := n2.EmailVerification(t.Context(), "Chris <u@example.test>", "chris", "tok-secret-1"); err != nil {
		t.Fatal(err)
	}
	if gotFrom != "no-reply@example.test" {
		t.Errorf("envelope sender = %q", gotFrom)
	}
	if len(gotTo) != 1 || gotTo[0] != "u@example.test" {
		t.Errorf("envelope recipients = %q, want the bare address", gotTo)
	}
	if got := headerOf(gotMsg, "To"); got != "u@example.test" {
		t.Errorf("To header = %q, want the bare address", got)
	}
	if !hasDeadline || gotDeadline.After(start.Add(20*time.Second+time.Second)) || gotDeadline.Before(start.Add(19*time.Second)) {
		t.Errorf("send deadline = %v (set %v), want about 20s after the call", gotDeadline, hasDeadline)
	}
	line := logs.String()
	if !strings.Contains(line, "notify: sent") || !strings.Contains(line, "kind=email_verification") {
		t.Errorf("delivery not logged with its kind: %s", line)
	}
	if strings.Contains(line, "tok-secret-1") {
		t.Errorf("the verification token reached the log: %s", line)
	}

	// A digest with nobody in it is not a mail.
	n3, sent3 := capture(t)
	if err := n3.OrgPendingMembers(t.Context(), PendingMembersNotice{ToEmail: "admin@example.test", Org: "acme"}); err != nil {
		t.Errorf("empty digest = %v, want nil", err)
	}
	if len(*sent3) != 0 {
		t.Errorf("an empty digest was sent:\n%s", (*sent3)[0])
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

	// CRLF input is not doubled, only a leading dot is stuffed (a dot inside
	// a line is left alone), a stuffed line is stuffed once more, and an
	// empty body stays empty.
	for _, c := range []struct{ name, in, want string }{
		{"CRLF input", "a\r\n.b\r\nc\r\n", "a\r\n..b\r\nc\r\n"},
		{"dot inside a line", "a.b\nend.\n", "a.b\r\nend.\r\n"},
		{"already stuffed", "..x\n", "...x\r\n"},
		{"empty", "", ""},
		{"no trailing newline", "x\n.", "x\r\n.."},
	} {
		if got := normalizeBody(c.in); got != c.want {
			t.Errorf("%s: normalizeBody(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
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

	// The message exactly: header order, the clock's date, the 8-bit body
	// marker, the blank line, and a body that is normalised on the way in.
	want := "From: \"Agentry\" <no-reply@example.test>\r\n" +
		"To: u@example.test\r\n" +
		"Subject: hello\r\n" +
		"Date: Sat, 29 Aug 2026 12:00:00 +0000\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n" +
		"Auto-Submitted: auto-generated\r\n" +
		"\r\n" +
		"body\r\n"
	if s != want {
		t.Errorf("composed message:\n%q\nwant:\n%q", s, want)
	}
	// The date keeps the clock's own zone offset.
	n.nowFn = func() time.Time { return time.Date(2026, 8, 29, 12, 0, 0, 0, time.FixedZone("far", 5*3600)) }
	zoned, err := n.compose("u@example.test", message{Subject: "s", Body: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := headerOf(string(zoned), "Date"), "Sat, 29 Aug 2026 12:00:00 +0500"; got != want {
		t.Errorf("Date = %q, want %q", got, want)
	}
	// The body goes through dot-stuffing inside compose, not only on its own.
	stuffed, err := n.compose("u@example.test", message{Subject: "s", Body: "x\n.\ny\n"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(stuffed), "\r\n\r\nx\r\n..\r\ny\r\n") {
		t.Errorf("compose did not dot-stuff the body:\n%q", stuffed)
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
	if got, want := headerOf(string(raw), "Subject"), "=?utf-8?q?caf=C3=A9_findings?="; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}
	if got := encodeHeader("plain ascii subject"); got != "plain ascii subject" {
		t.Errorf("an ASCII subject was altered: %q", got)
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

	// Every notification names its own kind in the error, wraps the
	// transport's error, and logs the failure under that kind, without the
	// verification token it may carry.
	ctx := t.Context()
	to := "u@example.test"
	for _, c := range []struct {
		kind string
		call func(n *SMTPNotifier) error
	}{
		{"email_verification", func(n *SMTPNotifier) error { return n.EmailVerification(ctx, to, "chris", "tok-secret-2") }},
		{"agent_quarantined", func(n *SMTPNotifier) error { return n.AgentQuarantined(ctx, QuarantineNotice{ToEmail: to}) }},
		{"review_decided", func(n *SMTPNotifier) error { return n.ReviewDecided(ctx, ReviewNotice{ToEmail: to}) }},
		{"advisory_published", func(n *SMTPNotifier) error { return n.AdvisoryPublished(ctx, AdvisoryNotice{ToEmail: to}) }},
		{"mcp_dependency_alert", func(n *SMTPNotifier) error {
			return n.MCPDependencyAlert(ctx, MCPDependencyAlertNotice{ToEmail: to})
		}},
		{"org_invite", func(n *SMTPNotifier) error { return n.OrgInvite(ctx, InviteOffer{ToEmail: to}) }},
		{"org_access_request", func(n *SMTPNotifier) error { return n.OrgAccessRequest(ctx, AccessRequestNotice{ToEmail: to}) }},
		{"org_pending_members", func(n *SMTPNotifier) error {
			return n.OrgPendingMembers(ctx, PendingMembersNotice{ToEmail: to, Members: []PendingMember{{Handle: "kim"}}})
		}},
		{"billing", func(n *SMTPNotifier) error {
			return n.Rendered(ctx, RenderedNotice{ToEmail: to, Subject: "s", Text: "t", Kind: KindBilling})
		}},
		{"schedules", func(n *SMTPNotifier) error {
			return n.Rendered(ctx, RenderedNotice{ToEmail: to, Subject: "s", Text: "t", Kind: KindSchedule})
		}},
	} {
		t.Run(c.kind, func(t *testing.T) {
			n, _ := capture(t)
			logger, logs := logSink()
			n.log = logger
			cause := errors.New("connection refused")
			n.send = func(context.Context, string, []string, []byte) error { return cause }
			err := c.call(n)
			if err == nil {
				t.Fatal("a failed send reported success")
			}
			if want := "notify: send " + c.kind + ": connection refused"; err.Error() != want {
				t.Errorf("error = %q, want %q", err, want)
			}
			if !errors.Is(err, cause) {
				t.Errorf("error %v does not wrap the transport's error", err)
			}
			line := logs.String()
			if !strings.Contains(line, "smtp send failed") || !strings.Contains(line, "kind="+c.kind) || !strings.Contains(line, "level=ERROR") {
				t.Errorf("failure not logged under its kind: %s", line)
			}
			if strings.Contains(line, "tok-secret-2") {
				t.Errorf("the token reached the log: %s", line)
			}
		})
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

	// What each method writes: the level, the facts an operator needs, the
	// recipient's address masked, and nothing a reader could act on that
	// belongs only to the recipient (the verification code, an acceptance
	// link, another person's address, the composed text).
	const masked = "to=u…@example.test"
	for _, c := range []struct {
		name   string
		call   func(LogNotifier) error
		level  string
		msg    string
		wants  []string
		forbid []string
	}{
		{"verification", func(l LogNotifier) error { return l.EmailVerification(ctx, "u@example.test", "chris", "tok-secret-3") },
			"INFO", "notify: email verification not sent (no sender configured)", []string{masked}, []string{"tok-secret-3", "u@example.test"}},
		{"quarantine", func(l LogNotifier) error {
			return l.AgentQuarantined(ctx, QuarantineNotice{ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0", Severity: "high", Reason: "obfuscated", ReportURL: "https://r.example/agyr_SECRETLINK"})
		}, "WARN", "notify: agent quarantined (author notification)",
			[]string{masked, "agent=acme/widget", "version=1.0.0", "severity=high", "reason=obfuscated"}, []string{"u@example.test", "SECRETLINK"}},
		{"review", func(l LogNotifier) error {
			return l.ReviewDecided(ctx, ReviewNotice{ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0", Decision: "rejected", Reviewer: "rev"})
		}, "INFO", "notify: review decided (author notification)",
			[]string{masked, "agent=acme/widget", "version=1.0.0", "decision=rejected", "reviewer=rev"}, []string{"u@example.test"}},
		{"advisory", func(l LogNotifier) error {
			return l.AdvisoryPublished(ctx, AdvisoryNotice{ToEmail: "u@example.test", Agent: "acme/widget", Severity: "critical"})
		}, "WARN", "notify: advisory published (author notification)",
			[]string{masked, "agent=acme/widget", "severity=critical"}, []string{"u@example.test"}},
		{"dependency alert", func(l LogNotifier) error {
			return l.MCPDependencyAlert(ctx, MCPDependencyAlertNotice{ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0", Server: "npm:srv@1.2.3", Severity: "high", Advisories: []string{"GHSA-1"}})
		}, "WARN", "notify: MCP dependency alert (author notification)",
			[]string{masked, "agent=acme/widget", "version=1.0.0", "server=npm:srv@1.2.3", "severity=high", "advisories=[GHSA-1]"}, []string{"u@example.test"}},
		{"invite", func(l LogNotifier) error {
			return l.OrgInvite(ctx, InviteOffer{ToEmail: "u@example.test", Org: "acme", Role: "member", AcceptURL: "https://r.example/agyi_SECRETLINK"})
		}, "INFO", "notify: org invite",
			[]string{masked, "org=acme", "role=member"}, []string{"u@example.test", "SECRETLINK"}},
		{"access request", func(l LogNotifier) error {
			return l.OrgAccessRequest(ctx, AccessRequestNotice{ToEmail: "u@example.test", Org: "acme", Requester: "kim", RequesterEmail: "kim@acme.test"})
		}, "INFO", "notify: org access request",
			[]string{masked, "org=acme", "requester=kim"}, []string{"u@example.test", "kim@acme.test"}},
		{"pending members", func(l LogNotifier) error {
			return l.OrgPendingMembers(ctx, PendingMembersNotice{ToEmail: "u@example.test", Org: "acme", Members: []PendingMember{{Handle: "kim", Email: "kim@acme.test"}, {Handle: "lee", Email: "lee@acme.test"}}})
		}, "INFO", "notify: org pending members",
			[]string{masked, "org=acme", "pending=2"}, []string{"u@example.test", "kim@acme.test", "lee@acme.test"}},
		{"rendered", func(l LogNotifier) error {
			return l.Rendered(ctx, RenderedNotice{ToEmail: "u@example.test", Subject: "Payment failed", Text: "composed-body-secret", Kind: KindBilling})
		}, "INFO", "notify: rendered message",
			[]string{masked, "kind=billing", `subject="Payment failed"`}, []string{"u@example.test", "composed-body-secret"}},
	} {
		t.Run("logs "+c.name, func(t *testing.T) {
			logger, logs := logSink()
			if err := c.call(LogNotifier{Log: logger}); err != nil {
				t.Fatal(err)
			}
			line := logs.String()
			if strings.Count(line, "\n") != 1 || !strings.Contains(line, "level="+c.level+" ") || !strings.Contains(line, `msg="`+c.msg+`"`) {
				t.Errorf("log = %q, want one %s line %q", line, c.level, c.msg)
			}
			for _, w := range c.wants {
				if !strings.Contains(line, w) {
					t.Errorf("log lacks %q: %s", w, line)
				}
			}
			for _, f := range c.forbid {
				if strings.Contains(line, f) {
					t.Errorf("log carries %q: %s", f, line)
				}
			}
		})
	}

	// With no logger of its own the notifier writes to the process default.
	t.Run("no logger uses the process default", func(t *testing.T) {
		prev := slog.Default()
		t.Cleanup(func() { slog.SetDefault(prev) })
		logger, logs := logSink()
		slog.SetDefault(logger)
		if err := (LogNotifier{}).OrgInvite(ctx, InviteOffer{ToEmail: "u@example.test", Org: "acme"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(logs.String(), "notify: org invite") {
			t.Errorf("the process logger saw %q", logs.String())
		}
	})
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
	// The mail must not promise "the address will not be used", which
	// nothing in the server keeps: no job deletes an unconfirmed account,
	// and a later org grant mails the address anyway. The mail states the
	// gate instead.
	if strings.Contains(m.Body, "will not be used") {
		t.Errorf("verification mail promises the address goes unused:\n%s", m.Body)
	}
	// Everything after the opening sentence, which names the account.
	want := "Verification code: tok123\n\n" +
		"The code works once. Until this address is confirmed, the account can\n" +
		"browse but not publish.\n\n" +
		"If you did not create an account named chris, do not follow the\n" +
		"link: someone may have signed up with your address. Ignore this message.\n" +
		wantFooter("Agentry", "")
	if opening, rest, _ := strings.Cut(m.Body, "\n\n"); rest != want || !strings.Contains(opening, "activate the Agentry account chris.") {
		t.Errorf("code-branch body:\n%q\nwant the opening sentence, then:\n%q", m.Body, want)
	}
	if m.Subject != "Agentry: activate your account" {
		t.Errorf("subject = %q", m.Subject)
	}
}

// TestAdvisoryNamesItsRangeAndTheFooterNamesTheSettingsPage:
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

	// The advisory mail exactly: every optional line present, the public
	// advisories page as the link when the notice has none, and the footer
	// with the settings page.
	const (
		open = "The registry published an advisory naming acme/widget. An advisory is\n" +
			"the public record of a security problem in a published QuickAgent.\n\n"
		closing = "Nothing in the registry reaches copies that are already installed.\n" +
			"This advisory and its page are how a consumer finds out.\n"
	)
	wantAdvisory := open + "Severity: high\nAffected versions: <1.0.1\nSummary: leaks the token\n" +
		"\nhttps://registry.example/advisories\n\n" + closing + wantFooter("registry.example", "https://site.example/settings")
	if got := bodyOf((*sent)[0]); got != wantAdvisory {
		t.Errorf("advisory body:\n%q\nwant:\n%q", got, wantAdvisory)
	}
	if got, want := headerOf((*sent)[0], "Subject"), "registry.example: advisory published for acme/widget"; got != want {
		t.Errorf("advisory subject = %q, want %q", got, want)
	}
	// The notice's own page wins; with nothing set the mail says severity
	// is unspecified and names no range, summary or link.
	own := n.render.advisory(AdvisoryNotice{Agent: "acme/widget", Severity: "low", AdvisoryURL: "https://pub.example/a/1"})
	if want := open + "Severity: low\n\nhttps://pub.example/a/1\n\n" + closing + wantFooter("registry.example", "https://site.example/settings"); own.Body != want {
		t.Errorf("advisory with its own URL:\n%q\nwant:\n%q", own.Body, want)
	}
	bare := renderer{registry: "Agentry"}.advisory(AdvisoryNotice{Agent: "acme/widget"})
	if want := open + "Severity: unspecified\n\n" + closing + wantFooter("Agentry", ""); bare.Body != want {
		t.Errorf("bare advisory body:\n%q\nwant:\n%q", bare.Body, want)
	}
}

// The dependency alert names the server, the severity, the advisories and
// the fixed versions on label lines, says the version stays installable and
// what clears the alert, and links the agent's page, else the dashboard.
func TestMCPDependencyAlertMailNamesTheServerAndTheFix(t *testing.T) {
	const (
		lead = "acme/widget@1.0.0 declares an MCP server that now has a known\n" +
			"vulnerability.\n\n"
		tail = "\nThe version stays published and installable. The QuickAgent's page\n" +
			"and your dashboard list this alert.\n\n" +
			"To clear it, publish a new version that pins a fixed server version,\n" +
			"then yank the affected one. The alert closes when the version leaves\n" +
			"published.\n"
	)
	n, sent := capture(t)
	n.render.dashboard = "https://site.example/dash"
	if err := n.MCPDependencyAlert(t.Context(), MCPDependencyAlertNotice{
		ToEmail: "u@example.test", Agent: "acme/widget", Version: "1.0.0",
		Server: "npm:server-filesystem@1.2.3", Severity: "high",
		Advisories: []string{"GHSA-1", "CVE-2"}, FixedIn: []string{"1.2.4", "1.3.0"},
		AgentURL: "https://registry.example/acme/widget",
	}); err != nil {
		t.Fatal(err)
	}
	want := lead + "Server: npm:server-filesystem@1.2.3\nSeverity: high\nAdvisories: GHSA-1, CVE-2\nFixed in: 1.2.4, 1.3.0\n" +
		tail + "\nhttps://registry.example/acme/widget\n" + wantFooter("registry.example", "")
	if got := bodyOf((*sent)[0]); got != want {
		t.Errorf("alert body:\n%q\nwant:\n%q", got, want)
	}
	if got, want := headerOf((*sent)[0], "Subject"), "registry.example: acme/widget@1.0.0 uses a vulnerable MCP server (high)"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}

	// Without the agent's page the dashboard is the link; without either,
	// no link; with no advisories, no fixed versions and no severity, only
	// the server line and an unspecified severity.
	notice := MCPDependencyAlertNotice{Agent: "acme/widget", Version: "1.0.0", Server: "pypi:srv@0.1.0"}
	viaDash := n.render.mcpAlert(notice)
	if want := lead + "Server: pypi:srv@0.1.0\nSeverity: unspecified\n" + tail + "\nhttps://site.example/dash\n" + wantFooter("registry.example", ""); viaDash.Body != want {
		t.Errorf("alert body with the dashboard link:\n%q\nwant:\n%q", viaDash.Body, want)
	}
	if viaDash.Subject != "registry.example: acme/widget@1.0.0 uses a vulnerable MCP server (unspecified)" {
		t.Errorf("subject = %q", viaDash.Subject)
	}
	// One advisory and one fixed version are still listed.
	one := n.render.mcpAlert(MCPDependencyAlertNotice{
		Agent: "acme/widget", Version: "1.0.0", Server: "pypi:srv@0.1.0", Severity: "critical",
		Advisories: []string{"GHSA-9"}, FixedIn: []string{"0.1.1"},
	})
	if want := lead + "Server: pypi:srv@0.1.0\nSeverity: critical\nAdvisories: GHSA-9\nFixed in: 0.1.1\n" + tail + "\nhttps://site.example/dash\n" + wantFooter("registry.example", ""); one.Body != want {
		t.Errorf("alert body with one advisory and one fix:\n%q\nwant:\n%q", one.Body, want)
	}
	noLink := renderer{registry: "Agentry"}.mcpAlert(notice)
	if want := lead + "Server: pypi:srv@0.1.0\nSeverity: unspecified\n" + tail + wantFooter("Agentry", ""); noLink.Body != want {
		t.Errorf("alert body with no link:\n%q\nwant:\n%q", noLink.Body, want)
	}
}

// An invitation is an offer: it names the organisation (display name with the
// handle, or the handle alone), who invited and for what role, the link to
// accept, an expiry in UTC, and says nothing changes until the person accepts.
func TestOrgInviteMailIsAnOfferWithAnExpiry(t *testing.T) {
	const tail = "\nNothing changes until you accept, and only an account signed in with\n" +
		"this address can. If you did not expect this invitation, ignore it and\n" +
		"it will expire.\n"
	n, sent := capture(t)
	// 02:00 at +05:00 on the 6th is the evening of the 5th in UTC.
	expires := time.Date(2026, 9, 6, 2, 0, 0, 0, time.FixedZone("far", 5*3600))
	if err := n.OrgInvite(t.Context(), InviteOffer{
		ToEmail: "u@example.test", Org: "acme", OrgDisplayName: "Acme Inc", Role: "member", InvitedBy: "kim",
		AcceptURL: "https://registry.example/invitations/abc", ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
	want := "You have been invited to join the Acme Inc (acme) organization on registry.example.\n" +
		"Invited by: kim\nRole: member\n\n" +
		"Accept it here:\nhttps://registry.example/invitations/abc\n\n" +
		"The invitation expires 5 September 2026.\n" + tail + wantFooter("registry.example", "")
	if got := bodyOf((*sent)[0]); got != want {
		t.Errorf("invitation body:\n%q\nwant:\n%q", got, want)
	}
	if got, want := headerOf((*sent)[0], "Subject"), "registry.example: you are invited to the acme organization"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}

	r := renderer{registry: "Agentry"}
	bare := r.invite(InviteOffer{Org: "acme"})
	if want := "You have been invited to join the acme organization on Agentry.\n" + tail + wantFooter("Agentry", ""); bare.Body != want {
		t.Errorf("bare invitation body:\n%q\nwant:\n%q", bare.Body, want)
	}
	for _, display := range []string{"", "acme"} {
		if got := r.invite(InviteOffer{Org: "acme", OrgDisplayName: display}).Body; !strings.HasPrefix(got, "You have been invited to join the acme organization on Agentry.\n") {
			t.Errorf("display name %q: body begins %q", display, got)
		}
	}
}

// The access-request mail tells an admin who asks, from which verified
// address, that nobody joins uninvited, and where to invite them.
func TestOrgAccessRequestMailPointsAtTheConsole(t *testing.T) {
	const (
		why = "Their address is at the domain registered to your organization, which is\n" +
			"why this reached you. Nobody joins uninvited: to add them, send them an\n" +
			"invitation from the organization's console"
		tail = "\nIf you do not know them, there is nothing to do: they hold nothing of the\n" +
			"organization, and they can ask again at most once a day.\n"
	)
	n, sent := capture(t)
	if err := n.OrgAccessRequest(t.Context(), AccessRequestNotice{
		ToEmail: "admin@example.test", Org: "acme", OrgDisplayName: "Acme Inc",
		Requester: "kim", RequesterEmail: "kim@acme.test", ConsoleURL: "https://registry.example/console/acme",
	}); err != nil {
		t.Fatal(err)
	}
	want := "kim <kim@acme.test> asks to join the Acme Inc (acme) organization on registry.example.\n\n" +
		why + ":\nhttps://registry.example/console/acme\n" + tail + wantFooter("registry.example", "")
	if got := bodyOf((*sent)[0]); got != want {
		t.Errorf("request body:\n%q\nwant:\n%q", got, want)
	}
	if got, want := headerOf((*sent)[0], "Subject"), "registry.example: kim asks to join the acme organization"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}
	if got, want := headerOf((*sent)[0], "To"), "admin@example.test"; got != want {
		t.Errorf("To = %q, want the admin", got)
	}

	noConsole := renderer{registry: "Agentry"}.accessRequest(AccessRequestNotice{Org: "acme", Requester: "kim", RequesterEmail: "kim@acme.test"})
	if want := "kim <kim@acme.test> asks to join the acme organization on Agentry.\n\n" + why + ".\n" + tail + wantFooter("Agentry", ""); noConsole.Body != want {
		t.Errorf("request body with no console link:\n%q\nwant:\n%q", noConsole.Body, want)
	}
}

// The digest names each waiting person with the door they came through, in
// arrival order, says what approving and declining do, and varies its
// opening and its subject with the count.
func TestOrgPendingMembersDigestNamesEachDoor(t *testing.T) {
	const (
		domain = "their address is at the domain registered to your organization"
		scim   = "your organization's identity provider provisioned them"
		mid    = "\nEach of them holds nothing of the organization until an admin approves\n" +
			"them, which is also where their seat is taken; declining removes them and\n" +
			"is remembered. Approve or decline from the organization's console"
		tail = "\nYou are told about each person once.\n"
	)
	n, sent := capture(t)
	if err := n.OrgPendingMembers(t.Context(), PendingMembersNotice{
		ToEmail: "admin@example.test", Org: "acme", OrgDisplayName: "Acme Inc",
		Members: []PendingMember{
			{Handle: "kim", Email: "kim@acme.test", Via: "domain"},
			{Handle: "lee", Email: "lee@acme.test", Via: "scim"},
		},
		ConsoleURL: "https://registry.example/console/acme",
	}); err != nil {
		t.Fatal(err)
	}
	want := "2 people are waiting to join the Acme Inc (acme) organization on registry.example:\n\n" +
		"  kim <kim@acme.test> — " + domain + "\n" +
		"  lee <lee@acme.test> — " + scim + "\n" +
		mid + ":\nhttps://registry.example/console/acme\n" + tail + wantFooter("registry.example", "")
	if got := bodyOf((*sent)[0]); got != want {
		t.Errorf("digest body:\n%q\nwant:\n%q", got, want)
	}
	if got, want := headerOf((*sent)[0], "Subject"), "registry.example: 2 people are waiting to join the acme organization"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}

	one := renderer{registry: "Agentry"}.pendingMembers(PendingMembersNotice{
		Org: "acme", Members: []PendingMember{{Handle: "kim", Email: "kim@acme.test"}},
	})
	if want := "One person is waiting to join the acme organization on Agentry:\n\n" +
		"  kim <kim@acme.test> — " + domain + "\n" + mid + ".\n" + tail + wantFooter("Agentry", ""); one.Body != want {
		t.Errorf("single-person digest body:\n%q\nwant:\n%q", one.Body, want)
	}
	if one.Subject != "Agentry: kim is waiting to join the acme organization" {
		t.Errorf("single-person subject = %q", one.Subject)
	}
}

// A message composed elsewhere is carried in the core's frame and nothing
// more: the registry's name on the subject, the text as given (nothing in it
// is interpreted), one closing newline, and the footer.
func TestRenderedMailCarriesTheTextInTheFrame(t *testing.T) {
	r := renderer{registry: "Agentry"}
	text := "Your card was declined.\n{{.Name}} Subject: not a header\n\n\n"
	m := r.rendered(RenderedNotice{Subject: "  Payment failed  ", Text: text, Kind: KindBilling})
	if m.Subject != "Agentry: Payment failed" {
		t.Errorf("subject = %q", m.Subject)
	}
	if want := "Your card was declined.\n{{.Name}} Subject: not a header\n" + wantFooter("Agentry", ""); m.Body != want {
		t.Errorf("body:\n%q\nwant:\n%q", m.Body, want)
	}

	// Only trailing newlines go: indentation and trailing spaces are the
	// composer's.
	indented := r.rendered(RenderedNotice{Subject: "s", Text: "  indented first\nlast line  \n"})
	if want := "  indented first\nlast line  \n" + wantFooter("Agentry", ""); indented.Body != want {
		t.Errorf("body:\n%q\nwant:\n%q", indented.Body, want)
	}

	n, sent := capture(t)
	n.render.settings = "https://site.example/settings"
	if err := n.Rendered(t.Context(), RenderedNotice{ToEmail: "u@example.test", Subject: "Payment failed", Text: "Line one", Kind: KindBilling}); err != nil {
		t.Fatal(err)
	}
	if got, want := headerOf((*sent)[0], "Subject"), "registry.example: Payment failed"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}
	if want := "Line one\n" + wantFooter("registry.example", "https://site.example/settings"); bodyOf((*sent)[0]) != want {
		t.Errorf("body:\n%q\nwant:\n%q", bodyOf((*sent)[0]), want)
	}
}

// smtpScript says how the stand-in SMTP server behaves.
type smtpScript struct {
	starttls, auth                                 bool // extensions it advertises
	rejectAuth, rejectMail, rejectRcpt, rejectData bool
	// cert, when set, is what the server presents after STARTTLS; without
	// it the server drops the connection there.
	cert *tls.Certificate
	// trusted makes the server present the certificate the system roots
	// vouch for.
	trusted bool
	// maxTLS, when set, caps the protocol version the server will speak.
	maxTLS uint16
}

var (
	trustedOnce sync.Once
	trusted     *tls.Certificate
)

// trustedCert is a certificate for 127.0.0.1 that this process's system roots
// vouch for, so a STARTTLS handshake against it verifies the way it would
// against a real server. The roots are read once per process, hence the
// certificate is made once too.
func trustedCert(t *testing.T) *tls.Certificate {
	t.Helper()
	trustedOnce.Do(func() {
		trusted = selfSignedCert(t)
		file := t.TempDir() + "/roots.pem"
		block := &pem.Block{Type: "CERTIFICATE", Bytes: trusted.Certificate[0]}
		if err := os.WriteFile(file, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SSL_CERT_FILE", file)
	})
	return trusted
}

// selfSignedCert is a certificate for 127.0.0.1 that no root vouches for.
func selfSignedCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveSMTP runs a one-connection SMTP server on a loopback port. finish
// waits for the conversation to end (or, if no client ever connected, ends
// it) and returns the commands the client sent and the message it
// delivered, dot-unstuffed.
func serveSMTP(t *testing.T, s smtpScript) (port int, finish func() (cmds []string, data string)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	var cmds []string
	var data strings.Builder
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reply := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
		verdict := func(reject bool, ok, no string) {
			if reject {
				reply(no)
				return
			}
			reply(ok)
		}
		r := bufio.NewReader(conn)
		reply("220 stand-in ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmds = append(cmds, line)
			up := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(up, "EHLO"):
				// Every line but the last carries the "-" continuation.
				lines := []string{"stand-in"}
				if s.starttls {
					lines = append(lines, "STARTTLS")
				}
				if s.auth {
					lines = append(lines, "AUTH PLAIN")
				}
				for i, l := range lines {
					sep := "-"
					if i == len(lines)-1 {
						sep = " "
					}
					reply("250" + sep + l)
				}
			case strings.HasPrefix(up, "STARTTLS"):
				reply("220 ready")
				if s.cert == nil {
					return
				}
				cfg := &tls.Config{Certificates: []tls.Certificate{*s.cert}, MinVersion: tls.VersionTLS12}
				if s.maxTLS != 0 {
					cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS10, s.maxTLS
				}
				secured := tls.Server(conn, cfg)
				if secured.Handshake() != nil {
					return
				}
				conn = secured
				r = bufio.NewReader(conn)
			case strings.HasPrefix(up, "AUTH"):
				verdict(s.rejectAuth, "235 ok", "535 no")
			case strings.HasPrefix(up, "MAIL FROM"):
				verdict(s.rejectMail, "250 ok", "550 no")
			case strings.HasPrefix(up, "RCPT TO"):
				verdict(s.rejectRcpt, "250 ok", "550 no")
			case up == "DATA":
				if s.rejectData {
					reply("554 no")
					continue
				}
				reply("354 go")
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					l = strings.TrimRight(l, "\r\n")
					if l == "." {
						break
					}
					data.WriteString(strings.TrimPrefix(l, ".") + "\r\n")
				}
				reply("250 queued")
			case up == "QUIT":
				reply("221 bye")
				return
			default:
				reply("502 unknown")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() ([]string, string) {
		// A client that never connected leaves the server waiting in Accept;
		// one that did has been greeted, so closing the listener is safe.
		_ = ln.Close()
		<-done
		return cmds, data.String()
	}
}

// The socket code speaks SMTP to a real listener: greeting name, optional
// STARTTLS and AUTH PLAIN, envelope, dot-stuffed data and QUIT, and it stops
// at the first refusal with a message that names the step.
func TestDialAndSendSpeaksSMTP(t *testing.T) {
	const from, rcpt = "no-reply@example.test", "u@example.test"
	// The system roots are read once, at the first certificate check, so the
	// certificate they must trust is installed before any case runs.
	trustedCert(t)
	msg := []byte("Subject: s\r\n\r\nline\r\n.dotted\r\n")
	creds := base64.StdEncoding.EncodeToString([]byte("\x00mailer\x00s3cret"))
	mailer := func(t *testing.T, port int, opt SMTPOptions) *SMTPNotifier {
		t.Helper()
		opt.Host, opt.Port, opt.From = "127.0.0.1", port, "Agentry <"+from+">"
		n, err := NewSMTP(opt, "registry.example", "https://registry.example", nil)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	envelope := []string{"EHLO localhost", "MAIL FROM:<" + from + ">", "RCPT TO:<" + rcpt + ">"}
	for _, c := range []struct {
		name    string
		script  smtpScript
		opt     SMTPOptions
		wantErr string   // empty: delivered
		cmds    []string // exactly the commands the server must have seen
	}{
		{"plain delivery", smtpScript{}, SMTPOptions{}, "",
			append(append([]string{}, envelope...), "DATA", "QUIT")},
		{"credentials are sent as AUTH PLAIN before the envelope", smtpScript{auth: true}, SMTPOptions{Username: "mailer", Password: "s3cret"}, "",
			[]string{"EHLO localhost", "AUTH PLAIN " + creds, "MAIL FROM:<" + from + ">", "RCPT TO:<" + rcpt + ">", "DATA", "QUIT"}},
		{"no username means no AUTH even when offered", smtpScript{auth: true}, SMTPOptions{Password: "s3cret"}, "",
			append(append([]string{}, envelope...), "DATA", "QUIT")},
		{"a refused login stops before the envelope", smtpScript{auth: true, rejectAuth: true}, SMTPOptions{Username: "mailer", Password: "s3cret"}, "auth: 535",
			[]string{"EHLO localhost", "AUTH PLAIN " + creds, "*", "QUIT"}},
		{"STARTTLS required but not offered sends nothing further", smtpScript{auth: true}, SMTPOptions{StartTLS: true, Username: "mailer", Password: "s3cret"}, "server does not advertise STARTTLS",
			[]string{"EHLO localhost"}},
		{"STARTTLS is attempted before AUTH and a failed handshake ends it", smtpScript{starttls: true, auth: true}, SMTPOptions{StartTLS: true, Username: "mailer", Password: "s3cret"}, "starttls: ",
			[]string{"EHLO localhost", "STARTTLS"}},
		{"an untrusted certificate is refused before AUTH", smtpScript{starttls: true, auth: true, cert: selfSignedCert(t)}, SMTPOptions{StartTLS: true, Username: "mailer", Password: "s3cret"}, "starttls: tls: failed to verify certificate: x509: certificate signed by unknown authority",
			[]string{"EHLO localhost", "STARTTLS"}},
		{"a verified STARTTLS session carries AUTH and the message", smtpScript{starttls: true, auth: true, trusted: true}, SMTPOptions{StartTLS: true, Username: "mailer", Password: "s3cret"}, "",
			[]string{"EHLO localhost", "STARTTLS", "EHLO localhost", "AUTH PLAIN " + creds, "MAIL FROM:<" + from + ">", "RCPT TO:<" + rcpt + ">", "DATA", "QUIT"}},
		{"a server that only speaks TLS 1.1 is refused", smtpScript{starttls: true, auth: true, trusted: true, maxTLS: tls.VersionTLS11}, SMTPOptions{StartTLS: true, Username: "mailer", Password: "s3cret"}, "starttls: ",
			[]string{"EHLO localhost", "STARTTLS"}},
		{"a refused sender stops the conversation", smtpScript{rejectMail: true}, SMTPOptions{}, "mail from: 550",
			[]string{"EHLO localhost", "MAIL FROM:<" + from + ">"}},
		{"a refused recipient stops the conversation", smtpScript{rejectRcpt: true}, SMTPOptions{}, "rcpt to: 550", envelope},
		{"a refused DATA stops the conversation", smtpScript{rejectData: true}, SMTPOptions{}, "data: 554",
			append(append([]string{}, envelope...), "DATA")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.script.trusted {
				if runtime.GOOS != "linux" {
					t.Skip("system roots are injected through SSL_CERT_FILE, which only Linux reads")
				}
				c.script.cert = trustedCert(t)
			}
			port, finish := serveSMTP(t, c.script)
			err := mailer(t, port, c.opt).dialAndSend(t.Context(), from, []string{rcpt}, msg)
			cmds, data := finish()
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("dialAndSend: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("dialAndSend error = %v, want one containing %q", err, c.wantErr)
			}
			if strings.Join(cmds, "|") != strings.Join(c.cmds, "|") {
				t.Errorf("server saw %q, want %q", cmds, c.cmds)
			}
			if c.wantErr == "" && data != "Subject: s\r\n\r\nline\r\n.dotted\r\n" {
				t.Errorf("server received %q", data)
			}
			if c.wantErr != "" && data != "" {
				t.Errorf("a message was delivered despite %q: %q", c.wantErr, data)
			}
		})
	}

	// Each recipient gets its own RCPT.
	port, finish := serveSMTP(t, smtpScript{})
	if err := mailer(t, port, SMTPOptions{}).dialAndSend(t.Context(), from, []string{rcpt, "v@example.test"}, msg); err != nil {
		t.Fatal(err)
	}
	if cmds, _ := finish(); strings.Join(cmds, "|") != strings.Join([]string{"EHLO localhost", "MAIL FROM:<" + from + ">", "RCPT TO:<" + rcpt + ">", "RCPT TO:<v@example.test>", "DATA", "QUIT"}, "|") {
		t.Errorf("two recipients: server saw %q", cmds)
	}

	// An address nobody listens on is a dial error that names it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	derr := mailer(t, dead, SMTPOptions{}).dialAndSend(t.Context(), from, []string{rcpt}, msg)
	if derr == nil || !strings.Contains(derr.Error(), "dial 127.0.0.1:"+strconv.Itoa(dead)) {
		t.Errorf("dial error = %v", derr)
	}

	// Through the notifier: the transport New and NewSMTP install is this
	// one, and a body line of a single dot does not end the message early.
	port, finish = serveSMTP(t, smtpScript{})
	n := mailer(t, port, SMTPOptions{})
	if err := n.Rendered(t.Context(), RenderedNotice{ToEmail: "Chris <" + rcpt + ">", Subject: "Hello", Text: "before\n.\nafter", Kind: KindBilling}); err != nil {
		t.Fatal(err)
	}
	cmds, data := finish()
	if want := append(append([]string{}, envelope...), "DATA", "QUIT"); strings.Join(cmds, "|") != strings.Join(want, "|") {
		t.Errorf("through the notifier the server saw %q", cmds)
	}
	if !strings.Contains(data, "\r\n\r\nbefore\r\n") || !strings.HasSuffix(data, "after\r\n\r\n--\r\nregistry.example sent this automatically to the address\r\non the account it concerns. Do not reply to this message.\r\n") {
		t.Errorf("the message was cut short in transit:\n%q", data)
	}
}
