package notify

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
)

// loopbackSMTP is a one-message SMTP server on the loopback interface. It
// reads DATA the way a receiving server does, removing the leading dot a
// sender adds to a line that starts with one, and hands the message back.
type loopbackSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	data string
	done chan struct{}
}

func newLoopbackSMTP(t *testing.T) *loopbackSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &loopbackSMTP{ln: ln, done: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *loopbackSMTP) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *loopbackSMTP) message() string {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

func (s *loopbackSMTP) serve() {
	defer close(s.done)
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	say := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	say("220 loopback ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 loopback")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
			say("250 ok")
		case cmd == "DATA":
			say("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				l = strings.TrimSuffix(l, "\r\n")
				if l == "." {
					break
				}
				l = strings.TrimPrefix(l, ".")
				b.WriteString(l + "\r\n")
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 not implemented")
		}
	}
}

// A body line that is a single "." must reach the recipient as ".", and the
// lines after it must arrive: the writer net/smtp hands out already stuffs a
// leading dot, so the message handed to it is not stuffed a second time.
func TestSMTPDeliversALoneDotLineIntact(t *testing.T) {
	srv := newLoopbackSMTP(t)
	n, err := NewSMTP(SMTPOptions{
		Host: "127.0.0.1", Port: srv.port(),
		From: "Agentry <no-reply@example.test>",
	}, "registry.example", "https://registry.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = n.Rendered(t.Context(), RenderedNotice{
		ToEmail: "u@example.test", Kind: "test_kind",
		Subject: "dots", Text: "first\n.\n.hidden\nlast\n",
	})
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	got := srv.message()
	for _, want := range []string{"\r\nfirst\r\n.\r\n.hidden\r\nlast\r\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("received message lacks %q:\n%q", want, got)
		}
	}
}

func TestBodyIsCRLFAndLeavesDotsToTheDataWriter(t *testing.T) {
	got := normalizeBody("first\n.\r\n.hidden\nlast\n")
	want := "first\r\n.\r\n.hidden\r\nlast\r\n"
	if got != want {
		t.Errorf("normalizeBody = %q, want %q", got, want)
	}
}

// captureLog builds a notifier that writes its log lines to the returned
// buffer, with the transport answering as err says.
func captureLog(t *testing.T, sendErr error) (*SMTPNotifier, *bytes.Buffer) {
	t.Helper()
	n, _ := capture(t)
	var buf bytes.Buffer
	n.log = slog.New(slog.NewJSONHandler(&buf, nil))
	n.send = func(_ context.Context, _ string, _ []string, _ []byte) error { return sendErr }
	return n, &buf
}

const logRecipient = "alice.smith@example.test"

func assertMasked(t *testing.T, line string) {
	t.Helper()
	if !strings.Contains(line, `"to":"a…@example.test"`) {
		t.Errorf("log line lacks the masked recipient:\n%s", line)
	}
	for _, leak := range []string{logRecipient, "alice", "smith"} {
		if strings.Contains(strings.ToLower(line), leak) {
			t.Errorf("log line carries %q of the recipient:\n%s", leak, line)
		}
	}
}

func TestSentLineMasksTheRecipient(t *testing.T) {
	n, buf := captureLog(t, nil)
	if err := n.OrgInvite(t.Context(), InviteOffer{ToEmail: logRecipient, Org: "acme"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "notify: sent") {
		t.Fatalf("no sent line:\n%s", buf.String())
	}
	assertMasked(t, buf.String())
}

// A server's refusal quotes the mailbox it refused; that text is logged too.
func TestSendFailedLineMasksTheRecipientEverywhere(t *testing.T) {
	cause := errors.New("rcpt to: 550 5.1.1 <Alice.Smith@Example.Test> user unknown")
	n, buf := captureLog(t, cause)
	err := n.OrgInvite(t.Context(), InviteOffer{ToEmail: logRecipient, Org: "acme"})
	if err == nil {
		t.Fatal("a failed send reported success")
	}
	// Callers log the returned error, so it carries the masked form too, and
	// the transport's own error is still reachable.
	if strings.Contains(strings.ToLower(err.Error()), "alice") {
		t.Errorf("returned error carries the recipient: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("returned error lost its cause: %v", err)
	}
	if !strings.Contains(buf.String(), "notify: smtp send failed") {
		t.Fatalf("no failure line:\n%s", buf.String())
	}
	assertMasked(t, buf.String())
}

// With no base URL the message carries a code and no link, and must say so
// from its first sentence to its last.
func TestVerificationWithoutALinkNeverMentionsOne(t *testing.T) {
	m := renderer{registry: "Agentry"}.verification("chris", "tok123")
	if strings.Contains(strings.ToLower(m.Body), "link") {
		t.Errorf("code-only verification mail mentions a link:\n%s", m.Body)
	}
	if !strings.HasPrefix(m.Body, "Use this code to confirm this address") {
		t.Errorf("code-only verification mail opens with the wrong sentence:\n%s", m.Body)
	}
	withLink := renderer{registry: "Agentry", baseURL: "https://registry.example"}.verification("chris", "tok123")
	if !strings.HasPrefix(withLink.Body, "Follow this link to confirm this address") {
		t.Errorf("link verification mail lost its opening:\n%s", withLink.Body)
	}
	if strings.Contains(withLink.Body, "code") {
		t.Errorf("link verification mail mentions a code:\n%s", withLink.Body)
	}
}

func TestMalformedRecipientErrorDoesNotEchoIt(t *testing.T) {
	n, _ := capture(t)
	err := n.EmailVerification(t.Context(), "alice.smith at example.test", "chris", "tok")
	if err == nil {
		t.Fatal("delivery to a malformed address was attempted")
	}
	if strings.Contains(strings.ToLower(err.Error()), "alice") {
		t.Errorf("error echoes the recipient: %v", err)
	}
}
