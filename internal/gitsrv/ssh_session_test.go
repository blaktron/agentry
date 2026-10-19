package gitsrv

// White-box: what the SSH listener accepts and refuses before any
// repository is involved. A fake key lookup stands in for the database; the
// SSH wire is the real one.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blaktron/agentry/internal/auth"
)

func TestParseGitCommand(t *testing.T) {
	for _, tc := range []struct {
		cmd            string
		service        string
		ns, name       string
		wantOK         bool
		whyItIsRefused string
	}{
		{"git-upload-pack '/ns/name.git'", "upload-pack", "ns", "name", true, ""},
		{"git-receive-pack '/ns/name.git'", "receive-pack", "ns", "name", true, ""},
		{"git upload-pack 'ns/name.git'", "upload-pack", "ns", "name", true, ""},
		{"git receive-pack 'ns/name.git'", "receive-pack", "ns", "name", true, ""},
		{`git-upload-pack "ns/name.git"`, "upload-pack", "ns", "name", true, ""},
		{"git-upload-pack ns/name.git", "upload-pack", "ns", "name", true, ""},
		{"git-upload-pack   '/ns/name.git'  ", "upload-pack", "ns", "name", true, ""},
		{"git-upload-pack '/ns/a.b-c_d.git'", "upload-pack", "ns", "a.b-c_d", true, ""},

		{"", "", "", "", false, "empty"},
		{"ls", "", "", "", false, "not a git command"},
		{"git-upload-pack", "", "", "", false, "no path"},
		{"git-upload-pack 'ns/name.git' extra", "", "", "", false, "extra field"},
		{"git upload-pack", "", "", "", false, "git with only a service"},
		{"git status 'ns/name.git'", "", "", "", false, "other git command"},
		{"git-upload-archive 'ns/name.git'", "", "", "", false, "archive service"},
		{"git archive 'ns/name.git'", "", "", "", false, "archive via git"},
		{"git-lfs-authenticate 'ns/name.git' download", "", "", "", false, "lfs"},
		{"git-upload-pack 'ns/name'", "", "", "", false, "no .git suffix"},
		{"git-upload-pack 'ns.git'", "", "", "", false, "no namespace separator"},
		{"git-upload-pack '/name.git'", "", "", "", false, "empty namespace"},
		{"git-upload-pack '//name.git'", "", "", "", false, "empty namespace after one slash"},
		{"git-upload-pack 'ns/.git'", "", "", "", false, "empty name"},
		{"git-upload-pack 'ns/a/b.git'", "", "", "", false, "nested path"},
		{`git-upload-pack 'ns/a\b.git'`, "", "", "", false, "backslash in the name"},
		{`git-upload-pack 'n\s/ab.git'`, "", "", "", false, "backslash in the namespace"},
		{"git-upload-pack '//ns/name.git'", "", "", "", false, "two leading slashes"},
	} {
		service, ns, name, ok := parseGitCommand(tc.cmd)
		if ok != tc.wantOK || service != tc.service || ns != tc.ns || name != tc.name {
			t.Errorf("parseGitCommand(%q) = %q %q %q %v, want %q %q %q %v (%s)",
				tc.cmd, service, ns, name, ok, tc.service, tc.ns, tc.name, tc.wantOK, tc.whyItIsRefused)
		}
	}
}

// sessionServer is an SSH listener whose key lookup accepts every key as an
// empty principal. Anything that would need a repository is out of reach.
func sessionServer(t *testing.T) *SSHServer {
	t.Helper()
	srv, _ := proxyTestServer(t, 1000, nil)
	srv.resolveKey = func(context.Context, string) (*auth.Principal, error) { return &auth.Principal{}, nil }
	return srv
}

func freshSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func dialSession(t *testing.T, srv *SSHServer) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", srv.Addr().String(), &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(freshSigner(t))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test against an in-process server
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("a key the lookup accepts was refused: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSSHServesNothingButGitSessions: after authentication the listener
// opens session channels only, and in them answers no shell, subsystem or
// terminal request and no command but the two git services.
func TestSSHServesNothingButGitSessions(t *testing.T) {
	srv := sessionServer(t)
	c := dialSession(t, srv)

	t.Run("forwarding channels are refused", func(t *testing.T) {
		_, _, err := c.OpenChannel("direct-tcpip", ssh.Marshal(struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}{"127.0.0.1", 22, "127.0.0.1", 40000}))
		var open *ssh.OpenChannelError
		if !errors.As(err, &open) || open.Reason != ssh.UnknownChannelType || !strings.Contains(open.Message, "only git sessions are served") {
			t.Fatalf("direct-tcpip channel: %v, want an unknown-channel-type refusal saying only git sessions are served", err)
		}
	})

	t.Run("a shell is refused and says why", func(t *testing.T) {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sess.Close() }()
		stderr, err := sess.StderrPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.Shell(); err == nil {
			t.Fatal("a shell was started")
		}
		msg, _ := io.ReadAll(stderr)
		if !strings.Contains(string(msg), "only git-upload-pack and git-receive-pack are served over SSH") {
			t.Fatalf("shell refusal says %q", msg)
		}
	})

	t.Run("a subsystem is refused and says why", func(t *testing.T) {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sess.Close() }()
		stderr, err := sess.StderrPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.RequestSubsystem("sftp"); err == nil {
			t.Fatal("a subsystem was started")
		}
		msg, _ := io.ReadAll(stderr)
		if !strings.Contains(string(msg), "only git-upload-pack and git-receive-pack are served over SSH") {
			t.Fatalf("subsystem refusal says %q", msg)
		}
	})

	t.Run("a terminal is refused and the session goes on", func(t *testing.T) {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sess.Close() }()
		if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
			t.Fatal("a pty was granted")
		}
		var stderr bytes.Buffer
		sess.Stderr = &stderr
		var exit *ssh.ExitError
		if err := sess.Run("ls"); !errors.As(err, &exit) || exit.ExitStatus() != 127 {
			t.Fatalf("command after the refused pty: %v, want exit status 127", err)
		}
	})

	t.Run("a command that is not a git service exits 127", func(t *testing.T) {
		for _, cmd := range []string{"ls", "git-upload-archive 'ns/name.git'", "git-upload-pack 'not-a-path'", "git-receive-pack"} {
			sess, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			sess.Stderr = &stderr
			var exit *ssh.ExitError
			err = sess.Run(cmd)
			_ = sess.Close()
			if !errors.As(err, &exit) || exit.ExitStatus() != 127 {
				t.Fatalf("%q: %v, want exit status 127", cmd, err)
			}
			if !strings.Contains(stderr.String(), "only git-upload-pack and git-receive-pack '<ns>/<name>.git' are served") {
				t.Fatalf("%q refusal says %q", cmd, stderr.String())
			}
		}
	})
}

// TestSSHStopsAfterTheAuthTries: one connection may offer six keys, not
// more, however many it has.
func TestSSHStopsAfterTheAuthTries(t *testing.T) {
	srv, lookups := proxyTestServer(t, 1000, nil)
	var signers []ssh.Signer
	for range 10 {
		signers = append(signers, freshSigner(t))
	}
	_, err := ssh.Dial("tcp", srv.Addr().String(), &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test against an in-process server
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("unregistered keys were accepted")
	}
	if n := lookups.Load(); n != sshMaxAuthTries {
		t.Fatalf("%d keys were looked up on one connection, want %d", n, sshMaxAuthTries)
	}
}

// TestHostKeyIsCreatedOnceAndKept: the first start makes the host key,
// private to the server, and every later start loads that same key; a file
// that is not a key stops the listener instead of being replaced.
func TestHostKeyIsCreatedOnceAndKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "ssh_host_ed25519_key")
	first, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("host key file mode %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm()&0o077 != 0 {
		t.Errorf("host key directory mode %v is open to others", di.Mode().Perm())
	}
	second, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(first.PublicKey()) != ssh.FingerprintSHA256(second.PublicKey()) {
		t.Fatal("a restart generated a different host key")
	}

	// With no path given the key is made in the store's data directory and
	// kept there.
	store := limitsStore(t)
	h := &Handler{repos: store, log: slog.Default()}
	srv, err := h.NewSSHServer("127.0.0.1:0", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	kept, err := loadOrCreateHostKey(filepath.Join(store.dataDir, "ssh_host_ed25519_key"))
	if err != nil {
		t.Fatal(err)
	}
	if srv.HostKeyFingerprint() != ssh.FingerprintSHA256(kept.PublicKey()) {
		t.Fatal("the default host key is not the one in the data directory")
	}

	garbage := filepath.Join(t.TempDir(), "hostkey")
	if err := os.WriteFile(garbage, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateHostKey(garbage); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("a file that is not a key: %v, want a host key error", err)
	}
	if got, _ := os.ReadFile(garbage); string(got) != "not a key\n" {
		t.Fatalf("the unreadable host key was overwritten with %q", got)
	}
	asDir := t.TempDir()
	if _, err := loadOrCreateHostKey(asDir); err == nil || !strings.HasPrefix(err.Error(), "git ssh: host key "+asDir+": ") {
		t.Fatalf("a host key path that is a directory: %v, want a read error naming the path", err)
	}
}

// TestTruncateKeepsAtMostN: a logged value is cut to n bytes, marked.
func TestTruncateKeepsAtMostN(t *testing.T) {
	if got := truncate("abcdef", 6); got != "abcdef" {
		t.Errorf("a value of exactly n bytes: %q", got)
	}
	if got := truncate("abcdefg", 6); got != "abcdef…" {
		t.Errorf("a value past n bytes: %q", got)
	}
}
