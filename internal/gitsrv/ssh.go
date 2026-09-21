package gitsrv

// The SSH git transport (§6.1 Q7, agentry#70): ssh://git@host/{ns}/{name}.git
// over a small SSH server that speaks exactly the two git services and
// nothing else — no shell, no pty, no forwarding, no other commands. The
// credential is a user's registered SSH public key (user_ssh_keys, looked
// up by SHA256 fingerprint); authorization, the pre-receive hooks, quotas
// and post-push bookkeeping are the same code the smart-HTTP transport
// runs, so the two transports cannot drift on what a push may do.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/ratelimit"
	"github.com/blaktron/agentry/internal/registry"
)

// SSHServer serves git over SSH for one Handler.
type SSHServer struct {
	h               *Handler
	config          *ssh.ServerConfig
	ln              net.Listener
	wg              sync.WaitGroup
	closed          chan struct{}
	hostFingerprint string
	// resolveKey is the credential lookup, a fingerprint to its principal;
	// the database in production, faked in tests that count it.
	resolveKey func(ctx context.Context, fingerprint string) (*auth.Principal, error)
}

// sshMaxAuthTries bounds public-key attempts per connection.
const sshMaxAuthTries = 6

// sshKeyOffersPerMin is the per-source budget on public-key offers from
// config, with the shipped default when unset.
func (h *Handler) sshKeyOffersPerMin() int {
	if n := h.cfg.Limits.SSHKeyOffersPerMin; n > 0 {
		return n
	}
	return 60
}

// admitKeyOffer spends one public-key offer from the source address's
// budget and reports whether the key may be looked up. The listener is
// the one service the shipped stack publishes beyond loopback, and each
// offer used to cost a database lookup before anything bounded the
// source; MaxAuthTries bounds a connection, not a stranger opening many
// (agentry#410). Keyed by address, not by key: the point is what one
// source can make the registry do.
func (h *Handler) admitKeyOffer(remote net.Addr) bool {
	source := remote.String()
	if host, _, err := net.SplitHostPort(source); err == nil {
		source = host
	}
	n := h.sshKeyOffersPerMin()
	res := h.limits.Allow("ssh-key-offer", source, ratelimit.PerMinute(n), n)
	if !res.OK {
		h.log.Info("rate limited", logevent.HTTPRateLimited.Attr(), "class", "ssh-key-offer", "source", source)
	}
	return res.OK
}

// sshPermFingerprint carries the authenticated key from the auth callback
// to the session (the principal is resolved again at exec time so a key
// revoked mid-connection cannot run a second command).
const sshPermFingerprint = "agentry-fingerprint"

// NewSSHServer builds the server listening on addr. hostKeyFile is the
// OpenSSH-format private key; an empty path means {dataDir}/ssh_host_ed25519_key,
// generated on first use.
func (h *Handler) NewSSHServer(addr, hostKeyFile string) (*SSHServer, error) {
	if hostKeyFile == "" {
		hostKeyFile = filepath.Join(h.repos.dataDir, "ssh_host_ed25519_key")
	}
	signer, err := loadOrCreateHostKey(hostKeyFile)
	if err != nil {
		return nil, err
	}
	s := &SSHServer{h: h, closed: make(chan struct{}), hostFingerprint: ssh.FingerprintSHA256(signer.PublicKey())}
	s.resolveKey = func(ctx context.Context, fp string) (*auth.Principal, error) {
		return auth.ResolveSSHKey(ctx, h.st.Queries(), fp)
	}
	s.config = &ssh.ServerConfig{
		MaxAuthTries:  sshMaxAuthTries,
		ServerVersion: "SSH-2.0-agentry",
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !h.admitKeyOffer(conn.RemoteAddr()) {
				return nil, errors.New("too many key offers from this address; retry later")
			}
			fp := ssh.FingerprintSHA256(key)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := s.resolveKey(ctx, fp); err != nil {
				return nil, errors.New("unknown key")
			}
			return &ssh.Permissions{Extensions: map[string]string{sshPermFingerprint: fp}}, nil
		},
	}
	s.config.AddHostKey(signer)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("git ssh: listen %s: %w", addr, err)
	}
	s.ln = ln
	return s, nil
}

// HostKeyFingerprint is the SHA256 fingerprint operators publish for
// known_hosts pinning.
func (s *SSHServer) HostKeyFingerprint() string { return s.hostFingerprint }

// Addr is the bound listener address (tests use it for a random port).
func (s *SSHServer) Addr() net.Addr { return s.ln.Addr() }

// Serve accepts connections until ctx ends or Close is called.
func (s *SSHServer) Serve(ctx context.Context) error {
	go func() {
		select {
		case <-ctx.Done():
			_ = s.ln.Close()
		case <-s.closed:
		}
	}()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-s.closed:
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// Close stops accepting and waits for in-flight sessions.
func (s *SSHServer) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *SSHServer) handleConn(ctx context.Context, nc net.Conn) {
	defer func() { _ = nc.Close() }()
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second)) // handshake budget
	sconn, chans, reqs, err := ssh.NewServerConn(nc, s.config)
	if err != nil {
		return
	}
	_ = nc.SetDeadline(time.Time{})
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)
	fp := sconn.Permissions.Extensions[sshPermFingerprint]
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only git sessions are served")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSession(ctx, ch, chReqs, fp)
		}()
	}
}

// handleSession answers exactly one exec request per session channel.
func (s *SSHServer) handleSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, fp string) {
	defer func() { _ = ch.Close() }()
	gitProtocol := ""
	for req := range reqs {
		switch req.Type {
		case "env":
			var kv struct{ Name, Value string }
			if ssh.Unmarshal(req.Payload, &kv) == nil && kv.Name == "GIT_PROTOCOL" {
				gitProtocol = kv.Value
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			code := s.runGit(ctx, ch, fp, gitProtocol, payload.Command)
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)})) //nolint:gosec // small exit codes
			return
		default: // shell, pty-req, subsystem, forwarding: not a git server's business
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			if req.Type == "shell" || req.Type == "subsystem" {
				_, _ = fmt.Fprintf(ch.Stderr(), "agentry: only git-upload-pack and git-receive-pack are served over SSH\n")
				return
			}
		}
	}
}

// parseGitCommand accepts the two forms git clients send:
//
//	git-upload-pack '/ns/name.git'
//	git upload-pack 'ns/name.git'
//
// and returns the service ("upload-pack" | "receive-pack") and ns/name.
func parseGitCommand(cmd string) (service, ns, name string, ok bool) {
	fields := strings.Fields(cmd)
	if len(fields) == 3 && fields[0] == "git" {
		fields = []string{"git-" + fields[1], fields[2]}
	}
	if len(fields) != 2 {
		return "", "", "", false
	}
	switch fields[0] {
	case "git-upload-pack":
		service = "upload-pack"
	case "git-receive-pack":
		service = "receive-pack"
	default:
		return "", "", "", false
	}
	path := strings.Trim(fields[1], `'"`)
	path = strings.TrimPrefix(path, "/")
	path, hasGit := strings.CutSuffix(path, ".git")
	ns, name, found := strings.Cut(path, "/")
	if !hasGit || !found || ns == "" || name == "" || strings.ContainsAny(name, "/\\") || strings.ContainsAny(ns, "\\") {
		return "", "", "", false
	}
	return service, ns, name, true
}

// runGit authorizes and runs one git service over the channel, returning
// the exit status to report.
func (s *SSHServer) runGit(ctx context.Context, ch ssh.Channel, fp, gitProtocol, command string) int {
	h := s.h
	service, ns, name, ok := parseGitCommand(command)
	if !ok {
		_, _ = fmt.Fprintf(ch.Stderr(), "agentry: only git-upload-pack and git-receive-pack '<ns>/<name>.git' are served\n")
		return 127
	}
	ctx, cancel := context.WithTimeout(ctx, h.opTimeout)
	defer cancel()

	principal, err := s.resolveKey(ctx, fp)
	if err != nil {
		_, _ = fmt.Fprintf(ch.Stderr(), "agentry: key no longer accepted\n")
		return 1
	}
	act := auth.ActAgentRepoRead
	if service == "receive-pack" {
		act = auth.ActAgentRepoWrite
	}
	agent, role, denial := h.authorizeGit(ctx, ns, name, principal, act)
	if denial != nil {
		msg := denial.message
		if denial.status == http.StatusNotFound {
			msg = "repository not found"
		}
		_, _ = fmt.Fprintf(ch.Stderr(), "agentry: %s\n", msg)
		return 1
	}
	// The §19 push budget is the HTTP transport's, spent at the same
	// admission point, before git runs (agentry#410).
	if service == "receive-pack" {
		if retry, ok := h.admitPush(ctx, agent); !ok {
			_, _ = fmt.Fprintf(ch.Stderr(), "agentry: %s\n", pushBudgetRefusal(retry))
			return 1
		}
	}
	return s.execGit(ctx, ch, service, gitProtocol, agent, principal, role)
}

func (s *SSHServer) execGit(ctx context.Context, ch ssh.Channel, service, gitProtocol string, agent registry.Agent, principal *auth.Principal, role auth.AgentRole) int {
	h := s.h
	start := time.Now()
	outcome := "ok"
	h.mx.RecordGitConcurrency(ctx, service, h.inflight.Add(1))
	defer func() {
		h.mx.RecordGitConcurrency(ctx, service, h.inflight.Add(-1))
		h.mx.RecordGitOp(ctx, service, outcome, time.Since(start))
	}()

	var cmdCapture *bytes.Buffer
	var stdin io.Reader = ch
	if service == "receive-pack" {
		cmdCapture = &bytes.Buffer{}
		stdin = io.TeeReader(ch, newCommandCapture(cmdCapture))
	}
	cmd := exec.CommandContext(ctx, h.repos.GitBin(), service, h.repos.Path(agent.RepoID))
	cmd.Env = h.gitEnvFor(ctx, gitProtocol, agent, principal, role)
	cmd.Stdin = stdin
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()

	release, err := h.acquireGit(ctx, agent.RepoID)
	if err != nil {
		outcome = "busy"
		_, _ = fmt.Fprintf(ch.Stderr(), "agentry: repository busy, try again\n")
		return 1
	}
	defer release()
	if err := cmd.Run(); err != nil {
		outcome = "error"
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		h.log.Warn("git ssh exec", "service", service, "err", err)
		return 1
	}
	if service == "receive-pack" {
		h.afterReceive(context.WithoutCancel(ctx), agent, principal, cmdCapture)
	}
	return 0
}

// loadOrCreateHostKey reads the OpenSSH private key at path, generating an
// ed25519 key there (0600) when absent.
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-configured path
	if err == nil {
		signer, perr := ssh.ParsePrivateKey(raw)
		if perr != nil {
			return nil, fmt.Errorf("git ssh: host key %s: %w", path, perr)
		}
		return signer, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("git ssh: host key %s: %w", path, err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "agentry git host key")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("git ssh: write host key: %w", err)
	}
	return ssh.NewSignerFromKey(priv)
}
