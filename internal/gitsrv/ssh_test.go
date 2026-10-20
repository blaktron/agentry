package gitsrv_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/gitsrv"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// sshClient is a generated client key on disk plus the GIT_SSH_COMMAND that
// uses it against the in-process server.
type sshClient struct {
	keyPath string
	pubLine string
	fp      string
}

func newSSHClient(t *testing.T) *sshClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &sshClient{keyPath: keyPath, pubLine: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), fp: ssh.FingerprintSHA256(sshPub)}
}

// signer is the client key as an SSH library signer, for tests that hold one
// connection open across several commands.
func (c *sshClient) signer(t *testing.T) ssh.Signer {
	t.Helper()
	raw, err := os.ReadFile(c.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// dialSSH opens one authenticated connection to the in-process server.
func dialSSH(t *testing.T, srv *gitsrv.SSHServer, c *sshClient) *ssh.Client {
	t.Helper()
	conn, err := ssh.Dial("tcp", srv.Addr().String(), &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(c.signer(t))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test against an in-process server
	})
	if err != nil {
		t.Fatalf("a registered key was refused: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// sshExec runs one command in its own session on an open connection, with
// the given environment requests sent first, and returns what the server
// wrote and the exit status it reported. The command's stdin is one flush
// packet, which a git service reads as the client ending the conversation.
func sshExec(t *testing.T, conn *ssh.Client, env map[string]string, command string) (stdout, stderr string, exit int) {
	t.Helper()
	sess, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	for name, value := range env {
		if err := sess.Setenv(name, value); err != nil {
			t.Fatalf("env %s was refused: %v", name, err)
		}
	}
	var out, errOut bytes.Buffer
	sess.Stdin, sess.Stdout, sess.Stderr = strings.NewReader("0000"), &out, &errOut
	if err := sess.Run(command); err != nil {
		var exitErr *ssh.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("%q: %v", command, err)
		}
		exit = exitErr.ExitStatus()
	}
	return out.String(), errOut.String(), exit
}

func (c *sshClient) gitSSHCommand() string {
	return fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o LogLevel=ERROR", c.keyPath)
}

// seedSSHKey registers a client key for a user directly through the store.
func (e *gitEnv) seedSSHKey(userID uuid.UUID, c *sshClient) {
	e.t.Helper()
	keyType, canonical, fp, err := auth.ParseSSHPublicKey(c.pubLine)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.st.Queries().CreateSSHKey(context.Background(), storegen.CreateSSHKeyParams{
		ID: newUUID(e.t), UserID: userID, Title: "test", KeyType: keyType, PublicKey: canonical, Fingerprint: fp,
	}); err != nil {
		e.t.Fatal(err)
	}
}

// TestSSHTransportCloneAndPush: a registered key clones and pushes over
// SSH through the same hooks as HTTPS; an unregistered key is refused at
// authentication; a key revoked mid-way is refused at the next command; a
// read-only member cannot push; the server answers nothing but the two git
// services.
func TestSSHTransportCloneAndPush(t *testing.T) {
	env := newGitEnv(t)
	sshSrv := env.startSSH(t)
	if !strings.HasPrefix(sshSrv.HostKeyFingerprint(), "SHA256:") {
		t.Fatalf("host key fingerprint = %q", sshSrv.HostKeyFingerprint())
	}
	port := sshPort(sshSrv)
	agent := env.seedAgent("sshagent", "public")
	sshURL := fmt.Sprintf("ssh://git@127.0.0.1:%d/%s/%s.git", port, env.owner.handle, agent.Name)

	owner := newSSHClient(t)
	env.seedSSHKey(env.owner.id, owner)
	stranger := newSSHClient(t)

	// Clone (empty repo) and push a first commit over SSH.
	work := filepath.Join(t.TempDir(), "work")
	ownerEnv := []string{"GIT_SSH_COMMAND=" + owner.gitSSHCommand()}
	if out, err := gitRunWithEnv(t, t.TempDir(), ownerEnv, "clone", sshURL, work); err != nil {
		t.Fatalf("ssh clone: %v\n%s", err, out)
	}
	for path, content := range kindFixture("skill", env.owner.handle, agent.Name, "0.1.0") {
		full := filepath.Join(work, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"add", "-A"}, {"-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-qm", "first"}} {
		if out, err := gitRun(t, work, args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if out, err := gitRunWithEnv(t, work, ownerEnv, "push", "-q", "origin", "HEAD:main"); err != nil {
		t.Fatalf("ssh push: %v\n%s", err, out)
	}
	// The push is bookkept exactly like an HTTPS push.
	if n := env.pushAudits(agent.ID); n != 1 {
		t.Fatalf("repo.push audits after ssh push = %d, want 1", n)
	}
	// A second clone sees the commit.
	work2 := filepath.Join(t.TempDir(), "work2")
	if out, err := gitRunWithEnv(t, t.TempDir(), ownerEnv, "clone", "-q", sshURL, work2); err != nil {
		t.Fatalf("ssh clone 2: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(work2, "agent.yaml")); err != nil {
		t.Fatal("clone over ssh lacks the pushed agent.yaml")
	}

	// Unregistered key: refused at auth (public repo or not — SSH has no
	// anonymous mode; anonymous reads stay an HTTPS affair).
	if out, err := gitRunWithEnv(t, t.TempDir(), []string{"GIT_SSH_COMMAND=" + stranger.gitSSHCommand()}, "clone", "-q", sshURL, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatalf("unregistered key must be refused:\n%s", out)
	}

	// Read-only member (no role on this agent, private repo): hidden.
	private := env.seedAgent("sshprivate", "private")
	privURL := fmt.Sprintf("ssh://git@127.0.0.1:%d/%s/%s.git", port, env.owner.handle, private.Name)
	reader := newSSHClient(t)
	readerID := env.seedUser("sshreader" + env.sfx)
	env.seedSSHKey(readerID, reader)
	if out, err := gitRunWithEnv(t, t.TempDir(), []string{"GIT_SSH_COMMAND=" + reader.gitSSHCommand()}, "clone", "-q", privURL, filepath.Join(t.TempDir(), "y")); err == nil || !strings.Contains(out, "repository not found") {
		t.Fatalf("private repo must be hidden from a non-member: %v\n%s", err, out)
	}
	// Owner can clone the private one.
	if out, err := gitRunWithEnv(t, t.TempDir(), ownerEnv, "clone", "-q", privURL, filepath.Join(t.TempDir(), "z")); err != nil {
		t.Fatalf("owner private clone: %v\n%s", err, out)
	}

	// Not a git command: refused with a clear message.
	sshCmd := strings.Fields(owner.gitSSHCommand())
	sshCmd = append(sshCmd, "-p", fmt.Sprint(port), "git@127.0.0.1", "ls")
	out, err := exec.Command(sshCmd[0], sshCmd[1:]...).CombinedOutput() //nolint:gosec // test
	if err == nil || !strings.Contains(string(out), "only git-upload-pack and git-receive-pack") {
		t.Fatalf("shell command must be refused: %v\n%s", err, out)
	}

	// Revoked key: refused at the next command.
	if _, err := env.st.Queries().RevokeSSHKey(context.Background(), storegen.RevokeSSHKeyParams{ID: env.sshKeyIDFor(owner), UserID: env.owner.id}); err != nil {
		t.Fatal(err)
	}
	if out, err := gitRunWithEnv(t, work, ownerEnv, "fetch", "-q", "origin"); err == nil {
		t.Fatalf("revoked key must be refused:\n%s", out)
	}

	// One connection, several commands: the key is looked up again for every
	// command, so a key revoked while the connection is open runs no more.
	t.Run("a key revoked mid-connection runs no further command", func(t *testing.T) {
		mid := newSSHClient(t)
		env.seedSSHKey(env.owner.id, mid)
		conn := dialSSH(t, sshSrv, mid)
		readCmd := fmt.Sprintf("git-upload-pack '/%s/%s.git'", env.owner.handle, agent.Name)
		out, errOut, exit := sshExec(t, conn, nil, readCmd)
		if exit != 0 || !strings.Contains(out, "refs/heads/main") {
			t.Fatalf("a command on a live key: exit %d, stdout %q, stderr %q", exit, out, errOut)
		}
		if _, err := env.st.Queries().RevokeSSHKey(context.Background(), storegen.RevokeSSHKeyParams{ID: env.sshKeyIDFor(mid), UserID: env.owner.id}); err != nil {
			t.Fatal(err)
		}
		out, errOut, exit = sshExec(t, conn, nil, readCmd)
		if exit != 1 || out != "" || !strings.Contains(errOut, "agentry: key no longer accepted") {
			t.Fatalf("a command on the revoked key: exit %d, stdout %q, stderr %q, want exit 1, nothing served and %q", exit, out, errOut, "key no longer accepted")
		}
	})

	// Pushing needs write, not read: a reader's receive-pack is refused at
	// authorization, before git runs, on a public agent and on a private one
	// the reader holds a read grant on, while the same reader's upload-pack
	// on the private agent is served.
	t.Run("a reader cannot push over SSH", func(t *testing.T) {
		if err := env.st.Queries().UpsertAgentUserGrant(context.Background(), storegen.UpsertAgentUserGrantParams{
			AgentID: private.ID, UserID: readerID, Role: "read",
		}); err != nil {
			t.Fatal(err)
		}
		conn := dialSSH(t, sshSrv, reader)
		pushPublic := fmt.Sprintf("git-receive-pack '/%s/%s.git'", env.owner.handle, agent.Name)
		pushPrivate := fmt.Sprintf("git-receive-pack '/%s/%s.git'", env.owner.handle, private.Name)
		readPrivate := fmt.Sprintf("git-upload-pack '/%s/%s.git'", env.owner.handle, private.Name)
		for name, command := range map[string]string{"a public agent": pushPublic, "a private agent the reader may read": pushPrivate} {
			out, errOut, exit := sshExec(t, conn, nil, command)
			if exit != 1 || out != "" || !strings.Contains(errOut, "agentry: forbidden") {
				t.Fatalf("receive-pack on %s: exit %d, stdout %q, stderr %q, want exit 1 and %q", name, exit, out, errOut, "agentry: forbidden")
			}
		}
		if _, errOut, exit := sshExec(t, conn, nil, readPrivate); exit != 0 {
			t.Fatalf("upload-pack on a private agent the reader may read: exit %d, stderr %q", exit, errOut)
		}
		if n := env.pushAudits(private.ID); n != 0 {
			t.Fatalf("a refused push was bookkept: %d repo.push audits", n)
		}
	})

	// The client asks for protocol v2 with the GIT_PROTOCOL environment
	// request, as git does over ssh; without it the server speaks v0.
	t.Run("the client's GIT_PROTOCOL request picks the protocol", func(t *testing.T) {
		proto := newSSHClient(t)
		env.seedSSHKey(env.owner.id, proto)
		conn := dialSSH(t, sshSrv, proto)
		readCmd := fmt.Sprintf("git-upload-pack '/%s/%s.git'", env.owner.handle, agent.Name)
		out, errOut, exit := sshExec(t, conn, nil, readCmd)
		if exit != 0 || !strings.Contains(out, "refs/heads/main") || strings.Contains(out, "version 2") {
			t.Fatalf("without the request: exit %d, stdout %q, stderr %q, want a v0 advertisement of the refs", exit, out, errOut)
		}
		out, errOut, exit = sshExec(t, conn, map[string]string{"GIT_PROTOCOL": "version=2"}, readCmd)
		if exit != 0 || !strings.Contains(out, "version 2") || strings.Contains(out, "refs/heads/main") {
			t.Fatalf("with GIT_PROTOCOL=version=2: exit %d, stdout %q, stderr %q, want a v2 capability advertisement", exit, out, errOut)
		}
	})
}

func (e *gitEnv) sshKeyIDFor(c *sshClient) uuid.UUID {
	e.t.Helper()
	row, err := e.st.Queries().GetSSHKeyByFingerprint(context.Background(), c.fp)
	if err != nil {
		e.t.Fatal(err)
	}
	return row.ID
}

// startSSH serves the env's git handler over SSH on a random loopback port.
func (e *gitEnv) startSSH(t *testing.T) *gitsrv.SSHServer {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	sshSrv, err := e.git.NewSSHServer("127.0.0.1:0", filepath.Join(t.TempDir(), "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = sshSrv.Serve(ctx) }()
	t.Cleanup(func() { _ = sshSrv.Close() })
	return sshSrv
}

func sshPort(s *gitsrv.SSHServer) int { return s.Addr().(*net.TCPAddr).Port }

// TestSSHPushBudgetIsTheHTTPBudget: the per-repository push budget is one
// number on both transports. A budget spent over HTTPS refuses the next
// push over SSH with the same words, and a push over SSH spends the budget
// HTTPS then finds empty.
func TestSSHPushBudgetIsTheHTTPBudget(t *testing.T) {
	env := newGitEnvCfg(t, func(c *config.Config) { c.Limits.GitPushesPerHour = 1 })
	port := sshPort(env.startSSH(t))
	owner := newSSHClient(t)
	env.seedSSHKey(env.owner.id, owner)
	ownerEnv := []string{"GIT_SSH_COMMAND=" + owner.gitSSHCommand()}

	t.Run("spent over HTTPS, refused over SSH", func(t *testing.T) {
		agent := env.seedAgent("sshbudget-a", "public")
		res := env.receivePackAttempt(t, env.owner.handle, agent.Name, env.owner.patRW)
		_ = res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			t.Fatal("the first push of the budget was refused")
		}
		work := seedWorkdir(t, kindFixture("skill", env.owner.handle, agent.Name, "0.1.0"))
		url := fmt.Sprintf("ssh://git@127.0.0.1:%d/%s/%s.git", port, env.owner.handle, agent.Name)
		out, err := gitRunWithEnv(t, work, ownerEnv, "push", "-q", url, "HEAD:main")
		if err == nil || !strings.Contains(out, "over its hourly push limit") {
			t.Fatalf("push over SSH past the budget: err=%v\n%s", err, out)
		}
		if n := env.pushAudits(agent.ID); n != 0 {
			t.Fatalf("a refused push was bookkept: %d repo.push audits", n)
		}
	})

	t.Run("spent over SSH, refused over HTTPS", func(t *testing.T) {
		agent := env.seedAgent("sshbudget-b", "public")
		work := seedWorkdir(t, kindFixture("skill", env.owner.handle, agent.Name, "0.1.0"))
		url := fmt.Sprintf("ssh://git@127.0.0.1:%d/%s/%s.git", port, env.owner.handle, agent.Name)
		if out, err := gitRunWithEnv(t, work, ownerEnv, "push", "-q", url, "HEAD:main"); err != nil {
			t.Fatalf("push over SSH within the budget: %v\n%s", err, out)
		}
		res := env.receivePackAttempt(t, env.owner.handle, agent.Name, env.owner.patRW)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("push over HTTPS after SSH spent the budget: %d, want 429", res.StatusCode)
		}
	})
}
