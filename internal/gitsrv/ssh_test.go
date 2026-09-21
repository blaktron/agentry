package gitsrv_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
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

// TestSSHTransportCloneAndPush (§6.1 Q7, agentry#70): a registered key
// clones and pushes over SSH through the same hooks as HTTPS; an
// unregistered key is refused at authentication; a key revoked mid-way is
// refused at the next command; a read-only member cannot push; the server
// answers nothing but the two git services.
func TestSSHTransportCloneAndPush(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	env := newGitEnv(t)
	sshSrv, err := env.git.NewSSHServer("127.0.0.1:0", filepath.Join(t.TempDir(), "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = sshSrv.Serve(ctx) }()
	t.Cleanup(func() { _ = sshSrv.Close() })
	if !strings.HasPrefix(sshSrv.HostKeyFingerprint(), "SHA256:") {
		t.Fatalf("host key fingerprint = %q", sshSrv.HostKeyFingerprint())
	}
	port := sshSrv.Addr().(*net.TCPAddr).Port
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
}

func (e *gitEnv) sshKeyIDFor(c *sshClient) uuid.UUID {
	e.t.Helper()
	row, err := e.st.Queries().GetSSHKeyByFingerprint(context.Background(), c.fp)
	if err != nil {
		e.t.Fatal(err)
	}
	return row.ID
}

// startSSH serves the env's git handler over SSH on a random loopback port
// and returns the port.
func (e *gitEnv) startSSH(t *testing.T) int {
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
	return sshSrv.Addr().(*net.TCPAddr).Port
}

// TestSSHPushBudgetIsTheHTTPBudget (§19, agentry#410): the per-repository
// push budget is one number on both transports. A budget spent over HTTPS
// refuses the next push over SSH with the same words, and a push over SSH
// spends the budget HTTPS then finds empty.
func TestSSHPushBudgetIsTheHTTPBudget(t *testing.T) {
	env := newGitEnvCfg(t, func(c *config.Config) { c.Limits.GitPushesPerHour = 1 })
	port := env.startSSH(t)
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
