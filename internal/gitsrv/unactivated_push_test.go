package gitsrv_test

// An unactivated account is read-only: the API's gate does not see git, so
// git refuses its pushes itself, on both transports (they share
// authorizeGit), and still lets it read.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestUnactivatedAccountCannotPush(t *testing.T) {
	env := newGitEnvCfg(t, nil)
	env.seedAgent("unactivated", "private")
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE users SET email_verified_at = NULL WHERE id = $1`, env.owner.id); err != nil {
		t.Fatal(err)
	}
	res := env.receivePackAttempt(t, env.owner.handle, "unactivated", env.owner.patRW)
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "activate your account") {
		t.Fatalf("push by an unactivated owner: %d %q, want 403 asking for activation", res.StatusCode, body)
	}

	// Reading is still allowed: only the write is held back.
	read := env.infoRefsAs(t, env.owner.handle, "unactivated", env.owner.patRO, "git-upload-pack")
	_ = read.Body.Close()
	if read.StatusCode != http.StatusOK {
		t.Fatalf("read by an unactivated owner over HTTPS: %d, want 200", read.StatusCode)
	}

	// The same decision over SSH, where authorization is shared.
	sshSrv := env.startSSH(t)
	key := newSSHClient(t)
	env.seedSSHKey(env.owner.id, key)
	conn := dialSSH(t, sshSrv, key)
	command := func(service string) string {
		return fmt.Sprintf("git-%s '/%s/unactivated.git'", service, env.owner.handle)
	}
	if out, errOut, exit := sshExec(t, conn, nil, command("receive-pack")); exit != 1 || out != "" || !strings.Contains(errOut, "activate your account") {
		t.Fatalf("receive-pack by an unactivated owner over SSH: exit %d, stdout %q, stderr %q, want exit 1 asking for activation", exit, out, errOut)
	}
	if out, errOut, exit := sshExec(t, conn, nil, command("upload-pack")); exit != 0 {
		t.Fatalf("upload-pack by an unactivated owner over SSH: exit %d, stdout %q, stderr %q, want it served", exit, out, errOut)
	}
}
