package gitsrv_test

// An unactivated account is read-only: the API's gate does not see git, so
// git refuses its pushes itself, on both transports (they share
// authorizeGit), and still lets it read.

import (
	"context"
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
}
