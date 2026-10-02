package gitsrv_test

// An unactivated account (agentry#861, plan unactivated-accounts.md D2) is
// read-only where the directory owns credentials: the API's gate does not
// see git, so git refuses its pushes itself, on both transports (they share
// authorizeGit), and still lets it read.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

func TestUnactivatedAccountCannotPush(t *testing.T) {
	for _, tc := range []struct {
		name         string
		externalOnly bool
		refused      bool
	}{
		{"the directory owns credentials", true, true},
		{"a native deployment keeps its own gates", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newGitEnvCfg(t, func(c *config.Config) { c.Auth.ExternalOnly = tc.externalOnly })
			env.seedAgent("unactivated", "private")
			if _, err := env.st.Pool().Exec(context.Background(),
				`UPDATE users SET email_verified_at = NULL WHERE id = $1`, env.owner.id); err != nil {
				t.Fatal(err)
			}
			res := env.receivePackAttempt(t, env.owner.handle, "unactivated", env.owner.patRW)
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			refused := res.StatusCode == http.StatusForbidden && strings.Contains(string(body), "activate your account")
			if refused != tc.refused {
				t.Fatalf("push by an unactivated owner: %d %q, refused for activation %v, want %v", res.StatusCode, body, refused, tc.refused)
			}
		})
	}
}
