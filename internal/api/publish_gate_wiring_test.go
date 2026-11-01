package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// TestThePublicPublishGateFollowsTheConfiguration: the registry enforces
// the second-factor rule for a public namespace exactly where the
// configuration turns it on: outside dev mode with the provider's evidence
// required. With the rule on, a submission waits for evidence of a second
// factor from the sign-in provider; with it off, in dev mode or without the
// requirement, it does not.
func TestThePublicPublishGateFollowsTheConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name                string
		dev, requireMFA     bool
		refusedWithoutProof bool
	}{
		{"production, evidence required", false, true, true},
		{"production, no evidence asked for", false, false, false},
		{"dev mode, evidence required", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyPath, _ := writeSigningKey(t, filepath.Join(t.TempDir(), "signing.pem"))
			env := newTestEnvCfg(t, func(c *config.Config) {
				c.DevMode = tc.dev
				c.Auth.RequireIdPMFA = tc.requireMFA
				// Outside dev mode the server will not start without a sealing
				// key and a signing key.
				c.Auth.SealingKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
				c.Signing.Kind = "file"
				c.Signing.KeyFile = keyPath
			})
			user := env.register("gw-user")
			env.verifyEmail(user)
			sess := env.login(user)
			env.doJSON(sess, http.MethodPost, "/api/v1/agents",
				map[string]any{"namespace": user, "name": "gated", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
			_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
			files := skillFiles(user, "gated", "1.0.0", nil)

			status, body := env.uploadVersionCLI(user, "gated", pat, files)
			if tc.refusedWithoutProof {
				if status != http.StatusForbidden {
					t.Fatalf("without any second factor: %d %s, want 403", status, body)
				}
				if _, err := env.st.Pool().Exec(context.Background(),
					`UPDATE users SET idp_mfa_at = now() WHERE id = (SELECT id FROM handles WHERE handle = $1)`, user); err != nil {
					t.Fatal(err)
				}
				status, body = env.uploadVersionCLI(user, "gated", pat, files)
			}
			if status != http.StatusAccepted {
				t.Fatalf("submission: %d %s, want 202", status, body)
			}
		})
	}
}
