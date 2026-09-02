package api_test

// The directory's `amr` claim is evidence for the §12.1 public-publish gate
// (agentry#23): a sign-in whose ID token names a second factor stamps
// users.idp_mfa_at; one that names only a password does not; and the gate,
// when on, accepts the stamp in place of native TOTP.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

func loginThroughFakeOIDC(t *testing.T, env *testEnv, idp *fakeOIDC) string {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, "google")
	visit, err := idp.srv.Client().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	res := env.socialCallback(t, "google", state, cookie)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Id string `json:"id"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.User.Id
}

func TestSocialLoginRecordsIdPMFA(t *testing.T) {
	for _, tc := range []struct {
		name string
		amr  []string
		want bool
	}{
		{"password only", []string{"pwd"}, false},
		{"no amr at all", nil, false},
		{"password plus mfa", []string{"pwd", "mfa"}, true},
		{"webauthn spelling", []string{"pwd", "webauthn"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeOIDC(t)
			idp.amr = tc.amr
			env := newTestEnvCfg(t, func(cfg *config.Config) {
				cfg.Social.Google = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
			}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
			userID := loginThroughFakeOIDC(t, env, idp)
			var stamped bool
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT idp_mfa_at IS NOT NULL FROM users WHERE id = $1::uuid`, userID).Scan(&stamped); err != nil {
				t.Fatal(err)
			}
			if stamped != tc.want {
				t.Fatalf("amr=%v: idp_mfa_at set = %v, want %v", tc.amr, stamped, tc.want)
			}
			// The login audit row shows what the directory sent, so an
			// operator can check before enabling requireIdpMFA.
			var got []string
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT COALESCE(detail->'amr', '[]'::jsonb) FROM audit_events WHERE action = 'user.login' AND actor_id = $1::uuid ORDER BY occurred_at DESC LIMIT 1`, userID).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.amr) {
				t.Fatalf("audit amr = %v, want %v", got, tc.amr)
			}
		})
	}
}

func TestPublicPublishGateAcceptsIdPMFA(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) { s.Reg().SetPublicPublish2FA(true) })
	user := env.register("gate-mfa")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "gated", "kind": "skill", "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	files := map[string]string{
		"agent.yaml": skillYAML(user, "gated", "1.0.0"),
		"README.md":  "# gated\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}
	// Neither native TOTP nor a directory-asserted factor: refused.
	if status, body := env.uploadVersionCLI(user, "gated", pat, files); status != http.StatusForbidden {
		t.Fatalf("without any second factor: %d %s (want 403)", status, body)
	}
	// The directory asserted one at sign-in: accepted.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE users SET idp_mfa_at = now() WHERE id = (SELECT id FROM handles WHERE handle = $1)`, user); err != nil {
		t.Fatal(err)
	}
	if status, body := env.uploadVersionCLI(user, "gated", pat, files); status != http.StatusAccepted {
		t.Fatalf("with idp_mfa_at: %d %s (want 202)", status, body)
	}
}
