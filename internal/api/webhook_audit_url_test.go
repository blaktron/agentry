package api_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// An endpoint whose address carries a token in its path and query leaves that
// token out of the audit row its creation writes and out of the log line that
// mirrors the row; both name only the scheme and host.
func TestCreatingAnEndpointKeepsItsTokenOutOfTheAuditEvent(t *testing.T) {
	var logs lockedBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	env := newTestEnvCfg(t, func(c *config.Config) { c.Audit.StreamKind = "log" })
	owner := env.register("wa-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "waorg" + env.sfx
	env.createOrg(sess, orgH)

	const pathToken, queryToken = "tok_PATH_5d41402abc4b", "tok_QUERY_7d793037a076"
	const host = "https://hooks.example.test"
	var created struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
		"url":    "https://user:pw_USERINFO_9e107d9d372b@hooks.example.test/services/" + pathToken + "?key=" + queryToken + "#frag_FRAGMENT_1679091c5a88",
		"events": []string{"version.published"},
	}, &created, http.StatusCreated)

	var stored string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail::text FROM audit_events WHERE action = 'webhook.create' AND target_id = $1`, created.Id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, host) {
		t.Fatalf("audit detail = %s, want it to name %s", stored, host)
	}
	line := ""
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "audit.webhook.create") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no audit.webhook.create log line in:\n%s", logs.String())
	}
	if !strings.Contains(line, host) {
		t.Fatalf("log line = %s, want it to name %s", line, host)
	}

	for name, text := range map[string]string{"audit row": stored, "log line": line, "log": logs.String()} {
		for _, secret := range []string{pathToken, queryToken, "pw_USERINFO", "frag_FRAGMENT", "/services"} {
			if strings.Contains(text, secret) {
				t.Errorf("the %s carries %q: %s", name, secret, text)
			}
		}
	}
}
