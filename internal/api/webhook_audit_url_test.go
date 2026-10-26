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
	orgID := env.createOrg(sess, orgH)

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

	// The row is the organization's, about the endpoint, and lists what the
	// endpoint subscribed to.
	var kind, rowOrg, rowHost, rowEvents string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT target_kind, org_id::text, detail->>'host', (detail->'events')::text FROM audit_events WHERE action = 'webhook.create' AND target_id = $1`,
		created.Id).Scan(&kind, &rowOrg, &rowHost, &rowEvents); err != nil {
		t.Fatal(err)
	}
	if kind != "webhook" || rowOrg != orgID || rowHost != host || rowEvents != `["version.published"]` {
		t.Fatalf("audit row = kind %q org %q host %q events %s, want webhook, %s, %s, [\"version.published\"]", kind, rowOrg, rowHost, rowEvents, orgID, host)
	}

	// A port is part of the host and stays; an address with no host at all
	// is named "the endpoint". Neither lets the rest of the address in.
	for _, c := range []struct{ name, url, want string }{
		{"a port", "https://user2:pw_USER2_aa11@hooks2.example.test:8443/x/tok_PATH2_bb22?key=tok_QUERY2_cc33", "https://hooks2.example.test:8443"},
		{"no host", "https:///only/tok_PATH3_dd44?key=tok_QUERY3_ee55", "the endpoint"},
	} {
		var ep struct {
			Id string `json:"id"`
		}
		env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
			"url": c.url, "events": []string{"version.published"},
		}, &ep, http.StatusCreated)
		var row string
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT detail->>'host' FROM audit_events WHERE action = 'webhook.create' AND target_id = $1`, ep.Id).Scan(&row); err != nil {
			t.Fatal(err)
		}
		if row != c.want {
			t.Errorf("%s: the audit row names %q, want %q", c.name, row, c.want)
		}
		for _, secret := range []string{"pw_USER2", "tok_PATH2", "tok_QUERY2", "tok_PATH3", "tok_QUERY3", "/x/", "/only"} {
			if strings.Contains(row, secret) || strings.Contains(logs.String(), secret) {
				t.Errorf("%s: the audit row or the log carries %q", c.name, secret)
			}
		}
	}
}
