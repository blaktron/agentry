package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/scan"
)

// The surfaces of a dependency alert (agentry#177 M3): the submitter's list
// (banner and dashboard), the agent's public page, and the registry's scan
// record for one server version.
func TestDependencyAlertSurfaces(t *testing.T) {
	osv := &fakeOSV{vulns: map[string][]scan.OSVVulnerability{}}
	env := newTestEnvCfg(t, func(c *config.Config) {}, func(s *api.Server) { s.SetMCPScanning(osv) })
	author := env.register("da-auth")
	env.verifyEmail(author)
	sess := env.login(author)
	other := env.register("da-other")
	env.verifyEmail(other)
	otherSess := env.login(other)
	_, _ = env.st.Pool().Exec(context.Background(),
		`UPDATE users SET created_at = now() - interval '30 days' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, author)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": author, "name": "alerted", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read", "repo:read")
	if status, body := env.uploadVersionCLI(author, "alerted", pat, map[string]string{
		"agent.yaml": mcpManifest(author, "alerted", "1.0.0", "alerts-fixture", "2.0.0"),
		"AGENT.md":   "Summarise the ticket the user pastes.\n",
		"README.md":  "# alerted\n",
		"LICENSE":    "Apache-2.0\n",
	}); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	waitStatusLong(env, author, "alerted", "1.0.0", "published")

	// The registry's record is public and says what S7 saw.
	var rec struct {
		Status     string  `json:"status"`
		Advisories []any   `json:"advisories"`
		Ecosystem  string  `json:"ecosystem"`
		Package    string  `json:"package"`
		Version    string  `json:"version"`
		LastError  *string `json:"lastError"`
		MaxSev     *string `json:"maxSeverity"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=npm&package=alerts-fixture&version=2.0.0", nil, &rec, http.StatusOK)
	if rec.Status != "safe" || len(rec.Advisories) != 0 || rec.Package != "alerts-fixture" || rec.MaxSev != nil {
		t.Fatalf("scan record: %+v", rec)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=npm&package=alerts-fixture&version=9.9.9", nil, nil, http.StatusNotFound)

	// Each advisory is served with its own severity and the gate's rating
	// of it beside it (agentry#774): a High below 8.5 is medium for the
	// gate, a High with no score and a Critical keep their own.
	if _, err := env.st.Pool().Exec(context.Background(), `
		INSERT INTO mcp_server_scans (ecosystem, package, version, status, max_severity, advisories)
		VALUES ('npm', 'rated-fixture', '1.0.0', 'vulnerable', 'critical', $1)`,
		[]byte(`[{"id":"GHSA-high-84","severity":"high","cvssScore":8.4,"scored":true,"summary":"a"},
		         {"id":"GHSA-high-none","severity":"high","scored":true,"summary":"b"},
		         {"id":"GHSA-crit","severity":"critical","cvssScore":8.6,"scored":true,"summary":"c"}]`)); err != nil {
		t.Fatal(err)
	}
	var rated struct {
		MaxSeverity string `json:"maxSeverity"`
		Advisories  []struct {
			ID           string   `json:"id"`
			Severity     string   `json:"severity"`
			GateSeverity string   `json:"gateSeverity"`
			CVSSScore    *float64 `json:"cvssScore"`
		} `json:"advisories"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=npm&package=rated-fixture&version=1.0.0", nil, &rated, http.StatusOK)
	type want struct {
		severity, gate string
		score          float64 // 0: none served
	}
	wants := map[string]want{
		"GHSA-high-84":   {"high", "medium", 8.4},
		"GHSA-high-none": {"high", "high", 0},
		"GHSA-crit":      {"critical", "critical", 8.6},
	}
	if rated.MaxSeverity != "critical" || len(rated.Advisories) != len(wants) {
		t.Fatalf("rated record: %+v", rated)
	}
	for _, a := range rated.Advisories {
		w := wants[a.ID]
		var score float64
		if a.CVSSScore != nil {
			score = *a.CVSSScore
		}
		if a.Severity != w.severity || a.GateSeverity != w.gate || score != w.score {
			t.Errorf("%s: severity %s, gateSeverity %s, cvssScore %v; want %+v", a.ID, a.Severity, a.GateSeverity, score, w)
		}
	}

	// No alerts yet: an empty list, and none on the page.
	var alerts []map[string]any
	env.doJSON(sess, http.MethodGet, "/api/v1/user/dependency-alerts", nil, &alerts, http.StatusOK)
	if len(alerts) != 0 {
		t.Fatalf("alerts before any: %v", alerts)
	}

	// The sweep opens one (inserted directly: the sweep itself is tested in
	// internal/scan).
	if _, err := env.st.Pool().Exec(context.Background(), `
		INSERT INTO mcp_dependency_alerts (id, version_id, ecosystem, package, package_version, severity, advisory_ids, fixed_in)
		SELECT gen_random_uuid(), v.id, 'npm', 'alerts-fixture', '2.0.0', 'high', ARRAY['GHSA-xvch-5gv4-984h'], ARRAY['1.2.6']
		FROM agent_versions v JOIN agents a ON a.id = v.agent_id WHERE a.name = 'alerted' AND v.version = '1.0.0'`); err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/dependency-alerts", nil, &alerts, http.StatusOK)
	if len(alerts) != 1 || alerts[0]["agent"] != author+"/alerted" || alerts[0]["version"] != "1.0.0" || alerts[0]["severity"] != "high" {
		t.Fatalf("submitter's alerts: %v", alerts)
	}
	if fixed := alerts[0]["fixedIn"].([]any); len(fixed) != 1 || fixed[0] != "1.2.6" {
		t.Fatalf("fixedIn: %v", alerts[0]["fixedIn"])
	}
	var others []map[string]any
	env.doJSON(otherSess, http.MethodGet, "/api/v1/user/dependency-alerts", nil, &others, http.StatusOK)
	if len(others) != 0 {
		t.Fatalf("another user's alerts: %v", others)
	}
	var agent struct {
		DependencyAlerts []map[string]any `json:"dependencyAlerts"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+author+"/alerted", nil, &agent, http.StatusOK)
	if len(agent.DependencyAlerts) != 1 || agent.DependencyAlerts[0]["packageVersion"] != "2.0.0" {
		t.Fatalf("agent page alerts: %v", agent.DependencyAlerts)
	}
}
