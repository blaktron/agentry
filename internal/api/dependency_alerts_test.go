package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/scan"
)

// The surfaces of a dependency alert: the submitter's list
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
		FirstSeen  string  `json:"firstSeenAt"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=npm&package=alerts-fixture&version=2.0.0", nil, &rec, http.StatusOK)
	if rec.Status != "safe" || len(rec.Advisories) != 0 || rec.Package != "alerts-fixture" || rec.MaxSev != nil {
		t.Fatalf("scan record: %+v", rec)
	}
	if rec.Ecosystem != "npm" || rec.Version != "2.0.0" || rec.FirstSeen == "" || strings.HasPrefix(rec.FirstSeen, "0001") {
		t.Fatalf("scan record identity: %+v", rec)
	}
	// No advisories is an empty list on the wire, never null.
	scanRes := env.do(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=npm&package=alerts-fixture&version=2.0.0", nil)
	scanRaw, _ := io.ReadAll(scanRes.Body)
	_ = scanRes.Body.Close()
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(scanRaw, &wire); err != nil || string(wire["advisories"]) != "[]" {
		t.Fatalf("advisories on the wire = %s (%v), want []", wire["advisories"], err)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=npm&package=alerts-fixture&version=9.9.9", nil, nil, http.StatusNotFound)

	// Each advisory is served with its own severity and the gate's rating
	// of it beside it: a High below 8.5 is medium for the
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

	// A version the package registry does not publish is served as an error
	// with the reason, never as the stored word; a stored error keeps its
	// own reason.
	for _, row := range []struct{ pkg, status, lastError string }{
		{"absent-fixture", "not-found", ""},
		{"failing-fixture", "error", "registry unreachable"},
	} {
		var lastError *string
		if row.lastError != "" {
			lastError = &row.lastError
		}
		if _, err := env.st.Pool().Exec(context.Background(), `
			INSERT INTO mcp_server_scans (ecosystem, package, version, status, advisories, last_error)
			VALUES ('npm', $1, '1.0.0', $2, '[]', $3)`, row.pkg, row.status, lastError); err != nil {
			t.Fatal(err)
		}
		var got struct {
			Status    string  `json:"status"`
			LastError *string `json:"lastError"`
		}
		env.doJSON(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=npm&package="+row.pkg+"&version=1.0.0", nil, &got, http.StatusOK)
		want := row.lastError
		if row.status == "not-found" {
			want = "the package registry does not publish this version"
		}
		if got.Status != "error" || got.LastError == nil || *got.LastError != want {
			t.Fatalf("%s record: %+v, want status error and reason %q", row.pkg, got, want)
		}
	}

	// The ecosystem is part of the key: the same package name under another
	// ecosystem is another record.
	if _, err := env.st.Pool().Exec(context.Background(), `
		INSERT INTO mcp_server_scans (ecosystem, package, version, status, advisories)
		VALUES ('pypi', 'py-fixture', '1.0.0', 'safe', '[]')`); err != nil {
		t.Fatal(err)
	}
	var py struct {
		Ecosystem string `json:"ecosystem"`
		Package   string `json:"package"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=pypi&package=py-fixture&version=1.0.0", nil, &py, http.StatusOK)
	if py.Ecosystem != "pypi" || py.Package != "py-fixture" {
		t.Fatalf("pypi record: %+v", py)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=npm&package=py-fixture&version=1.0.0", nil, nil, http.StatusNotFound)

	// An advisory's other ids, fixed versions and references are served with
	// it; a High at exactly the gate's threshold is high, and a Critical
	// below it stays critical.
	if _, err := env.st.Pool().Exec(context.Background(), `
		INSERT INTO mcp_server_scans (ecosystem, package, version, status, max_severity, advisories)
		VALUES ('npm', 'detail-fixture', '1.0.0', 'vulnerable', 'critical', $1)`,
		[]byte(`[{"id":"GHSA-high-85","severity":"high","cvssScore":8.5,"scored":true,"summary":"d",
		          "aliases":["CVE-2026-0001"],"fixedIn":["1.2.6"],"references":["https://example.test/advisory"]},
		         {"id":"GHSA-crit-low","severity":"critical","cvssScore":7.0,"scored":true,"summary":"e"}]`)); err != nil {
		t.Fatal(err)
	}
	var detailed struct {
		Advisories []struct {
			ID           string    `json:"id"`
			GateSeverity string    `json:"gateSeverity"`
			Aliases      *[]string `json:"aliases"`
			FixedIn      *[]string `json:"fixedIn"`
			References   *[]string `json:"references"`
		} `json:"advisories"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/mcp-servers/scan?ecosystem=npm&package=detail-fixture&version=1.0.0", nil, &detailed, http.StatusOK)
	if len(detailed.Advisories) != 2 {
		t.Fatalf("detailed record: %+v", detailed)
	}
	for _, a := range detailed.Advisories {
		switch a.ID {
		case "GHSA-high-85":
			if a.GateSeverity != "high" || a.Aliases == nil || len(*a.Aliases) != 1 || (*a.Aliases)[0] != "CVE-2026-0001" ||
				a.FixedIn == nil || len(*a.FixedIn) != 1 || (*a.FixedIn)[0] != "1.2.6" ||
				a.References == nil || len(*a.References) != 1 || (*a.References)[0] != "https://example.test/advisory" {
				t.Errorf("GHSA-high-85 served as %+v", a)
			}
		case "GHSA-crit-low":
			if a.GateSeverity != "critical" || a.Aliases != nil || a.FixedIn != nil || a.References != nil {
				t.Errorf("GHSA-crit-low served as %+v", a)
			}
		default:
			t.Errorf("unexpected advisory %s", a.ID)
		}
	}

	// The submitter's list is the account's own: no credential, no answer.
	env.doJSON(anonymous, http.MethodGet, "/api/v1/user/dependency-alerts", nil, nil, http.StatusUnauthorized)

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

	// Another agent's alert is on that agent's page and not on this one's.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": author, "name": "alerted2", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	if status, body := env.uploadVersionCLI(author, "alerted2", pat, map[string]string{
		"agent.yaml": mcpManifest(author, "alerted2", "1.0.0", "alerts-fixture-two", "1.0.0"),
		"AGENT.md":   "Summarise the ticket the user pastes.\n",
		"README.md":  "# alerted2\n",
		"LICENSE":    "Apache-2.0\n",
	}); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	waitStatusLong(env, author, "alerted2", "1.0.0", "published")
	if _, err := env.st.Pool().Exec(context.Background(), `
		INSERT INTO mcp_dependency_alerts (id, version_id, ecosystem, package, package_version, severity, advisory_ids)
		SELECT gen_random_uuid(), v.id, 'npm', 'alerts-fixture-two', '1.0.0', 'high', ARRAY['GHSA-two']
		FROM agent_versions v JOIN agents a ON a.id = v.agent_id WHERE a.name = 'alerted2' AND v.version = '1.0.0'`); err != nil {
		t.Fatal(err)
	}
	var second struct {
		DependencyAlerts []map[string]any `json:"dependencyAlerts"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+author+"/alerted2", nil, &second, http.StatusOK)
	if len(second.DependencyAlerts) != 1 || second.DependencyAlerts[0]["package"] != "alerts-fixture-two" {
		t.Fatalf("second agent's page alerts: %v", second.DependencyAlerts)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+author+"/alerted", nil, &agent, http.StatusOK)
	if len(agent.DependencyAlerts) != 1 || agent.DependencyAlerts[0]["packageVersion"] != "2.0.0" {
		t.Fatalf("first agent's page alerts with another agent's alert in the registry: %v", agent.DependencyAlerts)
	}

	// A resolved alert is history and on neither surface; a second open alert
	// is listed, newest first for the submitter and oldest first on the page.
	for _, row := range []struct{ pkgVersion, resolved, created string }{
		{"1.0.0", "now()", "now()"},
		{"3.0.0", "NULL", "now() + interval '1 minute'"},
	} {
		if _, err := env.st.Pool().Exec(context.Background(), `
			INSERT INTO mcp_dependency_alerts (id, version_id, ecosystem, package, package_version, severity, advisory_ids, resolved_at, created_at)
			SELECT gen_random_uuid(), v.id, 'npm', 'alerts-fixture', '`+row.pkgVersion+`', 'critical', ARRAY['GHSA-later'], `+row.resolved+`, `+row.created+`
			FROM agent_versions v JOIN agents a ON a.id = v.agent_id WHERE a.name = 'alerted' AND v.version = '1.0.0'`); err != nil {
			t.Fatal(err)
		}
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/dependency-alerts", nil, &alerts, http.StatusOK)
	if len(alerts) != 3 || alerts[0]["packageVersion"] != "3.0.0" || alerts[1]["package"] != "alerts-fixture-two" || alerts[2]["packageVersion"] != "2.0.0" {
		t.Fatalf("submitter's alerts with a resolved one and two more open ones: %v", alerts)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+author+"/alerted", nil, &agent, http.StatusOK)
	if len(agent.DependencyAlerts) != 2 || agent.DependencyAlerts[0]["packageVersion"] != "2.0.0" || agent.DependencyAlerts[1]["packageVersion"] != "3.0.0" {
		t.Fatalf("agent page alerts with a resolved and a second open one: %v", agent.DependencyAlerts)
	}
}
