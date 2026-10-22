package scan_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// sweepOSV answers from a map the test edits between runs, standing in for
// a database that learns about a vulnerability after publication.
type sweepOSV struct {
	calls int
	asked []scan.OSVPackage
	vulns map[string][]scan.OSVVulnerability
	err   error // set to stand in for an outage
}

func (f *sweepOSV) Query(_ context.Context, pkgs []scan.OSVPackage) (map[string][]scan.OSVVulnerability, error) {
	f.calls++
	f.asked = append(f.asked, pkgs...)
	if f.err != nil {
		return nil, f.err
	}
	out := map[string][]scan.OSVVulnerability{}
	for _, p := range pkgs {
		if v, ok := f.vulns[p.Key()]; ok {
			out[p.Key()] = v
		}
	}
	return out, nil
}

func mcpServerManifest(ns, name, version, pkg string) string {
	return `schemaVersion: "2"
name: ` + name + `
namespace: ` + ns + `
modes: [autonomous]
version: ` + version + `
summary: "declares a server"
license: Apache-2.0
entrypoints:
  instruction: SKILL.md
capabilities:
  mcpServers:
    - npm: ` + pkg + `
      version: "0.1.0"
publish:
  include: [agent.yaml, README.md, SKILL.md, LICENSE]
`
}

// The daily sweep: a server version that was clean at
// publication (a fixture package name of its own for each run: the scanned-server
// registry is keyed by package version, so a row left by an earlier run of the
// test would answer the first publish without asking) and now
// carries a high advisory opens one alert per published
// version declaring it and tells each author once; a yanked version's alert
// closes with the transition; a withdrawn advisory closes the rest.
func TestMCPSweepOpensAndResolvesAlerts(t *testing.T) {
	notifier := &recordingNotifier{}
	e := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Notifier = notifier })
	ctx := context.Background()
	m, err := metrics.New(t.Context(), metrics.Config{ServiceName: "agentryd", Role: "all", Env: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	e.pipe.SetMetrics(m)
	type emitted struct {
		event   string
		agentID uuid.UUID
		payload map[string]any
	}
	var events []emitted
	e.reg.SetEventSink(func(_ context.Context, agentID uuid.UUID, event string, payload map[string]any) {
		events = append(events, emitted{event: event, agentID: agentID, payload: payload})
	})
	osv := &sweepOSV{vulns: map[string][]scan.OSVVulnerability{}}
	e.pipe.SetMCPScanning(osv, scan.NewStoreMCPScanCache(e.st))
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	pkg := "mcp-sweep-fixture-" + suffix()
	files := func(name string) map[string]string {
		return map[string]string{
			"agent.yaml": mcpServerManifest(u.Handle, name, "1.0.0", pkg),
			"README.md":  "# " + name + "\n",
			"SKILL.md":   "Summarize the input.\n",
			"LICENSE":    "Apache-2.0\n",
		}
	}
	v1 := e.publish("uses-a", "public", files("uses-a"))
	v2 := e.publish("uses-b", "public", files("uses-b"))
	if v1.Status != "published" || v2.Status != "published" {
		t.Fatalf("clean publishes: %s / %s", v1.Status, v2.Status)
	}
	if osv.calls != 1 {
		t.Fatalf("S7 lookups at publish = %d, want 1 (second version served from the registry)", osv.calls)
	}
	// Only this test's fixture package goes stale: the database is shared
	// by this binary's tests, and a server row another test
	// published at the same time would otherwise be re-checked and counted
	// here.
	// Two more versions declare the server and are left out of the sweep's
	// alerts: one admitted without a scan, one of an agent whose pipeline is
	// off.
	unscanned := e.publish("uses-unscanned", "public", files("uses-unscanned"))
	skipAgent := e.publish("uses-skip", "private", files("uses-skip"))
	if unscanned.Status != "published" || skipAgent.Status != "published" {
		t.Fatalf("setup: %s / %s", unscanned.Status, skipAgent.Status)
	}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE agent_versions SET scan_status = 'skipped' WHERE id = $1`, unscanned.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE agents SET pipeline_skip = true WHERE id = $1`, skipAgent.AgentID); err != nil {
		t.Fatal(err)
	}
	backdateTo := func(age string) {
		if _, err := e.st.Pool().Exec(ctx, `UPDATE mcp_server_scans SET last_checked_at = now() - $2::interval WHERE ecosystem = 'npm' AND package = $1`, pkg, age); err != nil {
			t.Fatal(err)
		}
	}
	backdate := func() { backdateTo("25 hours") }
	// A row is asked about again once it is 20 hours old: not at 19, at 21.
	for _, tc := range []struct {
		age       string
		wantAsked bool
	}{{"19 hours", false}, {"21 hours", true}} {
		backdateTo(tc.age)
		osv.asked = nil
		if _, err := e.pipe.MCPSweep(ctx); err != nil {
			t.Fatal(err)
		}
		asked := false
		for _, p := range osv.asked {
			asked = asked || p.Name == pkg
		}
		if asked != tc.wantAsked {
			t.Fatalf("a row checked %s ago: asked %v, want %v", tc.age, asked, tc.wantAsked)
		}
	}

	// Nothing new: the sweep re-checks and opens nothing.
	backdate()
	sum, err := e.pipe.MCPSweep(ctx)
	if err != nil || sum.Checked != 1 || sum.AlertsOpened != 0 {
		t.Fatalf("quiet sweep: %+v %v", sum, err)
	}

	// The database learns of high advisories for that exact version: two
	// that alert, with the versions fixing them overlapping and out of
	// order, and a low one, whose fix is not one of the alert's.
	osv.vulns["npm/"+pkg+"@0.1.0"] = []scan.OSVVulnerability{
		{ID: "GHSA-xvch-5gv4-984h", Aliases: []string{"CVE-2021-44906"}, Severity: "high", Summary: "Prototype Pollution", FixedIn: []string{"2.0.0"}},
		{ID: "GHSA-second", Severity: "high", Summary: "Second", FixedIn: []string{"1.3.0", "2.0.0"}},
		{ID: "GHSA-minor", Severity: "low", Summary: "Minor", FixedIn: []string{"0.9.9"}},
	}
	backdate()
	sum, err = e.pipe.MCPSweep(ctx)
	if err != nil || sum.AlertsOpened != 2 || sum.Vulnerable != 1 {
		t.Fatalf("alerting sweep: %+v %v", sum, err)
	}
	if len(notifier.mcpAlerts) != 2 {
		t.Fatalf("author notices: %d, want 2", len(notifier.mcpAlerts))
	}
	wantIDs, wantFixed := []string{"GHSA-xvch-5gv4-984h", "GHSA-second"}, []string{"1.3.0", "2.0.0"}
	n := notifier.mcpAlerts[0]
	if n.ToEmail != u.Email || n.Server != "npm:"+pkg+"@0.1.0" || n.Severity != "high" || !slices.Equal(n.Advisories, wantIDs) ||
		!slices.Equal(n.FixedIn, wantFixed) || n.Version != "1.0.0" || n.Agent != u.Handle+"/uses-a" || n.AgentURL != "https://test.example/"+u.Handle+"/uses-a" {
		t.Fatalf("notice: %+v", n)
	}
	if n1 := notifier.mcpAlerts[1]; n1.Agent != u.Handle+"/uses-b" || n1.AgentURL != "https://test.example/"+u.Handle+"/uses-b" {
		t.Fatalf("second notice: %+v", n1)
	}
	// The sweep writes the row as read since scores were kept, so
	// S7 answers from it rather than asking again; the row keeps its worst
	// severity.
	if rec, _ := scan.NewStoreMCPScanCache(e.st).Get(ctx, "npm", pkg, "0.1.0"); rec == nil || len(rec.Advisories) != 3 || rec.MaxSeverity != "high" || rec.Status != "vulnerable" ||
		!rec.Advisories[0].Scored || !rec.Advisories[1].Scored || !rec.Advisories[2].Scored {
		t.Fatalf("swept row: %+v", rec)
	}
	open1, _ := e.st.Queries().ListOpenMCPDependencyAlertsForVersion(ctx, v1.ID)
	if len(open1) != 1 || open1[0].Severity != "high" || open1[0].NotifiedAt == nil || !slices.Equal(open1[0].AdvisoryIds, wantIDs) || !slices.Equal(open1[0].FixedIn, wantFixed) {
		t.Fatalf("alert on v1: %+v", open1)
	}
	for _, left := range []storegen.AgentVersion{unscanned, skipAgent} {
		if open, _ := e.st.Queries().ListOpenMCPDependencyAlertsForVersion(ctx, left.ID); len(open) != 0 {
			t.Fatalf("an alert was opened on a version the sweep leaves out: %+v", open)
		}
	}
	// The three notifications of each alert: mail (above), the audit trail
	// and the org webhook.
	var alertEvents int
	for _, ev := range events {
		if ev.event != "agent.dependency_alert" {
			continue
		}
		alertEvents++
		if ev.payload["severity"] != "high" || ev.payload["server"] != "npm:"+pkg+"@0.1.0" || ev.payload["version"] != "1.0.0" ||
			!slices.Equal(payloadStrings(ev.payload["advisories"]), wantIDs) || !slices.Equal(payloadStrings(ev.payload["fixedIn"]), wantFixed) {
			t.Fatalf("agent.dependency_alert payload = %v", ev.payload)
		}
	}
	if alertEvents != 2 {
		t.Fatalf("agent.dependency_alert events = %d, want 2", alertEvents)
	}
	rows, err := e.st.Pool().Query(ctx, `SELECT detail FROM audit_events WHERE action = 'agent.dependency_alert' AND target_id = ANY($1)`, []uuid.UUID{v1.ID, v2.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	audited := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var d map[string]any
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		if d["server"] != "npm:"+pkg+"@0.1.0" || d["severity"] != "high" || d["version"] != "1.0.0" || d["alert_id"] == "" || len(payloadList(d["advisories"])) != 2 {
			t.Fatalf("audit detail = %v", d)
		}
		audited++
	}
	rows.Close()
	if audited != 2 {
		t.Fatalf("agent.dependency_alert audit events = %d, want 2", audited)
	}
	// The metric counts the alerts the sweep opened.
	gathered, err := m.Gather(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	opened := false
	for _, line := range strings.Split(string(gathered), "\n") {
		opened = opened || (strings.HasPrefix(line, "McpDependencyAlertsOpened") && strings.HasSuffix(line, " 2"))
	}
	if !opened {
		t.Fatalf("no McpDependencyAlertsOpened sample of 2 in:\n%s", gathered)
	}

	// The same advisory again is not news: no duplicate alert, no second mail.
	backdate()
	sum, err = e.pipe.MCPSweep(ctx)
	if err != nil || sum.AlertsOpened != 0 || len(notifier.mcpAlerts) != 2 {
		t.Fatalf("repeat sweep: %+v %v notices=%d", sum, err, len(notifier.mcpAlerts))
	}

	// Yanking a version closes its alert with the transition.
	if err := e.reg.Transition(ctx, v1.ID, registry.StatusYanked, "test yank", audit.Event{Actor: e.owner, ActorKind: audit.ActorUser}); err != nil {
		t.Fatal(err)
	}
	open1, _ = e.st.Queries().ListOpenMCPDependencyAlertsForVersion(ctx, v1.ID)
	if len(open1) != 0 {
		t.Fatalf("v1 alert survived the yank: %+v", open1)
	}
	var reason string
	_ = e.st.Pool().QueryRow(ctx, `SELECT resolved_reason FROM mcp_dependency_alerts WHERE version_id = $1`, v1.ID).Scan(&reason)
	if reason != "version-yanked" {
		t.Fatalf("resolved reason: %q", reason)
	}

	// A further advisory opens no alert on the yanked version.
	osv.vulns["npm/"+pkg+"@0.1.0"] = append(osv.vulns["npm/"+pkg+"@0.1.0"], scan.OSVVulnerability{ID: "GHSA-late", Severity: "critical", Summary: "late"})
	backdate()
	sum, err = e.pipe.MCPSweep(ctx)
	if err != nil || sum.AlertsOpened != 0 {
		t.Fatalf("sweep with a further advisory: %+v %v; want no alert on the yanked version", sum, err)
	}
	open1, _ = e.st.Queries().ListOpenMCPDependencyAlertsForVersion(ctx, v1.ID)
	if len(open1) != 0 {
		t.Fatalf("a yanked version got an alert: %+v", open1)
	}

	// The advisory is withdrawn: the remaining alert closes as such.
	osv.vulns = map[string][]scan.OSVVulnerability{}
	backdate()
	sum, err = e.pipe.MCPSweep(ctx)
	if err != nil || sum.AlertsResolved != 1 {
		t.Fatalf("withdrawal sweep: %+v %v", sum, err)
	}
	open2, _ := e.st.Queries().ListOpenMCPDependencyAlertsForVersion(ctx, v2.ID)
	if len(open2) != 0 {
		t.Fatalf("v2 alert survived the withdrawal: %+v", open2)
	}
	_ = e.st.Pool().QueryRow(ctx, `SELECT resolved_reason FROM mcp_dependency_alerts WHERE version_id = $1`, v2.ID).Scan(&reason)
	if reason != "withdrawn" {
		t.Fatalf("withdrawn reason: %q", reason)
	}

	// Belt and braces: an alert left open on a version that is no longer
	// published (whatever left it so) is closed by the next sweep, with the
	// version's state as the reason.
	pkg2 := "mcp-sweep-left-" + suffix()
	v3 := e.publish("uses-c", "public", map[string]string{
		"agent.yaml": mcpServerManifest(u.Handle, "uses-c", "1.0.0", pkg2),
		"README.md":  "# uses-c\n", "SKILL.md": "Summarize the input.\n", "LICENSE": "Apache-2.0\n",
	})
	if v3.Status != "published" {
		t.Fatalf("third publish: %s", v3.Status)
	}
	osv.vulns["npm/"+pkg2+"@0.1.0"] = []scan.OSVVulnerability{{ID: "GHSA-left", Severity: "critical", Summary: "x", FixedIn: []string{"0.2.0"}}}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE mcp_server_scans SET last_checked_at = now() - interval '25 hours' WHERE ecosystem = 'npm' AND package = $1`, pkg2); err != nil {
		t.Fatal(err)
	}
	if sum, err = e.pipe.MCPSweep(ctx); err != nil || sum.AlertsOpened != 1 {
		t.Fatalf("sweep opening the third alert: %+v %v", sum, err)
	}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE agent_versions SET status = 'quarantined' WHERE id = $1`, v3.ID); err != nil {
		t.Fatal(err)
	}
	if open3, _ := e.st.Queries().ListOpenMCPDependencyAlertsForVersion(ctx, v3.ID); len(open3) != 1 {
		t.Fatalf("setup: the alert on the third version = %+v, want it still open", open3)
	}
	if sum, err = e.pipe.MCPSweep(ctx); err != nil || sum.AlertsResolved < 1 {
		t.Fatalf("sweep after the version left published: %+v %v", sum, err)
	}
	_ = e.st.Pool().QueryRow(ctx, `SELECT resolved_reason FROM mcp_dependency_alerts WHERE version_id = $1`, v3.ID).Scan(&reason)
	if reason != "version-quarantined" {
		t.Fatalf("resolved reason for a version that left published: %q", reason)
	}
}

// A person who switched dependency-alert mail off still gets
// the alert — banner, dashboard, audit, webhook — and no mail.
func TestMCPSweepRespectsEmailPreference(t *testing.T) {
	notifier := &recordingNotifier{}
	e := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Notifier = notifier })
	ctx := context.Background()
	osv := &sweepOSV{vulns: map[string][]scan.OSVVulnerability{}}
	e.pipe.SetMCPScanning(osv, scan.NewStoreMCPScanCache(e.st))
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	if _, err := e.st.Pool().Exec(ctx, `INSERT INTO user_notification_settings (user_id, email_dependency_alerts) VALUES ($1, false)`, e.owner); err != nil {
		t.Fatal(err)
	}
	pkg := "quiet-fixture-" + suffix()
	manifest := mcpServerManifest(u.Handle, "quiet-owner", "1.0.0", pkg)
	v := e.publish("quiet-owner", "public", map[string]string{
		"agent.yaml": manifest, "README.md": "# quiet\n", "SKILL.md": "Summarize.\n", "LICENSE": "Apache-2.0\n",
	})
	if v.Status != "published" {
		t.Fatalf("publish: %s", v.Status)
	}
	osv.vulns["npm/"+pkg+"@0.1.0"] = []scan.OSVVulnerability{{ID: "GHSA-quiet", Severity: "high", Summary: "x"}}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE mcp_server_scans SET last_checked_at = now() - interval '25 hours' WHERE ecosystem = 'npm' AND package = $1`, pkg); err != nil {
		t.Fatal(err)
	}
	sum, err := e.pipe.MCPSweep(ctx)
	if err != nil || sum.AlertsOpened != 1 {
		t.Fatalf("sweep: %+v %v", sum, err)
	}
	if len(notifier.mcpAlerts) != 0 {
		t.Fatalf("mail sent despite the setting: %+v", notifier.mcpAlerts)
	}
	open, _ := e.st.Queries().ListOpenMCPDependencyAlertsForVersion(ctx, v.ID)
	if len(open) != 1 {
		t.Fatalf("alert must still open: %+v", open)
	}
}

// A sweep that stops on an error is counted as McpSweepRuns{outcome="error"},
// the series operators watch; a failed sweep must not record
// its run as "ok".
func TestMCPSweepCountsAFailedRunAsAnError(t *testing.T) {
	e := newPipeEnv(t)
	m, err := metrics.New(t.Context(), metrics.Config{ServiceName: "agentryd", Role: "all", Env: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	e.pipe.SetMetrics(m)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.pipe.MCPSweep(ctx); err == nil {
		t.Fatal("a sweep on a cancelled context returned no error")
	}
	out, err := m.Gather(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "McpSweepRuns{") && strings.Contains(line, `outcome="error"`) && strings.HasSuffix(line, " 1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no McpSweepRuns{outcome=\"error\"} 1 sample in:\n%s", out)
	}

	// With no vulnerability database the sweep re-checks nothing and says so
	// by doing nothing: it neither asks nor fails.
	cache := scan.NewStoreMCPScanCache(e.st)
	if e.pipe.MCPScanningEnabled() {
		t.Fatal("a pipeline with no vulnerability database reports MCP scanning enabled")
	}
	if sum, err := e.pipe.MCPSweep(context.Background()); err != nil || sum != (scan.MCPSweepSummary{}) {
		t.Fatalf("sweep with no database: %+v, %v; want a zero summary", sum, err)
	}
	e.pipe.SetMCPScanning(scan.OfflineOSV{}, cache)
	if e.pipe.MCPScanningEnabled() {
		t.Fatal("an offline vulnerability database reports MCP scanning enabled")
	}
	if sum, err := e.pipe.MCPSweep(context.Background()); err != nil || sum != (scan.MCPSweepSummary{}) {
		t.Fatalf("sweep with an offline database: %+v, %v; want a zero summary", sum, err)
	}
	e.pipe.SetMCPScanning(&sweepOSV{}, cache)
	if !e.pipe.MCPScanningEnabled() {
		t.Fatal("a pipeline with a vulnerability database and a registry reports MCP scanning disabled")
	}
	e.pipe.SetMCPScanning(&sweepOSV{}, nil)
	if e.pipe.MCPScanningEnabled() {
		t.Fatal("a vulnerability database with no scanned-server registry reports MCP scanning enabled")
	}
}

// A sweep whose lookup fails keeps each row's answer: a safe or vulnerable
// row stays so, advisories and all, and only records the error. S7 counts
// an error row as no answer, so a sweep that turned a real
// answer into an error row would hold every later submission for review.
func TestMCPSweepLookupFailureKeepsTheAnswer(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	osv := &sweepOSV{vulns: map[string][]scan.OSVVulnerability{}}
	cache := scan.NewStoreMCPScanCache(e.st)
	e.pipe.SetMCPScanning(osv, cache)
	long := time.Now().Add(-48 * time.Hour)
	adv := []scan.OSVVulnerability{{ID: "GHSA-kept", Severity: "medium", Summary: "kept"}}
	for _, r := range []scan.MCPScanRecord{
		{Ecosystem: "npm", Package: "sweep-outage-safe", Version: "1.0.0", Status: "safe", LastChecked: long},
		{Ecosystem: "npm", Package: "sweep-outage-vuln", Version: "1.0.0", Status: "vulnerable", MaxSeverity: "medium", Advisories: adv, LastChecked: long},
	} {
		if err := cache.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE mcp_server_scans SET last_checked_at = now() - interval '48 hours' WHERE package LIKE 'sweep-outage-%'`); err != nil {
		t.Fatal(err)
	}
	osv.err = errors.New("dial tcp: i/o timeout")
	sum, err := e.pipe.MCPSweep(ctx)
	if err != nil || sum.LookupErrors < 2 {
		t.Fatalf("sweep during an outage: %+v %v", sum, err)
	}
	safe, _ := cache.Get(ctx, "npm", "sweep-outage-safe", "1.0.0")
	if safe == nil || safe.Status != "safe" || safe.LastError == "" {
		t.Fatalf("safe row after a failed sweep: %+v", safe)
	}
	vuln, _ := cache.Get(ctx, "npm", "sweep-outage-vuln", "1.0.0")
	if vuln == nil || vuln.Status != "vulnerable" || len(vuln.Advisories) != 1 || vuln.Advisories[0].ID != "GHSA-kept" || vuln.LastError == "" {
		t.Fatalf("vulnerable row after a failed sweep: %+v", vuln)
	}
}

// A version its registry does not publish keeps "not-found"
// through the daily sweep. OSV's "no advisories" would otherwise turn it
// back into "safe". The row
// moves past the cutoff, so the sweep's loop ends, and OSV is not asked.
func TestMCPSweepLeavesANotFoundRow(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	osv := &sweepOSV{vulns: map[string][]scan.OSVVulnerability{}}
	cache := scan.NewStoreMCPScanCache(e.st)
	e.pipe.SetMCPScanning(osv, cache)
	if err := cache.Put(ctx, scan.MCPScanRecord{Ecosystem: "npm", Package: "sweep-not-found", Version: "0.1.23", Status: "not-found", LastChecked: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE mcp_server_scans SET last_checked_at = now() - interval '48 hours' WHERE package = 'sweep-not-found'`); err != nil {
		t.Fatal(err)
	}
	// With no vulnerability database to ask, the sweep re-checks nothing:
	// the row keeps its old check time.
	e.pipe.SetMCPScanning(scan.OfflineOSV{}, cache)
	if sum, err := e.pipe.MCPSweep(ctx); err != nil || sum.Checked != 0 {
		t.Fatalf("offline sweep = %+v, %v; want nothing checked", sum, err)
	}
	if n := countRows(t, e, `SELECT count(*) FROM mcp_server_scans WHERE package = 'sweep-not-found' AND last_checked_at < now() - interval '47 hours'`); n != 1 {
		t.Fatal("an offline sweep moved the not-found row's check time")
	}
	e.pipe.SetMCPScanning(osv, cache)
	if _, err := e.pipe.MCPSweep(ctx); err != nil {
		t.Fatal(err)
	}
	row, _ := cache.Get(ctx, "npm", "sweep-not-found", "0.1.23")
	if row == nil || row.Status != "not-found" || time.Since(row.LastChecked) > time.Hour {
		t.Fatalf("not-found row after the sweep: %+v", row)
	}
	for _, p := range osv.asked {
		if p.Name == "sweep-not-found" {
			t.Fatalf("the sweep asked OSV about a version that does not exist")
		}
	}
}

// payloadStrings is a notification payload's list of strings; nil when the
// field is missing or of another type.
func payloadStrings(v any) []string {
	s, _ := v.([]string)
	return s
}

// payloadList is a decoded JSON list; nil when the field is missing or not
// a list.
func payloadList(v any) []any {
	l, _ := v.([]any)
	return l
}
