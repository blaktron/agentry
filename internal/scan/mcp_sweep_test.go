package scan_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
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

func mcpServerManifest(ns, name, version string) string {
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
    - npm: mcp-sweep-fixture
      version: "0.1.0"
publish:
  include: [agent.yaml, README.md, SKILL.md, LICENSE]
`
}

// The daily sweep: a server version that was clean at
// publication (a fixture package name of its own: this binary's pipeline tests
// share a database, and mcp_server_scans is keyed by version) and now
// carries a high advisory opens one alert per published
// version declaring it and tells each author once; a yanked version's alert
// closes with the transition; a withdrawn advisory closes the rest.
func TestMCPSweepOpensAndResolvesAlerts(t *testing.T) {
	notifier := &recordingNotifier{}
	e := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Notifier = notifier })
	ctx := context.Background()
	osv := &sweepOSV{vulns: map[string][]scan.OSVVulnerability{}}
	e.pipe.SetMCPScanning(osv, scan.NewStoreMCPScanCache(e.st))
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	files := func(name string) map[string]string {
		return map[string]string{
			"agent.yaml": mcpServerManifest(u.Handle, name, "1.0.0"),
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
	backdate := func() {
		if _, err := e.st.Pool().Exec(ctx, `UPDATE mcp_server_scans SET last_checked_at = now() - interval '25 hours' WHERE ecosystem = 'npm' AND package = 'mcp-sweep-fixture'`); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing new: the sweep re-checks and opens nothing.
	backdate()
	sum, err := e.pipe.MCPSweep(ctx)
	if err != nil || sum.Checked != 1 || sum.AlertsOpened != 0 {
		t.Fatalf("quiet sweep: %+v %v", sum, err)
	}

	// The database learns of a high advisory for that exact version.
	osv.vulns["npm/mcp-sweep-fixture@0.1.0"] = []scan.OSVVulnerability{{ID: "GHSA-xvch-5gv4-984h", Aliases: []string{"CVE-2021-44906"}, Severity: "high", Summary: "Prototype Pollution", FixedIn: []string{"1.2.6"}}}
	backdate()
	sum, err = e.pipe.MCPSweep(ctx)
	if err != nil || sum.AlertsOpened != 2 || sum.Vulnerable != 1 {
		t.Fatalf("alerting sweep: %+v %v", sum, err)
	}
	if len(notifier.mcpAlerts) != 2 {
		t.Fatalf("author notices: %d, want 2", len(notifier.mcpAlerts))
	}
	n := notifier.mcpAlerts[0]
	if n.ToEmail != u.Email || n.Server != "npm:mcp-sweep-fixture@0.1.0" || n.Severity != "high" || len(n.Advisories) != 1 || n.FixedIn[0] != "1.2.6" || n.Version != "1.0.0" {
		t.Fatalf("notice: %+v", n)
	}
	// The sweep writes the row as read since scores were kept, so
	// S7 answers from it rather than asking again.
	if rec, _ := scan.NewStoreMCPScanCache(e.st).Get(ctx, "npm", "mcp-sweep-fixture", "0.1.0"); rec == nil || len(rec.Advisories) != 1 || !rec.Advisories[0].Scored {
		t.Fatalf("swept row: %+v", rec)
	}
	open1, _ := e.st.Queries().ListOpenMCPDependencyAlertsForVersion(ctx, v1.ID)
	if len(open1) != 1 || open1[0].Severity != "high" || open1[0].NotifiedAt == nil || open1[0].AdvisoryIds[0] != "GHSA-xvch-5gv4-984h" {
		t.Fatalf("alert on v1: %+v", open1)
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
	manifest := strings.ReplaceAll(mcpServerManifest(u.Handle, "quiet-owner", "1.0.0"), "mcp-sweep-fixture", "quiet-fixture")
	v := e.publish("quiet-owner", "public", map[string]string{
		"agent.yaml": manifest, "README.md": "# quiet\n", "SKILL.md": "Summarize.\n", "LICENSE": "Apache-2.0\n",
	})
	if v.Status != "published" {
		t.Fatalf("publish: %s", v.Status)
	}
	osv.vulns["npm/quiet-fixture@0.1.0"] = []scan.OSVVulnerability{{ID: "GHSA-quiet", Severity: "high", Summary: "x"}}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE mcp_server_scans SET last_checked_at = now() - interval '25 hours' WHERE ecosystem = 'npm' AND package = 'quiet-fixture'`); err != nil {
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
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "McpSweepRuns{") && strings.Contains(line, `outcome="error"`) && strings.HasSuffix(line, " 1") {
			return
		}
	}
	t.Fatalf("no McpSweepRuns{outcome=\"error\"} 1 sample in:\n%s", out)
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
