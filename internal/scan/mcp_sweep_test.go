package scan_test

import (
	"context"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
)

// sweepOSV answers from a map the test edits between runs, standing in for
// a database that learns about a vulnerability after publication.
type sweepOSV struct {
	calls int
	vulns map[string][]scan.OSVVulnerability
}

func (f *sweepOSV) Query(_ context.Context, pkgs []scan.OSVPackage) (map[string][]scan.OSVVulnerability, error) {
	f.calls++
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

// The daily sweep (agentry#177 M2): a server version that was clean at
// publication (a fixture package name of its own: the test database is
// shared with the API tests, and mcp_server_scans is keyed by version) and now
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
	// with every other package's tests, and a server row another test
	// published at the same time would otherwise be re-checked and counted
	// here (agentry#245).
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

// A person who switched dependency-alert mail off (agentry#190) still gets
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
