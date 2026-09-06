package scan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/webhook"
)

// The daily MCP server vulnerability sweep (agentry#177 M2, plan §5). Every
// row of the scanned-server registry older than mcpSweepRecheckAfter is
// asked about again. A server version that newly carries a high or critical
// advisory opens a dependency alert on every published version that
// declares it, and the author hears about it three ways: email, the audit
// trail, the org webhook. A server whose advisories were withdrawn closes
// its alerts; a version that left `published` closes its own.

// JobMCPSweep is the queue job kind; the worker process enqueues it once a
// day (and at start-up), and the handler is idempotent.
const JobMCPSweep = "scan.mcp_sweep"

// mcpSweepRecheckAfter is the age at which the sweep re-queries a row: under
// the 24 h S7 TTL so a daily sweep always refreshes every row.
const mcpSweepRecheckAfter = 20 * time.Hour

// mcpSweepBatch is the registry page size per OSV batch.
const mcpSweepBatch = 200

// MCPSweepSummary is what one sweep did.
type MCPSweepSummary struct {
	Checked        int
	Vulnerable     int
	AlertsOpened   int
	AlertsResolved int
	LookupErrors   int
}

// MCPSweep re-checks the scanned-server registry and reconciles alerts.
func (p *Pipeline) MCPSweep(ctx context.Context) (MCPSweepSummary, error) {
	var sum MCPSweepSummary
	q := p.st.Queries()
	defer func() { p.mx.RecordMCPSweep(ctx, sum.AlertsOpened, nil) }()

	// Versions that left `published` since the last sweep (belt and braces:
	// the transition itself resolves them too).
	if n, err := q.ResolveMCPDependencyAlertsForUnpublishedVersions(ctx); err != nil {
		return sum, fmt.Errorf("mcp sweep: resolve alerts of unpublished versions: %w", err)
	} else {
		sum.AlertsResolved += int(n)
	}
	if !osvEnabled(p.osv) || p.mcpCache == nil {
		p.log.Info("mcp sweep: no vulnerability database configured; registry not re-checked")
		return sum, nil
	}
	cutoff := time.Now().Add(-mcpSweepRecheckAfter)
	for {
		rows, err := q.ListMCPServerScansCheckedBefore(ctx, storegen.ListMCPServerScansCheckedBeforeParams{LastCheckedAt: cutoff, Limit: mcpSweepBatch})
		if err != nil {
			return sum, fmt.Errorf("mcp sweep: list registry: %w", err)
		}
		if len(rows) == 0 {
			break
		}
		pkgs := make([]OSVPackage, 0, len(rows))
		for _, r := range rows {
			pkgs = append(pkgs, OSVPackage{Ecosystem: osvEcosystem(r.Ecosystem), Name: r.Package, Version: r.Version})
		}
		vulns, err := p.osv.Query(ctx, pkgs)
		for i, r := range rows {
			prev := mcpScanRecordFromRow(r)
			sum.Checked++
			if err != nil {
				// Keep what we knew, note the failure, and move the row past
				// the cutoff so the loop terminates; tomorrow tries again.
				sum.LookupErrors++
				stale := *prev
				stale.LastError = err.Error()
				stale.LastChecked = time.Now()
				if perr := p.mcpCache.Put(ctx, stale); perr != nil {
					return sum, fmt.Errorf("mcp sweep: record lookup error: %w", perr)
				}
				continue
			}
			cur := MCPScanRecord{Ecosystem: r.Ecosystem, Package: r.Package, Version: r.Version,
				Status: "safe", Advisories: vulns[pkgs[i].Key()], FirstSeen: prev.FirstSeen, LastChecked: time.Now()}
			if len(cur.Advisories) > 0 {
				cur.Status = "vulnerable"
				cur.MaxSeverity = worstSeverity(cur.Advisories)
				sum.Vulnerable++
			}
			if perr := p.mcpCache.Put(ctx, cur); perr != nil {
				return sum, fmt.Errorf("mcp sweep: record %s: %w", pkgs[i].Key(), perr)
			}
			if newIDs, sev := newlyAlertable(prev, cur); len(newIDs) > 0 {
				opened, oerr := p.openMCPAlerts(ctx, cur, newIDs, sev)
				if oerr != nil {
					return sum, oerr
				}
				sum.AlertsOpened += opened
			} else if prev.Status == "vulnerable" && cur.Status == "safe" {
				reason := "withdrawn"
				n, rerr := q.ResolveMCPDependencyAlertsForServer(ctx, storegen.ResolveMCPDependencyAlertsForServerParams{
					Ecosystem: r.Ecosystem, Package: r.Package, PackageVersion: r.Version, ResolvedReason: &reason})
				if rerr != nil {
					return sum, fmt.Errorf("mcp sweep: resolve withdrawn alerts: %w", rerr)
				}
				sum.AlertsResolved += int(n)
			}
		}
		if err != nil {
			p.log.Error("mcp sweep: vulnerability lookup failed for a batch", "servers", len(rows), "err", err)
		}
	}
	p.log.Info("mcp sweep: done", "checked", sum.Checked, "vulnerable", sum.Vulnerable,
		"alertsOpened", sum.AlertsOpened, "alertsResolved", sum.AlertsResolved, "lookupErrors", sum.LookupErrors)
	return sum, nil
}

// newlyAlertable returns the high/critical advisory ids of cur that prev did
// not already carry, and the worst of their severities. A server that was
// safe, or vulnerable only at lower severities, and now has a high or
// critical advisory is exactly the "new CVE for a version marked safe" the
// sweep exists to catch; an advisory prev already knew is not news.
func newlyAlertable(prev *MCPScanRecord, cur MCPScanRecord) ([]string, string) {
	known := map[string]bool{}
	if prev != nil {
		for _, v := range prev.Advisories {
			if alertable(v.Severity) {
				known[v.ID] = true
			}
		}
	}
	var ids []string
	worst := ""
	for _, v := range cur.Advisories {
		if !alertable(v.Severity) || known[v.ID] {
			continue
		}
		ids = append(ids, v.ID)
		if severityRank(Severity(v.Severity)) > severityRank(Severity(worst)) {
			worst = v.Severity
		}
	}
	return ids, worst
}

func alertable(sev string) bool { return sev == string(SevHigh) || sev == string(SevCritical) }

// openMCPAlerts opens one alert per published version declaring the server
// and notifies each author once. Returns the number opened.
func (p *Pipeline) openMCPAlerts(ctx context.Context, rec MCPScanRecord, advisoryIDs []string, severity string) (int, error) {
	q := p.st.Queries()
	versions, err := q.ListPublishedVersionsUsingMCPServer(ctx, storegen.ListPublishedVersionsUsingMCPServerParams{
		Ecosystem: rec.Ecosystem, Package: rec.Package, Version: rec.Version})
	if err != nil {
		return 0, fmt.Errorf("mcp sweep: versions using %s: %w", rec.Ecosystem+":"+rec.Package+"@"+rec.Version, err)
	}
	fixed := fixedVersions(rec, advisoryIDs)
	opened := 0
	for _, v := range versions {
		id, err := uuid.NewV7()
		if err != nil {
			return opened, err
		}
		alert, err := q.OpenMCPDependencyAlert(ctx, storegen.OpenMCPDependencyAlertParams{
			ID: id, VersionID: v.ID, Ecosystem: rec.Ecosystem, Package: rec.Package, PackageVersion: rec.Version,
			Severity: severity, AdvisoryIds: advisoryIDs, FixedIn: fixed,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue // already open for this (version, server)
			}
			return opened, fmt.Errorf("mcp sweep: open alert: %w", err)
		}
		opened++
		p.notifyMCPAlert(ctx, v, rec, alert, advisoryIDs)
	}
	return opened, nil
}

// fixedVersions collects, deduplicated and sorted, the versions the named
// advisories say fix the server.
func fixedVersions(rec MCPScanRecord, advisoryIDs []string) []string {
	seen := map[string]bool{}
	fixed := []string{}
	for _, a := range rec.Advisories {
		for _, id := range advisoryIDs {
			if a.ID != id {
				continue
			}
			for _, f := range a.FixedIn {
				if !seen[f] {
					seen[f] = true
					fixed = append(fixed, f)
				}
			}
		}
	}
	sort.Strings(fixed)
	return fixed
}

// notifyMCPAlert delivers the three §8.7-style notifications for one alert.
func (p *Pipeline) notifyMCPAlert(ctx context.Context, v storegen.AgentVersion, rec MCPScanRecord, alert storegen.McpDependencyAlert, advisoryIDs []string) {
	q := p.st.Queries()
	agent, err := q.GetAgentByID(ctx, v.AgentID)
	if err != nil {
		p.log.Error("mcp sweep: load agent for alert", "version", v.ID, "err", err)
		return
	}
	server := rec.Ecosystem + ":" + rec.Package + "@" + rec.Version
	fixed := alert.FixedIn
	if err := p.aud.Write(ctx, q, audit.Event{
		ActorKind: audit.ActorSystem, Action: audit.ActionAgentDependencyAlert,
		TargetKind: "agent_version", TargetID: v.ID,
		Detail: map[string]any{
			"agent": agent.Namespace + "/" + agent.Name, "version": v.Version, "server": server,
			"severity": alert.Severity, "advisories": advisoryIDs, "alert_id": alert.ID.String(),
		},
	}); err != nil {
		p.log.Error("mcp sweep: audit alert", "version", v.ID, "err", err)
	}
	p.reg.EmitAgentEvent(ctx, v.AgentID, webhook.EventAgentDependencyAlert, map[string]any{
		"agent": agent.Namespace + "/" + agent.Name, "version": v.Version, "server": server,
		"severity": alert.Severity, "advisories": advisoryIDs, "fixedIn": fixed,
	})
	if p.notifier != nil && notify.AllowsEmail(ctx, q, v.SubmittedBy, notify.KindDependencyAlert) {
		u, err := q.GetUserByID(ctx, v.SubmittedBy)
		if err != nil {
			p.log.Error("mcp sweep: load author for alert", "version", v.ID, "err", err)
			return
		}
		if err := p.notifier.MCPDependencyAlert(ctx, notify.MCPDependencyAlertNotice{
			ToEmail: u.Email, Agent: agent.Namespace + "/" + agent.Name, Version: v.Version,
			Server: server, Severity: alert.Severity, Advisories: advisoryIDs, FixedIn: fixed,
			AgentURL: p.registryURL + "/" + agent.Namespace + "/" + agent.Name,
		}); err != nil {
			p.log.Error("mcp sweep: author notification", "version", v.ID, "err", err)
			return
		}
	}
	if err := q.MarkMCPDependencyAlertNotified(ctx, alert.ID); err != nil {
		p.log.Error("mcp sweep: mark alert notified", "alert", alert.ID, "err", err)
	}
}
