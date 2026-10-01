package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Dependency alerts and the scanned-server registry (agentry#177 M3, plan
// agentry-notes/plans/mcp-vuln-scanning.md §6).

// ListUserDependencyAlerts implements GET /user/dependency-alerts: the open
// alerts on published versions the caller submitted, newest first. This is
// what the site's sign-in banner and dashboard read.
func (s *Server) ListUserDependencyAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	rows, err := s.q().ListOpenMCPDependencyAlertsForSubmitter(r.Context(), p.UserID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "dependency alerts: list", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]DependencyAlert, 0, len(rows))
	names := map[uuid.UUID]string{}
	for _, row := range rows {
		name, ok := names[row.AgentID]
		if !ok {
			a, err := s.q().GetAgentByID(r.Context(), row.AgentID)
			if err != nil {
				continue // the agent is gone; the alert is history
			}
			name = a.Namespace + "/" + a.Name
			names[row.AgentID] = name
		}
		out = append(out, dependencyAlertToAPI(name, row.AgentVersion, storegen.McpDependencyAlert{
			ID: row.ID, VersionID: row.VersionID, Ecosystem: row.Ecosystem, Package: row.Package,
			PackageVersion: row.PackageVersion, Severity: row.Severity, AdvisoryIds: row.AdvisoryIds,
			FixedIn: row.FixedIn, CreatedAt: row.CreatedAt,
		}))
	}
	writeJSON(w, http.StatusOK, out)
}

// dependencyAlertsForAgent lists an agent's open alerts for its page.
func (s *Server) dependencyAlertsForAgent(r *http.Request, agentID uuid.UUID, name string) []DependencyAlert {
	rows, err := s.q().ListOpenMCPDependencyAlertsForAgent(r.Context(), agentID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "dependency alerts: agent", "agent", agentID, "err", err)
		return nil
	}
	out := make([]DependencyAlert, 0, len(rows))
	for _, row := range rows {
		out = append(out, dependencyAlertToAPI(name, row.AgentVersion, storegen.McpDependencyAlert{
			ID: row.ID, VersionID: row.VersionID, Ecosystem: row.Ecosystem, Package: row.Package,
			PackageVersion: row.PackageVersion, Severity: row.Severity, AdvisoryIds: row.AdvisoryIds,
			FixedIn: row.FixedIn, CreatedAt: row.CreatedAt,
		}))
	}
	return out
}

func dependencyAlertToAPI(agent, version string, a storegen.McpDependencyAlert) DependencyAlert {
	ids := a.AdvisoryIds
	if ids == nil {
		ids = []string{}
	}
	fixed := a.FixedIn
	if fixed == nil {
		fixed = []string{}
	}
	return DependencyAlert{
		Id: a.ID, Agent: agent, Version: version,
		Ecosystem: DependencyAlertEcosystem(a.Ecosystem), Package: a.Package, PackageVersion: a.PackageVersion,
		Severity: DependencyAlertSeverity(a.Severity), AdvisoryIds: ids, FixedIn: fixed, CreatedAt: a.CreatedAt,
	}
}

// GetMcpServerScan implements GET /mcp-servers/scan: the registry's last
// check of one package version. Public: a consumer deciding whether to
// install, and the runner before it installs, both need it.
func (s *Server) GetMcpServerScan(w http.ResponseWriter, r *http.Request, params GetMcpServerScanParams) {
	if !s.authorize(w, r, auth.ActPublicRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	row, err := s.q().GetMCPServerScan(r.Context(), storegen.GetMCPServerScanParams{
		Ecosystem: string(params.Ecosystem), Package: params.Package, Version: params.Version,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, r, http.StatusNotFound, "not-found", "Not found", "No manifest has declared this MCP server version yet.")
			return
		}
		s.log.ErrorContext(r.Context(), "mcp server scan: get", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, mcpServerScanToAPI(row))
}

func mcpServerScanToAPI(row storegen.McpServerScan) McpServerScan {
	out := McpServerScan{
		Ecosystem: McpServerScanEcosystem(row.Ecosystem), Package: row.Package, Version: row.Version,
		Status: McpServerScanStatus(row.Status), FirstSeenAt: row.FirstSeenAt, LastCheckedAt: row.LastCheckedAt,
		Advisories: []McpAdvisory{},
	}
	if row.MaxSeverity != nil {
		sev := McpServerScanMaxSeverity(*row.MaxSeverity)
		out.MaxSeverity = &sev
	}
	out.LastError = row.LastError
	var advs []scan.OSVVulnerability
	_ = json.Unmarshal(row.Advisories, &advs)
	for _, v := range advs {
		a := McpAdvisory{Id: v.ID, Severity: McpAdvisorySeverity(v.Severity),
			GateSeverity: McpAdvisoryGateSeverity(scan.AdvisoryGateSeverity(v)), CvssScore: v.CVSSScore, Summary: v.Summary}
		if len(v.Aliases) > 0 {
			al := v.Aliases
			a.Aliases = &al
		}
		if len(v.FixedIn) > 0 {
			f := v.FixedIn
			a.FixedIn = &f
		}
		if len(v.References) > 0 {
			refs := v.References
			a.References = &refs
		}
		out.Advisories = append(out.Advisories, a)
	}
	return out
}
