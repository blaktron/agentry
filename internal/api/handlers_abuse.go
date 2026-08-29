package api

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// Abuse reporting (§8.7 intake). Reports are authed and rate-limited so the
// queue cannot be flooded, and they land in the platform triage queue rather
// than taking automatic action — a report is a signal, not a verdict.

// maxReportsPerHour bounds one reporter's submissions (§9.2 rate-limited).
const maxReportsPerHour = 10

// ReportAbuse implements POST /agents/{ns}/{name}/abuse-reports.
func (s *Server) ReportAbuse(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "reporting requires an account so we can follow up")
		return
	}
	// Public agents are reportable by anyone signed in; private ones only by
	// someone who can see them.
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return
	}

	var req ReportAbuseJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	detail := strings.TrimSpace(req.Detail)
	if len(detail) < 10 || len(detail) > 4000 {
		problemValidation(w, r, "detail must be 10-4000 characters — tell us what you observed")
		return
	}

	recent, err := s.q().CountRecentAbuseReportsByReporter(r.Context(), &p.UserID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	if recent >= maxReportsPerHour {
		problemTooMany(w, r, "too many reports in the last hour")
		return
	}

	var versionID *uuid.UUID
	if req.Version != nil && *req.Version != "" {
		v, err := s.q().GetVersion(r.Context(), storegen.GetVersionParams{AgentID: a.ID, Version: *req.Version})
		if err != nil {
			problemValidation(w, r, "unknown version")
			return
		}
		versionID = &v.ID
	}

	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.CreateAbuseReport(r.Context(), storegen.CreateAbuseReportParams{
			ID: newUUID(), AgentID: a.ID, VersionID: versionID,
			ReporterID: &p.UserID, Category: string(req.Category), Detail: detail,
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionAbuseReport)
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{"category": string(req.Category)}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("abuse report", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// requireStaff authorizes the caller as signed-in platform staff.
func (s *Server) requireStaff(w http.ResponseWriter, r *http.Request) bool {
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "")
		return false
	}
	if !p.PlatformStaff {
		problemForbidden(w, r, "this action is platform-staff only")
		return false
	}
	return true
}

// ListAbuseReports implements GET /platform/abuse-reports (staff only).
func (s *Server) ListAbuseReports(w http.ResponseWriter, r *http.Request, params ListAbuseReportsParams) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireStaff(w, r) {
		return
	}
	limit := int32(clampLimit(params.Limit, 50, 200))
	state := "open"
	if params.State != nil {
		state = string(*params.State)
	}
	rows, err := s.q().ListAbuseReports(r.Context(), storegen.ListAbuseReportsParams{State: state, Limit: limit})
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]AbuseReport, 0, len(rows))
	for _, row := range rows {
		item := AbuseReport{
			Id: row.ID, Namespace: row.Namespace, Agent: row.AgentName,
			Category: row.Category, Detail: row.Detail,
			State: AbuseReportState(row.State), CreatedAt: row.CreatedAt,
		}
		if row.Version != nil {
			item.Version = row.Version
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

// TriageAbuseReport implements POST /platform/abuse-reports/{id} (staff only).
// Recording a triage outcome is bookkeeping — enforcement actions go through
// the §7 platform agent actions so their audit trail names the agent.
func (s *Server) TriageAbuseReport(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireStaff(w, r) {
		return
	}
	rep, err := s.q().GetAbuseReport(r.Context(), id)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	var req TriageAbuseReportJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	resolution := strings.TrimSpace(req.Resolution)
	if resolution == "" {
		problemValidation(w, r, "resolution required — say what was decided and why")
		return
	}
	p := principalFrom(r.Context())
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.TriageAbuseReport(r.Context(), storegen.TriageAbuseReportParams{
			ID: rep.ID, State: string(req.State), TriagedBy: &p.UserID, Resolution: &resolution,
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionAbuseTriage)
		e.TargetKind, e.TargetID = "abuse_report", rep.ID
		e.Detail = map[string]any{"state": string(req.State)}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("abuse triage", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
