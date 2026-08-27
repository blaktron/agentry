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

// ListAbuseReports implements GET /platform/abuse-reports (staff only).
func (s *Server) ListAbuseReports(w http.ResponseWriter, r *http.Request, params ListAbuseReportsParams) {
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "")
		return
	}
	if !p.PlatformStaff {
		problemForbidden(w, r, "abuse triage is staff-only")
		return
	}
	limit := int32(50)
	if params.Limit != nil {
		limit = int32(*params.Limit)
	}
	rows, err := s.q().ListOpenAbuseReports(r.Context(), limit)
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
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}
