package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	"github.com/PLACEHOLDER_ORG/agentry/internal/scan"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

func findingToAPI(f storegen.Finding) ScanFinding {
	fid := f.ID
	out := ScanFinding{
		Id: &fid, Scanner: f.Scanner,
		Severity: ScanFindingSeverity(f.Severity), Confidence: ScanFindingConfidence(f.Confidence),
		Title: f.Title, Verdict: ScanFindingVerdict(f.Verdict),
	}
	if f.FilePath != nil {
		out.FilePath = f.FilePath
	}
	if f.LineStart != nil {
		ls := int(*f.LineStart)
		out.LineStart = &ls
	}
	if f.LineEnd != nil {
		le := int(*f.LineEnd)
		out.LineEnd = &le
	}
	if f.Excerpt != nil {
		out.Excerpt = f.Excerpt
	}
	if len(f.Detail) > 0 {
		var d map[string]interface{}
		if json.Unmarshal(f.Detail, &d) == nil {
			out.Detail = &d
		}
	}
	return out
}

// GetVersionReport implements GET .../versions/{version}/report (§8, public).
func (s *Server) GetVersionReport(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	_, v, ok := s.versionOrNotFound(w, r, ns, name, version, auth.ActAgentRead)
	if !ok {
		return
	}
	q := s.q()
	run, err := q.LatestScanRunForVersion(r.Context(), v.ID)
	if err != nil {
		// No scan yet (e.g. still submitted): empty report, not an error.
		writeJSON(w, http.StatusOK, ScanReport{VersionStatus: VersionStatus(v.Status), Findings: []ScanFinding{}})
		return
	}
	rows, err := q.ListFindings(r.Context(), run.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	counts := map[string]int{}
	findings := make([]ScanFinding, 0, len(rows))
	for _, f := range rows {
		findings = append(findings, findingToAPI(f))
		counts[f.Severity]++
	}
	rep := ScanReport{
		ScanRunId:     &run.ID,
		VersionStatus: VersionStatus(v.Status),
		ScanStatus:    &run.Status,
		FindingCounts: &counts,
		Findings:      findings,
	}
	if run.ReportDigest != nil {
		rep.ReportDigest = run.ReportDigest
	}
	if run.JudgeModel != nil {
		rep.JudgeModel = run.JudgeModel
	}
	if rs, err := q.GetRulesetBySemver(r.Context(), ""); err == nil {
		_ = rs // ruleset semver comes from the run's release below
	}
	writeJSON(w, http.StatusOK, rep)
}

// GetVersionAttestation implements GET .../versions/{version}/attestation (§8.8).
func (s *Server) GetVersionAttestation(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	_, v, ok := s.versionOrNotFound(w, r, ns, name, version, auth.ActAgentRead)
	if !ok {
		return
	}
	att, err := s.q().GetAttestation(r.Context(), v.ID)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(att.DsseEnvelope)
}

// ListReviewQueue implements GET /review-queue (§8.6).
func (s *Server) ListReviewQueue(w http.ResponseWriter, r *http.Request, params ListReviewQueueParams) {
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "")
		return
	}
	limit := 50
	if params.Limit != nil {
		limit = *params.Limit
	}
	qp := storegen.ListReviewQueueParams{Queue: string(params.Queue), Limit: int32(limit)}

	switch params.Queue {
	case "platform":
		if !p.PlatformStaff {
			problemForbidden(w, r, "platform review queue is staff-only")
			return
		}
	case "org":
		if params.Org == nil {
			problemValidation(w, r, "org required for the org queue")
			return
		}
		orgRow, ok := s.orgOrNotFound(w, r, *params.Org)
		if !ok {
			return
		}
		if !s.isOrgReviewer(p, orgRow.ID) {
			problemForbidden(w, r, "org security_reviewer role required")
			return
		}
		qp.OrgID = &orgRow.ID
	default:
		problemValidation(w, r, "queue must be platform or org")
		return
	}

	rows, err := s.q().ListReviewQueue(r.Context(), qp)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]ReviewItem, 0, len(rows))
	for _, ri := range rows {
		out = append(out, ReviewItem{
			Id: ri.ID, Queue: ReviewItemQueue(ri.Queue), State: ReviewItemState(ri.State),
			Version: ri.Version, Agent: ri.AgentName, Namespace: ri.Namespace,
			CreatedAt: &ri.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// reviewItemAccess loads a review item and authorizes the caller for it.
func (s *Server) reviewItemAccess(w http.ResponseWriter, r *http.Request, id uuid.UUID) (storegen.ReviewItem, bool) {
	ri, err := s.q().GetReviewItem(r.Context(), id)
	if err != nil {
		problemNotFound(w, r)
		return storegen.ReviewItem{}, false
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "")
		return storegen.ReviewItem{}, false
	}
	switch ri.Queue {
	case "platform":
		if !p.PlatformStaff {
			problemForbidden(w, r, "platform review is staff-only")
			return storegen.ReviewItem{}, false
		}
	case "org":
		if ri.OrgID == nil || !s.isOrgReviewer(p, *ri.OrgID) {
			problemForbidden(w, r, "org security_reviewer role required")
			return storegen.ReviewItem{}, false
		}
	}
	return ri, true
}

// GetReviewItem implements GET /review-items/{id}.
func (s *Server) GetReviewItem(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	ri, ok := s.reviewItemAccess(w, r, id)
	if !ok {
		return
	}
	run, err := s.q().LatestScanRunForVersion(r.Context(), ri.VersionID)
	findings := []ScanFinding{}
	if err == nil {
		rows, _ := s.q().ListFindings(r.Context(), run.ID)
		for _, f := range rows {
			findings = append(findings, findingToAPI(f))
		}
	}
	writeJSON(w, http.StatusOK, ReviewBundle{
		Item:     ReviewItem{Id: ri.ID, Queue: ReviewItemQueue(ri.Queue), State: ReviewItemState(ri.State), CreatedAt: &ri.CreatedAt},
		Findings: findings,
	})
}

// DecideReviewItem implements POST /review-items/{id}/decision. Authors can
// never approve their own versions (§12.2, enforced here).
func (s *Server) DecideReviewItem(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	ri, ok := s.reviewItemAccess(w, r, id)
	if !ok {
		return
	}
	if ri.State != "pending" {
		problemConflict(w, r, "review item already decided")
		return
	}
	var req DecideReviewItemJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	rationale := strings.TrimSpace(req.Rationale)
	if rationale == "" {
		problemValidation(w, r, "rationale required")
		return
	}
	p := principalFrom(r.Context())

	// Author-cannot-self-approve (§12.2), at every layer.
	v, err := s.q().GetVersionByID(r.Context(), ri.VersionID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	if v.SubmittedBy == p.UserID {
		problemForbidden(w, r, "authors cannot decide their own versions")
		return
	}

	target := registry.StatusPublished
	newState := "approved"
	if req.Decision == "reject" {
		target = registry.StatusRejected
		newState = "rejected"
	}

	e := auditEvent(r, audit.ActionReviewDecision)
	if ri.OrgID != nil {
		e.OrgID = *ri.OrgID
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.DecideReviewItem(r.Context(), storegen.DecideReviewItemParams{
			ID: ri.ID, State: newState, DecidedBy: &p.UserID, Rationale: &rationale,
		}); err != nil {
			return err
		}
		e.TargetKind, e.TargetID = "review_item", ri.ID
		e.Detail = map[string]any{"decision": req.Decision, "version_id": ri.VersionID.String()}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("review decision", "err", err)
		problemInternal(w, r)
		return
	}
	// Transition after the decision is recorded; sign on approve→published.
	if err := s.pipeline.ApproveOrReject(r.Context(), ri.VersionID, target, rationale); err != nil {
		if errors.Is(err, registry.ErrBadTransition) {
			problemConflict(w, r, err.Error())
			return
		}
		s.log.Error("review transition", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetFindingVerdict implements POST /findings/{id}/verdict (§8.5). Only org
// security_reviewers may accept-risk, and only up to medium.
func (s *Server) SetFindingVerdict(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "")
		return
	}
	f, err := s.q().GetFinding(r.Context(), id)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	// Authorize via the finding's review item.
	run, err := s.q().GetScanRun(r.Context(), f.ScanRunID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	ri, err := s.q().GetPendingReviewItemForVersion(r.Context(), run.VersionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemConflict(w, r, "finding is not under active review")
			return
		}
		problemInternal(w, r)
		return
	}
	if _, ok := s.reviewItemAccess(w, r, ri.ID); !ok {
		return
	}
	var req SetFindingVerdictJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	// accepted_risk only by org reviewers, only ≤ medium (§8.5).
	if req.Verdict == "dismissed_accepted_risk" {
		if scan.SeverityAtLeast(f.Severity, "high") {
			problemForbidden(w, r, "accepted-risk dismissal is limited to severity medium and below")
			return
		}
	}
	e := auditEvent(r, audit.ActionFindingVerdict)
	if ri.OrgID != nil {
		e.OrgID = *ri.OrgID
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.SetFindingVerdict(r.Context(), storegen.SetFindingVerdictParams{
			ID: id, Verdict: string(req.Verdict), VerdictBy: &p.UserID, VerdictReason: &req.Reason,
		}); err != nil {
			return err
		}
		e.TargetKind, e.TargetID = "finding", id
		e.Detail = map[string]any{"verdict": req.Verdict}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// isOrgReviewer reports whether p may act on the org review queue (§12.2:
// security_reviewer or higher).
func (s *Server) isOrgReviewer(p *auth.Principal, orgID uuid.UUID) bool {
	switch p.Role(orgID) {
	case auth.RoleOwner, auth.RoleAdmin, auth.RoleSecurityReviewer:
		return true
	default:
		return false
	}
}
