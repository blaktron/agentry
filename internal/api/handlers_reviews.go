package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
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
	// §8.5: dismissals "stay on the public report with rationale". Without
	// the rationale a dismissed finding reads as an unexplained disappearance,
	// which is the opposite of the honesty the report is for.
	if f.VerdictReason != nil && *f.VerdictReason != "" {
		out.VerdictReason = f.VerdictReason
	}
	return out
}

// scanReportFrom assembles the public report for one scan run.
func (s *Server) scanReportFrom(r *http.Request, run storegen.ScanRun, versionStatus string) (ScanReport, error) {
	q := s.q()
	rows, err := q.ListFindings(r.Context(), run.ID)
	if err != nil {
		return ScanReport{}, err
	}
	counts := map[string]int{}
	findings := make([]ScanFinding, 0, len(rows))
	for _, f := range rows {
		findings = append(findings, findingToAPI(f))
		counts[f.Severity]++
	}
	rep := ScanReport{
		ScanRunId:     &run.ID,
		VersionStatus: VersionStatus(versionStatus),
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
	// What the review cost is the platform's measurement, not part of the
	// public verdict: staff read it, everyone else sees the same report as
	// before (plan subscription-tiers §10).
	if p := principalFrom(r.Context()); p != nil && p.PlatformStaff &&
		run.JudgePromptTokens != nil && run.JudgeCompletionTokens != nil {
		rep.JudgeUsage = &JudgeUsage{
			PromptTokens:     int(*run.JudgePromptTokens),
			CompletionTokens: int(*run.JudgeCompletionTokens),
		}
	}
	if run.FinishedAt != nil {
		rep.FinishedAt = run.FinishedAt
	}
	if scanRunStandsBehindReport(run.Status) {
		scanned := Scanned
		rep.Verdict = &scanned
	}
	if rs, err := q.GetRulesetByID(r.Context(), run.RulesetReleaseID); err == nil {
		rep.RulesetVersion = &rs.Semver
	}
	return rep, nil
}

// scanRunStandsBehindReport reports whether a run's status lets a report
// call the version scanned: a run that passed, or found things, stands
// behind it, and the findings say the rest. A run still going has no
// verdict yet, and one that errored is not called scanned — that would be
// "scanned with a known gap" wearing the clean word; its scanStatus says
// error and the gate has sent the version to review. One rule for the
// version's report and for the account install list (agentry#448).
func scanRunStandsBehindReport(status string) bool {
	return status == "passed" || status == "findings"
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
	if v.ScanStatus == registry.ScanStatusSkipped {
		// Admitted without a scan (M21): no run, no findings, no
		// attestation, and the report says so as its own verdict —
		// never an empty report a reader could take for a clean one.
		skipped, unscanned := registry.ScanStatusSkipped, Unscanned
		writeJSON(w, http.StatusOK, ScanReport{VersionStatus: VersionStatus(v.Status), ScanStatus: &skipped, Verdict: &unscanned, Findings: []ScanFinding{}})
		return
	}
	run, err := s.q().LatestScanRunForVersion(r.Context(), v.ID)
	if err != nil {
		// No scan yet (still submitted, say) is a legitimately empty report.
		// A database failure is NOT, and answering 200-with-no-findings to
		// both told the reader "nothing was found" when the truth was "we
		// could not look" — the exact claim §1.6.3 forbids.
		if !errors.Is(err, pgx.ErrNoRows) {
			s.log.ErrorContext(r.Context(), "version report: load scan run", "version", v.ID, "err", err)
			problemInternal(w, r)
			return
		}
		writeJSON(w, http.StatusOK, ScanReport{VersionStatus: VersionStatus(v.Status), Findings: []ScanFinding{}})
		return
	}
	rep, err := s.scanReportFrom(r, run, v.Status)
	if err != nil {
		s.log.ErrorContext(r.Context(), "version report: findings", "run", run.ID, "err", err)
		problemInternal(w, r)
		return
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
	// Not immutable: a rotation countersigns the envelope with the new key
	// (agentry#350), and a cache that kept the old bytes for a year would
	// keep serving an envelope a fresh client cannot verify. The statement
	// inside never changes; the signature list grows.
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(att.DsseEnvelope)
}

// ListReviewQueue implements GET /review-queue (§8.6).
func (s *Server) ListReviewQueue(w http.ResponseWriter, r *http.Request, params ListReviewQueueParams) {
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "This request carried no valid session or token. Sign in and retry.")
		return
	}
	limit := clampLimit(params.Limit, 50, 100)
	qp := storegen.ListReviewQueueParams{Queue: string(params.Queue), Limit: int32(limit)}

	switch params.Queue {
	case "platform":
		if !p.PlatformStaff {
			problemForbidden(w, r, "The platform review queue is open to platform staff only.")
			return
		}
	case "org":
		if params.Org == nil {
			problemValidation(w, r, "Name the organization for the org queue.")
			return
		}
		orgRow, ok := s.orgOrNotFound(w, r, *params.Org)
		if !ok {
			return
		}
		if !s.isOrgReviewer(p, orgRow.ID) {
			problemForbidden(w, r, "The org queue needs the organization's security_reviewer role or higher.")
			return
		}
		qp.OrgID = &orgRow.ID
	default:
		problemValidation(w, r, "The queue must be platform or org.")
		return
	}

	rows, err := s.q().ListReviewQueue(r.Context(), qp)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]ReviewItem, 0, len(rows))
	for _, ri := range rows {
		vs := VersionStatus(ri.VersionStatus)
		out = append(out, ReviewItem{
			Id: ri.ID, Queue: ReviewItemQueue(ri.Queue), State: ReviewItemState(ri.State),
			Version: ri.Version, VersionStatus: &vs, Agent: ri.AgentName, Namespace: ri.Namespace,
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
		problemUnauthorized(w, r, "This request carried no valid session or token. Sign in and retry.")
		return storegen.ReviewItem{}, false
	}
	switch ri.Queue {
	case "platform":
		if !p.PlatformStaff {
			problemForbidden(w, r, "Platform review items are open to platform staff only.")
			return storegen.ReviewItem{}, false
		}
	case "org":
		if ri.OrgID == nil || !s.isOrgReviewer(p, *ri.OrgID) {
			problemForbidden(w, r, "This review item needs the organization's security_reviewer role or higher.")
			return storegen.ReviewItem{}, false
		}
	default:
		// A queue this code does not know is nobody's to read: the DDL's
		// CHECK names the two queues today, and this switch does not lean
		// on it staying that way (agentry#413).
		s.log.WarnContext(r.Context(), "review item of an unknown queue", "item", ri.ID, "queue", ri.Queue)
		problemForbidden(w, r, "This review item belongs to a queue this server does not serve.")
		return storegen.ReviewItem{}, false
	}
	return ri, true
}

// GetReviewItem implements GET /review-items/{id}. The bundle carries
// everything the §10.1 reviewer detail renders in one call: the findings,
// the submitted manifest and capabilities, and the previous published
// version as the capability-diff baseline.
func (s *Server) GetReviewItem(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	if _, ok := s.reviewItemAccess(w, r, id); !ok {
		return
	}
	q := s.q()
	ri, err := q.GetReviewItemDetail(r.Context(), id)
	if err != nil {
		problemInternal(w, r)
		return
	}
	vs := VersionStatus(ri.VersionStatus)
	bundle := ReviewBundle{
		Item: ReviewItem{
			Id: ri.ID, Queue: ReviewItemQueue(ri.Queue), State: ReviewItemState(ri.State),
			Namespace: ri.Namespace, Agent: ri.AgentName, Version: ri.Version, VersionStatus: &vs,
			CreatedAt: &ri.CreatedAt,
		},
		Findings: []ScanFinding{},
	}

	v, err := q.GetVersionByID(r.Context(), ri.VersionID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	vd := versionToAPI(v)
	bundle.VersionDetail = &vd
	if len(v.Manifest) > 0 {
		var m map[string]interface{}
		if json.Unmarshal(v.Manifest, &m) == nil {
			bundle.Manifest = &m
		}
	}
	if prev, err := q.GetPreviousPublishedVersion(r.Context(), storegen.GetPreviousPublishedVersionParams{
		AgentID: v.AgentID, ID: v.ID,
	}); err == nil {
		pd := versionToAPI(prev)
		bundle.Previous = &pd
	}

	run, err := q.LatestScanRunForVersion(r.Context(), ri.VersionID)
	switch {
	case err == nil:
		// A reviewer deciding on a partial finding list would be deciding on
		// the wrong evidence, so a findings error fails the request rather
		// than quietly rendering an empty list.
		rep, rerr := s.scanReportFrom(r, run, v.Status)
		if rerr != nil {
			s.log.ErrorContext(r.Context(), "review bundle: findings", "run", run.ID, "err", rerr)
			problemInternal(w, r)
			return
		}
		bundle.Findings = rep.Findings
		bundle.Report = &rep
	case errors.Is(err, pgx.ErrNoRows):
		// No run yet; the bundle carries the manifest and diff baseline only.
	default:
		s.log.ErrorContext(r.Context(), "review bundle: load scan run", "item", id, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
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
		problemConflict(w, r, "A reviewer already decided this item.")
		return
	}
	var req DecideReviewItemJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	rationale := strings.TrimSpace(req.Rationale)
	if rationale == "" {
		problemValidation(w, r, "Give a rationale for the decision.")
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
		problemForbidden(w, r, "Authors cannot decide their own versions.")
		return
	}

	// Approving a quarantined version republishes it (§7 quarantined →
	// published: "re-review clears"). Rejecting one cannot go to `rejected` —
	// that edge does not exist and the version is already public — so it
	// yanks instead; blocking stays a T&S console action (DEV-015).
	quarantined := registry.Status(v.Status) == registry.StatusQuarantined
	target := registry.StatusPublished
	newState := "approved"
	if req.Decision == "reject" {
		newState = "rejected"
		target = registry.StatusRejected
		if quarantined {
			target = registry.StatusYanked
		}
	}

	e := auditEvent(r, audit.ActionReviewDecision)
	if ri.OrgID != nil {
		e.OrgID = *ri.OrgID
	}
	// One transaction for the verdict AND the transition: recording them
	// separately let a transient failure leave the item decided with the
	// version still in needs_review, which the "already decided" guard above
	// then made unrecoverable.
	if err := s.pipeline.DecideReview(r.Context(), scan.ReviewDecision{
		ItemID: ri.ID, VersionID: ri.VersionID, Target: target, State: newState,
		Rationale: rationale, DecidedBy: p.UserID, Audit: e,
	}); err != nil {
		if errors.Is(err, registry.ErrBadTransition) {
			problemConflict(w, r, "This version's status changed while the item was open. The decision was not recorded.")
			return
		}
		s.log.ErrorContext(r.Context(), "review decision", "item", ri.ID, "err", err)
		problemInternal(w, r)
		return
	}
	s.notifyReviewDecided(r.Context(), v, string(target), p.Handle, rationale)
	w.WriteHeader(http.StatusNoContent)
}

// notifyReviewDecided tells the version's author what a reviewer decided
// (§8.7 author notification). Best-effort: the decision has already been
// committed, and a mail failure must not turn a successful review into a 500
// the reviewer would retry against an "already decided" item.
func (s *Server) notifyReviewDecided(ctx context.Context, v storegen.AgentVersion, decision, reviewer, rationale string) {
	if s.notifier == nil {
		return
	}
	author, err := s.q().GetUserByID(ctx, v.SubmittedBy)
	if err != nil {
		s.log.ErrorContext(ctx, "review notification: load author", "version", v.ID, "err", err)
		return
	}
	agent, err := s.q().GetAgentByID(ctx, v.AgentID)
	if err != nil {
		s.log.ErrorContext(ctx, "review notification: load agent", "version", v.ID, "err", err)
		return
	}
	if !notify.AllowsEmail(ctx, s.q(), s.log, author.ID, notify.KindReviewDecision) {
		return // unverified address, or the author switched these off (#299, #190)
	}
	if err := s.notifier.ReviewDecided(ctx, notify.ReviewNotice{
		ToEmail:   author.Email,
		Agent:     agent.Namespace + "/" + agent.Name,
		Version:   v.Version,
		Decision:  decision,
		Reviewer:  reviewer,
		Rationale: rationale,
	}); err != nil {
		s.log.ErrorContext(ctx, "review notification", "version", v.ID, "err", err)
	}
}

// SetFindingVerdict implements POST /findings/{id}/verdict (§8.5). Only org
// security_reviewers may accept-risk, and only up to medium.
func (s *Server) SetFindingVerdict(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "This request carried no valid session or token. Sign in and retry.")
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
			problemConflict(w, r, "This finding is not under active review.")
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
			problemForbidden(w, r, "Accepted-risk dismissal covers severity medium and below.")
			return
		}
		// The actor half of §8.5 (DEV-034): on an org-namespace agent the
		// waiver is the org's call. reviewItemAccess admits any platform
		// staff member to a platform-queue item — right for the protective
		// actions (quarantine, block, false-positive) but not for accepting
		// risk on someone else's behalf — so this re-checks the org role
		// regardless of the staff flag. Personal-namespace agents have no org
		// to defer to and keep the platform-queue rule.
		v, err := s.q().GetVersionByID(r.Context(), run.VersionID)
		if err != nil {
			problemInternal(w, r)
			return
		}
		agent, err := s.q().GetAgentByID(r.Context(), v.AgentID)
		if err != nil {
			problemInternal(w, r)
			return
		}
		if agent.NamespaceKind == "org" && !s.isOrgReviewer(p, agent.NamespaceID) {
			problemForbidden(w, r, "On a BriefAgent in an org namespace, only that organization's security reviewers may accept risk.")
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
// security_reviewer or higher). The reviewer role exists only inside a
// first-party organization (D20); in every other organization this is the
// admins alone — accepting risk on the org's agents included (DEV-034 as
// amended by agentry#360).
func (s *Server) isOrgReviewer(p *auth.Principal, orgID uuid.UUID) bool {
	switch p.Role(orgID) {
	case auth.RoleAdmin, auth.RoleSecurityReviewer:
		return true
	default:
		return false
	}
}
