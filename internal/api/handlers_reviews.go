package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	// Dismissals stay on the public report with rationale. Without
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
	// before.
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
	shipped, err := shippedKnowledgeOf(r.Context(), q, run.ID)
	if err != nil {
		return ScanReport{}, err
	}
	if len(shipped) > 0 {
		rep.Knowledge = &shipped
	}
	return rep, nil
}

// shippedKnowledgeOf is what a run's scan read of the knowledge packs the
// release ships, as the SK stage recorded it:
// none for a release that ships no pack, or a run whose SK has not
// finished.
func shippedKnowledgeOf(ctx context.Context, q *storegen.Queries, runID uuid.UUID) ([]ShippedKnowledgeScan, error) {
	stages, err := q.ListStageResults(ctx, runID)
	if err != nil {
		return nil, err
	}
	for _, st := range stages {
		if st.Scanner != scan.KnowledgeStageID {
			continue
		}
		var rec []ShippedKnowledgeScan
		if err := scan.DecodeKnowledgeRecord(st.Detail, &rec); err != nil {
			return nil, fmt.Errorf("scan report: the knowledge stage's record: %w", err)
		}
		return rec, nil
	}
	return nil, nil
}

// scanRunStandsBehindReport reports whether a run's status lets a report
// call the version scanned: a run that passed, or found things, stands
// behind it, and the findings say the rest. A run still going has no
// verdict yet, and one that errored is not called scanned — that would be
// "scanned with a known gap" wearing the clean word; its scanStatus says
// error and the gate has sent the version to review. One rule for the
// version's report and for the account install list.
func scanRunStandsBehindReport(status string) bool {
	return status == "passed" || status == "findings"
}

// reportRun picks the scan run a version's report describes, and the run
// still going beside it, if any. The report describes the newest run that
// finished, whatever its outcome; a run that is still going only takes
// over the report when no run has finished yet (the first scan). So a
// rescan sweep does not blank the verdict a published release stands on
// for as long as it runs, and a rescan that ends in error still becomes the
// report: an error is never hidden behind the verdict before it. One rule
// for the report and the account install row.
// pgx.ErrNoRows means the version has no run at all.
func reportRun(ctx context.Context, q *storegen.Queries, versionID uuid.UUID) (run storegen.ScanRun, inFlight *storegen.ScanRun, err error) {
	latest, err := q.LatestScanRunForVersion(ctx, versionID)
	if err != nil || latest.FinishedAt != nil {
		return latest, nil, err
	}
	finished, err := q.LatestFinishedScanRunForVersion(ctx, versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return latest, nil, nil
	}
	if err != nil {
		return storegen.ScanRun{}, nil, err
	}
	return finished, &latest, nil
}

// GetVersionReport implements GET .../versions/{version}/report (public).
func (s *Server) GetVersionReport(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	_, v, ok := s.versionOrNotFound(w, r, ns, name, version, auth.ActAgentRead)
	if !ok {
		return
	}
	if v.ScanStatus == registry.ScanStatusSkipped {
		// Admitted without a scan: no run, no findings, no
		// attestation, and the report says so as its own verdict —
		// never an empty report a reader could take for a clean one.
		skipped, unscanned := registry.ScanStatusSkipped, Unscanned
		writeJSON(w, http.StatusOK, ScanReport{VersionStatus: VersionStatus(v.Status), ScanStatus: &skipped, Verdict: &unscanned, Findings: []ScanFinding{}})
		return
	}
	run, inFlight, err := reportRun(r.Context(), s.q(), v.ID)
	if err != nil {
		// No scan yet (still submitted, say) is a legitimately empty report.
		// A database failure is NOT, and answering 200-with-no-findings to
		// both told the reader "nothing was found" when the truth was "we
		// could not look" — a claim the report must never make.
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
	if inFlight != nil {
		rep.RescanInFlight = &RescanInFlight{ScanRunId: inFlight.ID, StartedAt: inFlight.StartedAt}
	}
	writeJSON(w, http.StatusOK, rep)
}

// GetVersionAttestation implements GET .../versions/{version}/attestation.
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
	// Not immutable: a rotation countersigns the envelope with the new key,
	// and a cache that kept the old bytes for a year would
	// keep serving an envelope a fresh client cannot verify. The statement
	// inside never changes; the signature list grows.
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(att.DsseEnvelope)
}

// ListReviewQueue implements GET /review-queue.
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
		// Platform staff may read any organization's queue, or every
		// organization's at once by naming none.
		if params.Org == nil {
			if !p.PlatformStaff {
				problemValidation(w, r, "Name the organization for the org queue.")
				return
			}
			break
		}
		orgRow, ok := s.orgOrNotFound(w, r, *params.Org)
		if !ok {
			return
		}
		if !p.PlatformStaff && !s.isOrgReviewer(p, orgRow.ID) {
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
			Id: ri.ID, Queue: ReviewItemQueue(ri.Queue), State: ri.State,
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
		// Platform staff may review any organization's item.
		if ri.OrgID == nil || (!p.PlatformStaff && !s.isOrgReviewer(p, *ri.OrgID)) {
			problemForbidden(w, r, "This review item needs the organization's security_reviewer role or higher.")
			return storegen.ReviewItem{}, false
		}
	default:
		// A queue this code does not know is nobody's to read: the DDL's
		// CHECK names the two queues today, and this switch does not lean
		// on it staying that way.
		s.log.WarnContext(r.Context(), "review item of an unknown queue", "item", ri.ID, "queue", ri.Queue)
		problemForbidden(w, r, "This review item belongs to a queue this server does not serve.")
		return storegen.ReviewItem{}, false
	}
	return ri, true
}

// GetReviewItem implements GET /review-items/{id}. The bundle carries
// everything the reviewer detail renders in one call: the findings,
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
			Id: ri.ID, Queue: ReviewItemQueue(ri.Queue), State: ri.State,
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

	// The report the reviewer decides on is the latest finished run, as on
	// the version's own report: a new ruleset's redo of the queue rescans a
	// held version, and its run in progress is a partial list.
	run, inFlight, err := reportRun(r.Context(), q, ri.VersionID)
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
		if inFlight != nil {
			rep.RescanInFlight = &RescanInFlight{ScanRunId: inFlight.ID, StartedAt: inFlight.StartedAt}
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

// DecideReviewItem implements POST /review-items/{id}/decision. An author
// cannot decide their own version (enforced here), unless they are
// platform staff: staff may decide any item, and a
// staff decision on their own version is marked in its audit event.
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

	// Author-cannot-self-approve, at every layer, except for
	// platform staff, who publish the built-in packages.
	v, err := s.q().GetVersionByID(r.Context(), ri.VersionID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	selfDecision := v.SubmittedBy == p.UserID
	if selfDecision && !p.PlatformStaff {
		problemForbidden(w, r, "Authors cannot decide their own versions.")
		return
	}

	// Approving a quarantined version republishes it (quarantined →
	// published: "re-review clears"). Rejecting one cannot go to `rejected` —
	// that edge does not exist and the version is already public — so it
	// yanks instead; blocking stays a T&S console action.
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
	// separately could let a transient failure leave the item decided with the
	// version still in needs_review, which the "already decided" guard above
	// would then make unrecoverable.
	handedOff, err := s.pipeline.DecideReview(r.Context(), scan.ReviewDecision{
		ItemID: ri.ID, VersionID: ri.VersionID, Target: target, State: newState,
		Rationale: rationale, DecidedBy: p.UserID, SelfDecision: selfDecision, Audit: e,
	})
	if err != nil {
		switch {
		case errors.Is(err, scan.ErrAlreadyDecided):
			problemConflict(w, r, "A reviewer already decided this item.")
		case errors.Is(err, registry.ErrBadTransition):
			problemConflict(w, r, "This version's status changed while the item was open. The decision was not recorded.")
		default:
			s.log.ErrorContext(r.Context(), "review decision", "item", ri.ID, "err", err)
			problemInternal(w, r)
		}
		return
	}
	// A publish handed to the worker has not happened yet:
	// the author hears that it was approved, not that it is published.
	outcome := string(target)
	if handedOff {
		outcome = "approved"
	}
	s.notifyReviewDecided(r.Context(), v, outcome, p.Handle, rationale)
	w.WriteHeader(http.StatusNoContent)
}

// notifyReviewDecided tells the version's author what a reviewer decided
// (author notification). Best-effort: the decision has already been
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
		return // unverified address, or the author switched these off
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

// SetFindingVerdict implements POST /findings/{id}/verdict. Only org
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
	v, err := s.q().GetVersionByID(r.Context(), run.VersionID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	// The author rule of a decision holds for a verdict too: a dismissal
	// waives a finding, so an author cannot record one on their own
	// version, an organization's admin or security reviewer included.
	// Platform staff keep the decision's exception, marked in the audit
	// event.
	selfVerdict := v.SubmittedBy == p.UserID
	if selfVerdict && !p.PlatformStaff {
		problemForbidden(w, r, "Authors cannot set verdicts on their own versions' findings.")
		return
	}
	// accepted_risk only by org reviewers, only ≤ medium.
	if req.Verdict == "dismissed_accepted_risk" {
		if scan.SeverityAtLeast(f.Severity, "high") {
			problemForbidden(w, r, "Accepted-risk dismissal covers severity medium and below.")
			return
		}
		// The actor half of that rule: on an org-namespace agent the
		// waiver is the org's call. reviewItemAccess admits any platform
		// staff member to any item, an org-queue one included — right for
		// the protective actions (quarantine, block, false-positive) but
		// not for accepting risk on someone else's behalf — so this
		// re-checks the org role regardless of the staff flag.
		// Personal-namespace agents have no org
		// to defer to and keep the platform-queue rule.
		agent, err := s.q().GetAgentByID(r.Context(), v.AgentID)
		if err != nil {
			problemInternal(w, r)
			return
		}
		if agent.NamespaceKind == "org" && !s.isOrgReviewer(p, agent.NamespaceID) {
			problemForbidden(w, r, "On a QuickAgent in an org namespace, only that organization's security reviewers may accept risk.")
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
		if selfVerdict {
			e.Detail["self_decision"] = true
		}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// isOrgReviewer reports whether p may act on the org review queue:
// security_reviewer or higher. The reviewer role exists only inside a
// first-party organization; in every other organization this is the
// admins alone — accepting risk on the org's agents included.
func (s *Server) isOrgReviewer(p *auth.Principal, orgID uuid.UUID) bool {
	switch p.Role(orgID) {
	case auth.RoleAdmin, auth.RoleSecurityReviewer:
		return true
	default:
		return false
	}
}
