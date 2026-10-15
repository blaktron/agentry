package scan

// Outcome is the gate decision.
type Outcome string

// Gate outcomes map onto registry state-machine targets.
const (
	OutcomePublish     Outcome = "published"
	OutcomeNeedsReview Outcome = "needs_review"
	OutcomeRejected    Outcome = "rejected"
)

// GateInput is what the gate decides on.
type GateInput struct {
	// Findings are the open (post-dedup, non-dismissed) findings.
	Findings []Finding
	// Policy is the effective (merged) policy.
	Policy Policy
	// JudgeForcesReview is true when the judge provider requires human
	// review regardless of scores (the `none` provider) or a stage
	// failed closed.
	JudgeForcesReview bool
	// DeclaredCapabilities are the manifest's declared capability tokens
	// (for policy whenCapabilities and wildcard-egress checks).
	DeclaredCapabilities map[string]bool
	// WildcardEgress is true when the manifest asks for the network
	// without naming where: "*" egress, or a browser
	// whose scope is any public site (unrestrictedNetwork).
	WildcardEgress bool
	// Public marks a public agent (platform review queue for high).
	Public bool
	// NamespaceIsOrg marks an agent in an ORG namespace. Only those have an
	// org queue and an org security_reviewer to staff it; a personal-namespace
	// agent routed to "org" produces a review item with no org, which no
	// listing shows and no principal can decide.
	NamespaceIsOrg bool
}

// GateDecision is the gate output.
type GateDecision struct {
	Outcome Outcome
	// Reason is a short human-readable explanation.
	Reason string
	// Queue is "platform" or "org" when Outcome is needs_review.
	Queue string
	// WorstSeverity is the worst gating severity considered.
	WorstSeverity Severity
	// branch names the rule that decided, for the gate's published cases
	// (pkg/gatecases): every return in Evaluate names one, and the test
	// fails on a branch no case reaches.
	branch string
}

// The rules of Evaluate, as pkg/gatecases names them.
const (
	branchCritical             = "critical"
	branchWildcardEgressReject = "wildcard-egress-reject"
	branchWildcardEgressReview = "wildcard-egress-review"
	branchForcedReview         = "forced-review"
	branchCouldNotScan         = "could-not-scan"
	branchReviewAlways         = "review-always"
	branchReviewCapability     = "review-capability"
	branchWithinThreshold      = "within-threshold"
	branchOverThreshold        = "over-threshold"
)

// Evaluate applies the gate under the effective policy. Pure
// function: findings + policy → decision. This is the fail-closed heart of
// the pipeline; the property tests pin that nothing reaches Publish that
// shouldn't.
func Evaluate(in GateInput) GateDecision {
	// Worst finding at confidence ≥ medium gates (low-confidence
	// findings never gate alone; they surface to reviewers).
	worst := SevInfo
	var worstFinding *Finding
	for i := range in.Findings {
		f := &in.Findings[i]
		if confidenceRank(f.Confidence) < confidenceRank(ConfMedium) {
			continue
		}
		if severityRank(f.Severity) > severityRank(worst) {
			worst = f.Severity
			worstFinding = f
		}
	}

	// Critical (or S1 structural) ⇒ auto-reject.
	if worst == SevCritical {
		return GateDecision{Outcome: OutcomeRejected, WorstSeverity: worst, branch: branchCritical,
			Reason: "The gate rejected this version for a critical finding (" + titleOf(worstFinding) + ")."}
	}

	// Wildcard egress policy.
	if in.WildcardEgress {
		switch in.Policy.WildcardEgress {
		case "reject":
			return GateDecision{Outcome: OutcomeRejected, WorstSeverity: worst, branch: branchWildcardEgressReject,
				Reason: "Policy refuses unrestricted network access (\"*\" egress or a browser on any public site), so the gate rejected this version."}
		case "review", "":
			return review(in, worst, branchWildcardEgressReview, "This version asks for unrestricted network access (\"*\" egress or a browser on any public site), so the gate sent it to human review.")
		}
	}

	// Judge/stage forced review (fail-closed).
	if in.JudgeForcesReview {
		return review(in, maxSev(worst, SevMedium), branchForcedReview, "No automated judge ran, or a stage failed closed, so the gate sent this version to human review.")
	}

	// Content a stage could not read forces review whatever the threshold
	// (fail toward review): the finding is medium, and a threshold at
	// medium would otherwise publish what no scanner examined.
	if f := couldNotScan(in.Findings); f != nil {
		return review(in, maxSev(worst, SevMedium), branchCouldNotScan, "Part of this version could not be scanned ("+f.Title+"), so the gate sent it to human review.")
	}

	// Policy requireHumanReview.
	if mode, err := parseReviewMode(orNever(in.Policy.RequireHumanReview)); err == nil {
		if mode.always {
			return review(in, worst, branchReviewAlways, "Policy requires human review of every version, so the gate sent this one to a reviewer.")
		}
		for _, c := range mode.whenCapabilities {
			if in.DeclaredCapabilities[c] {
				return review(in, worst, branchReviewCapability, "Policy requires review of the capability "+c+", so the gate sent this version to a reviewer.")
			}
		}
	}

	// Severity table, tightened by maxAutoPublishSeverity. A policy
	// that names no threshold gets the ruleset's baseline (medium):
	// low and medium publish with their findings shown, high goes
	// to a person.
	maxAuto, _ := severityByName(baselineMaxAuto())
	if s, ok := severityByName(in.Policy.MaxAutoPublishSeverity); ok {
		maxAuto = s
	}
	switch {
	case severityRank(worst) <= severityRank(maxAuto):
		return GateDecision{Outcome: OutcomePublish, WorstSeverity: worst, branch: branchWithinThreshold, Reason: "This version's findings are within the auto-publish threshold, so the gate published it."}
	default:
		return review(in, worst, branchOverThreshold, "This version's findings exceed the auto-publish threshold ("+string(worst)+"), so the gate sent it to a reviewer.")
	}
}

// couldNotScanScanners are the findings that say a stage could not read
// part of the package. They keep their
// medium severity and force review as a stage error does. S7/osv-no-data,
// a declared server the advisory scan has no data for, is not one of them:
// a lookup with no answer is reported and publishes.
var couldNotScanScanners = map[string]bool{
	scannerUnreadableFile:                   true,
	scannerTextTruncated:                    true,
	scannerToolError:                        true,
	scannerHistoryError:                     true,
	KnowledgeStageID + "/" + packUnreadText: true,
}

// couldNotScan is the first finding that says content went unread, or nil.
// Confidence does not matter: unread content is a fact, not a guess.
func couldNotScan(findings []Finding) *Finding {
	for i := range findings {
		if couldNotScanScanners[findings[i].Scanner] {
			return &findings[i]
		}
	}
	return nil
}

// review routes a needs_review decision to a queue: the org queue for
// org-namespace agents, the platform queue for everything else — public
// agents with high findings, all T&S matters, and every personal-namespace
// agent, which has no org reviewer to hand it to.
func review(in GateInput, worst Severity, branch, reason string) GateDecision {
	queue := "platform"
	publicHigh := in.Public && severityRank(worst) >= severityRank(SevHigh)
	if in.NamespaceIsOrg && !publicHigh {
		queue = "org"
	}
	return GateDecision{Outcome: OutcomeNeedsReview, WorstSeverity: worst, Reason: reason, Queue: queue, branch: branch}
}

func confidenceRank(c Confidence) int {
	switch c {
	case ConfHigh:
		return 3
	case ConfMedium:
		return 2
	default:
		return 1
	}
}

func maxSev(a, b Severity) Severity {
	if severityRank(a) >= severityRank(b) {
		return a
	}
	return b
}

func titleOf(f *Finding) string {
	if f == nil {
		return ""
	}
	return f.Title
}
