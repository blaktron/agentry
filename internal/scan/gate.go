package scan

// Outcome is the gate decision (§8.5).
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
	// review regardless of scores (the `none` provider, §8.4.6) or a stage
	// failed closed.
	JudgeForcesReview bool
	// DeclaredCapabilities are the manifest's declared capability tokens
	// (for policy whenCapabilities and wildcard-egress checks).
	DeclaredCapabilities map[string]bool
	// WildcardEgress is true when the manifest declares "*" egress.
	WildcardEgress bool
	// Public marks a public agent (platform review queue for high, §8.6).
	Public bool
	// NamespaceIsOrg marks an agent in an ORG namespace. Only those have an
	// org queue and an org security_reviewer to staff it; a personal-namespace
	// agent routed to "org" produces a review item with no org, which no
	// listing shows and no principal can decide (§8.6).
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
}

// Evaluate applies the §8.5 gate under the effective policy (§8.6). Pure
// function: findings + policy → decision. This is the fail-closed heart of
// the pipeline; the property tests pin that nothing reaches Publish that
// shouldn't.
func Evaluate(in GateInput) GateDecision {
	// Worst finding at confidence ≥ medium gates (§8.5: low-confidence
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

	// Critical (or S1 structural) ⇒ auto-reject (§8.5).
	if worst == SevCritical {
		return GateDecision{Outcome: OutcomeRejected, WorstSeverity: worst,
			Reason: "The gate rejected this version for a critical finding (" + titleOf(worstFinding) + ")."}
	}

	// Wildcard egress policy (§8.6).
	if in.WildcardEgress {
		switch in.Policy.WildcardEgress {
		case "reject":
			return GateDecision{Outcome: OutcomeRejected, WorstSeverity: worst,
				Reason: "Policy refuses wildcard network egress, so the gate rejected this version."}
		case "review", "":
			return review(in, worst, "This version declares wildcard network egress, so the gate sent it to human review.")
		}
	}

	// Judge/stage forced review (§8.4.6, fail-closed).
	if in.JudgeForcesReview {
		return review(in, maxSev(worst, SevMedium), "No automated judge ran, or a stage failed closed, so the gate sent this version to human review.")
	}

	// Content a stage could not read forces review whatever the threshold
	// (§7 fail toward review): the finding is medium, and a threshold at
	// medium would otherwise publish what no scanner examined.
	if f := couldNotScan(in.Findings); f != nil {
		return review(in, maxSev(worst, SevMedium), "Part of this version could not be scanned ("+f.Title+"), so the gate sent it to human review.")
	}

	// Policy requireHumanReview.
	if mode, err := parseReviewMode(orNever(in.Policy.RequireHumanReview)); err == nil {
		if mode.always {
			return review(in, worst, "Policy requires human review of every version, so the gate sent this one to a reviewer.")
		}
		for _, c := range mode.whenCapabilities {
			if in.DeclaredCapabilities[c] {
				return review(in, worst, "Policy requires review of the capability "+c+", so the gate sent this version to a reviewer.")
			}
		}
	}

	// Severity table (§8.5), tightened by maxAutoPublishSeverity.
	maxAuto := SevLow
	if s, ok := severityByName(in.Policy.MaxAutoPublishSeverity); ok {
		maxAuto = s
	}
	switch {
	case severityRank(worst) <= severityRank(maxAuto):
		return GateDecision{Outcome: OutcomePublish, WorstSeverity: worst, Reason: "This version's findings are within the auto-publish threshold, so the gate published it."}
	default:
		return review(in, worst, "This version's findings exceed the auto-publish threshold ("+string(worst)+"), so the gate sent it to a reviewer.")
	}
}

// couldNotScanScanners are the findings that say a stage could not read
// part of the package (D5 of plans/scan-and-run-tweaks.md). They keep their
// medium severity and force review as a stage error does. The advisory
// lookup's failure, S7/osv-error, is not one of them: the operator decided
// that a lookup with no answer is reported and publishes (D3).
var couldNotScanScanners = map[string]bool{
	"S1/unreadable-file":              true,
	scannerTextTruncated:              true,
	"S2/tool-error":                   true,
	"S2/history-error":                true,
	KnowledgeStageID + "/unread-text": true,
}

// couldNotScan is the first open finding that says content went unread, or
// nil. Confidence does not matter: unread content is a fact, not a guess.
func couldNotScan(findings []Finding) *Finding {
	for i := range findings {
		if couldNotScanScanners[findings[i].Scanner] {
			return &findings[i]
		}
	}
	return nil
}

// review routes a needs_review decision to a queue (§8.6): the org queue for
// org-namespace agents, the platform queue for everything else — public
// agents with high findings, all T&S matters, and every personal-namespace
// agent, which has no org reviewer to hand it to.
func review(in GateInput, worst Severity, reason string) GateDecision {
	queue := "platform"
	publicHigh := in.Public && severityRank(worst) >= severityRank(SevHigh)
	if in.NamespaceIsOrg && !publicHigh {
		queue = "org"
	}
	return GateDecision{Outcome: OutcomeNeedsReview, WorstSeverity: worst, Reason: reason, Queue: queue}
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
