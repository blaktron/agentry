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
			Reason: "critical finding: " + titleOf(worstFinding)}
	}

	// Wildcard egress policy (§8.6).
	if in.WildcardEgress {
		switch in.Policy.WildcardEgress {
		case "reject":
			return GateDecision{Outcome: OutcomeRejected, WorstSeverity: worst,
				Reason: "wildcard network egress rejected by policy"}
		case "review", "":
			return review(in, worst, "wildcard network egress requires review")
		}
	}

	// Judge/stage forced review (§8.4.6, fail-closed).
	if in.JudgeForcesReview {
		return review(in, maxSev(worst, SevMedium), "human review required (no automated judge or a stage failed closed)")
	}

	// Policy requireHumanReview.
	if mode, err := parseReviewMode(orNever(in.Policy.RequireHumanReview)); err == nil {
		if mode.always {
			return review(in, worst, "policy requires human review for all versions")
		}
		for _, c := range mode.whenCapabilities {
			if in.DeclaredCapabilities[c] {
				return review(in, worst, "policy requires review for capability: "+c)
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
		return GateDecision{Outcome: OutcomePublish, WorstSeverity: worst, Reason: "within auto-publish threshold"}
	default:
		return review(in, worst, "findings exceed auto-publish threshold ("+string(worst)+")")
	}
}

func review(in GateInput, worst Severity, reason string) GateDecision {
	queue := "org"
	// Public agents with high findings go to the platform queue (§8.6).
	if in.Public && severityRank(worst) >= severityRank(SevHigh) {
		queue = "platform"
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
