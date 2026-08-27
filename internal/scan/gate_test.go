package scan

import (
	"encoding/json"
	"testing"
)

func f(sev Severity, conf Confidence) Finding {
	return Finding{Scanner: "Sx/test", Severity: sev, Confidence: conf, Title: string(sev)}
}

func TestGateSeverityTable(t *testing.T) {
	base := DefaultBaseline()
	cases := []struct {
		name string
		in   GateInput
		want Outcome
	}{
		{"clean", GateInput{Policy: base}, OutcomePublish},
		{"info", GateInput{Findings: []Finding{f(SevInfo, ConfHigh)}, Policy: base}, OutcomePublish},
		{"low auto", GateInput{Findings: []Finding{f(SevLow, ConfHigh)}, Policy: base}, OutcomePublish},
		{"medium review", GateInput{Findings: []Finding{f(SevMedium, ConfHigh)}, Policy: base}, OutcomeNeedsReview},
		{"high review", GateInput{Findings: []Finding{f(SevHigh, ConfHigh)}, Policy: base}, OutcomeNeedsReview},
		{"critical reject", GateInput{Findings: []Finding{f(SevCritical, ConfHigh)}, Policy: base}, OutcomeRejected},
		{"low-confidence high does not gate alone",
			GateInput{Findings: []Finding{f(SevHigh, ConfLow)}, Policy: base}, OutcomePublish},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(tc.in)
			if got.Outcome != tc.want {
				t.Fatalf("got %s want %s (%s)", got.Outcome, tc.want, got.Reason)
			}
		})
	}
}

func TestGateJudgeForcesReview(t *testing.T) {
	// A clean scan with the `none` judge (no automated adjudication) must
	// still go to review (§8.4.6 fail-toward-review).
	got := Evaluate(GateInput{Policy: DefaultBaseline(), JudgeForcesReview: true})
	if got.Outcome != OutcomeNeedsReview {
		t.Fatalf("judge-forced review: got %s", got.Outcome)
	}
}

func TestGatePlatformQueueForPublicHigh(t *testing.T) {
	got := Evaluate(GateInput{
		Findings: []Finding{f(SevHigh, ConfHigh)}, Policy: DefaultBaseline(), Public: true,
	})
	if got.Outcome != OutcomeNeedsReview || got.Queue != "platform" {
		t.Fatalf("public high must route to platform queue: %+v", got)
	}
}

func TestGateWildcardEgress(t *testing.T) {
	reject := DefaultBaseline()
	reject.WildcardEgress = "reject"
	if got := Evaluate(GateInput{Policy: reject, WildcardEgress: true}); got.Outcome != OutcomeRejected {
		t.Fatalf("wildcard reject: got %s", got.Outcome)
	}
	review := DefaultBaseline() // default is "review"
	if got := Evaluate(GateInput{Policy: review, WildcardEgress: true}); got.Outcome != OutcomeNeedsReview {
		t.Fatalf("wildcard review: got %s", got.Outcome)
	}
}

func TestGatePolicyRequireReviewWhenCapabilities(t *testing.T) {
	p := DefaultBaseline()
	p.RequireHumanReview = json.RawMessage(`{"whenCapabilities":["network"]}`)
	got := Evaluate(GateInput{
		Policy: p, DeclaredCapabilities: map[string]bool{"network": true},
	})
	if got.Outcome != OutcomeNeedsReview {
		t.Fatalf("network capability must trigger review: %s", got.Reason)
	}
	// Without the capability, a clean scan publishes.
	got = Evaluate(GateInput{Policy: p, DeclaredCapabilities: map[string]bool{}})
	if got.Outcome != OutcomePublish {
		t.Fatalf("no capability, clean scan should publish: %s", got.Reason)
	}
}

// TestPolicyTightenOnly pins §8.6: Merge never loosens the baseline.
func TestPolicyTightenOnly(t *testing.T) {
	baseline := Policy{
		RequireHumanReview:     json.RawMessage(`{"whenCapabilities":["exec"]}`),
		MaxAutoPublishSeverity: "low",
		WildcardEgress:         "review",
	}
	// An org policy that tries to LOOSEN every knob.
	loosen := Policy{
		RequireHumanReview:     json.RawMessage(`"never"`),
		MaxAutoPublishSeverity: "high",
		WildcardEgress:         "review",
	}
	merged := Merge(baseline, loosen)
	// requireHumanReview stays at the baseline's whenCapabilities (not never).
	mode, _ := parseReviewMode(merged.RequireHumanReview)
	if mode.never || len(mode.whenCapabilities) == 0 {
		t.Fatalf("merge loosened requireHumanReview: %s", merged.RequireHumanReview)
	}
	if merged.MaxAutoPublishSeverity != "low" {
		t.Fatalf("merge loosened maxAutoPublishSeverity: %s", merged.MaxAutoPublishSeverity)
	}
	if !LoosensBaseline(baseline, loosen) {
		t.Fatal("LoosensBaseline should flag the loosening attempt")
	}

	// An org policy that tightens is honored.
	tighten := Policy{RequireHumanReview: json.RawMessage(`"always"`), MaxAutoPublishSeverity: "info"}
	merged = Merge(baseline, tighten)
	if mode, _ := parseReviewMode(merged.RequireHumanReview); !mode.always {
		t.Fatalf("merge dropped a tightening: %s", merged.RequireHumanReview)
	}
	if merged.MaxAutoPublishSeverity != "info" {
		t.Fatalf("merge dropped severity tightening: %s", merged.MaxAutoPublishSeverity)
	}
	if LoosensBaseline(baseline, tighten) {
		t.Fatal("LoosensBaseline false-flagged a tightening")
	}
}
