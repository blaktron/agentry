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
		{"medium auto", GateInput{Findings: []Finding{f(SevMedium, ConfHigh)}, Policy: base}, OutcomePublish},
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

// TestBaselinePublishesOnMedium pins ruleset 0.3.0 (agentry#773, D8 of plan
// scan-and-run-tweaks): the baseline's threshold is medium and comes from the
// ruleset, and every reader of an empty threshold uses it.
func TestBaselinePublishesOnMedium(t *testing.T) {
	if got := DefaultBaseline().MaxAutoPublishSeverity; got != "medium" {
		t.Fatalf("DefaultBaseline threshold = %q, want medium", got)
	}
	medium := []Finding{f(SevMedium, ConfHigh)}
	// A policy that names no threshold gets the baseline's.
	if got := Evaluate(GateInput{Findings: medium, Policy: Policy{}}); got.Outcome != OutcomePublish {
		t.Fatalf("a policy with no threshold held a medium: %s (%s)", got.Outcome, got.Reason)
	}
	// A baseline that names none merges as medium, so an org at medium is
	// not a loosening and an org at high is.
	if LoosensBaseline(Policy{}, Policy{MaxAutoPublishSeverity: "medium"}) {
		t.Fatal("an org at medium was called a loosening of the baseline")
	}
	if !LoosensBaseline(Policy{}, Policy{MaxAutoPublishSeverity: "high"}) {
		t.Fatal("an org at high was not called a loosening of the baseline")
	}
	if got := Merge(Policy{}, Policy{MaxAutoPublishSeverity: "high"}).MaxAutoPublishSeverity; got == "high" {
		t.Fatal("merge let an org publish on high")
	}
}

// TestAnOrgAtLowStillHoldsMedium pins invariant 3 of plan scan-and-run-tweaks:
// an organization that wants medium held writes maxAutoPublishSeverity low,
// and the gate holds medium for it while the platform publishes it.
func TestAnOrgAtLowStillHoldsMedium(t *testing.T) {
	merged := Merge(DefaultBaseline(), Policy{MaxAutoPublishSeverity: "low"})
	if merged.MaxAutoPublishSeverity != "low" {
		t.Fatalf("merged threshold = %q, want the org's low", merged.MaxAutoPublishSeverity)
	}
	if LoosensBaseline(DefaultBaseline(), Policy{MaxAutoPublishSeverity: "low"}) {
		t.Fatal("an org at low was called a loosening")
	}
	medium := []Finding{f(SevMedium, ConfHigh)}
	if got := Evaluate(GateInput{Findings: medium, Policy: merged}); got.Outcome != OutcomeNeedsReview {
		t.Fatalf("the org at low published a medium: %s (%s)", got.Outcome, got.Reason)
	}
	low := []Finding{f(SevLow, ConfHigh)}
	if got := Evaluate(GateInput{Findings: low, Policy: merged}); got.Outcome != OutcomePublish {
		t.Fatalf("the org at low held a low: %s (%s)", got.Outcome, got.Reason)
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

// TestGateHoldsWhatCouldNotBeScanned pins D5 of plan scan-and-run-tweaks
// (agentry#771): content a stage could not read reaches a person whatever
// the threshold, so raising the baseline to medium cannot publish it. The
// advisory lookup's failure is the operator's one exception (D3).
func TestGateHoldsWhatCouldNotBeScanned(t *testing.T) {
	atMedium := DefaultBaseline()
	atMedium.MaxAutoPublishSeverity = "medium"
	for _, scanner := range []string{
		"S1/unreadable-file", "S1/text-scan-truncated", "S2/tool-error",
		"S2/history-error", "SK/unread-text",
	} {
		t.Run(scanner, func(t *testing.T) {
			finding := Finding{Scanner: scanner, Severity: SevMedium, Confidence: ConfHigh, Title: "unread"}
			got := Evaluate(GateInput{Findings: []Finding{finding}, Policy: atMedium})
			if got.Outcome != OutcomeNeedsReview {
				t.Fatalf("got %s (%s), want needs_review", got.Outcome, got.Reason)
			}
		})
	}
	t.Run("S7/osv-no-data publishes at medium", func(t *testing.T) {
		finding := Finding{Scanner: scannerOSVNoData, Severity: SevMedium, Confidence: ConfHigh, Title: "lookup failed"}
		if got := Evaluate(GateInput{Findings: []Finding{finding}, Policy: atMedium}); got.Outcome != OutcomePublish {
			t.Fatalf("got %s (%s), want published", got.Outcome, got.Reason)
		}
	})
}

// TestVerdictFindingsRateInjectionAndUndeclaredCapabilityHighFromProbable
// pins D16 (agentry#771): the two classes the operator keeps in front of a
// person are high at score 2; the other four axes stay medium there.
func TestVerdictFindingsRateInjectionAndUndeclaredCapabilityHighFromProbable(t *testing.T) {
	scores := map[JudgeCategory]int{}
	for _, c := range AllJudgeCategories() {
		scores[c] = 2
	}
	got := map[string]Severity{}
	for _, f := range verdictFindings(JudgeVerdict{Scores: scores}) {
		got[f.Scanner] = f.Severity
	}
	want := map[string]Severity{
		"S5/" + string(CatInjection): SevHigh, "S5/" + string(CatUndeclaredCap): SevHigh,
		"S5/" + string(CatExfiltration): SevMedium, "S5/" + string(CatDeception): SevMedium,
		"S5/" + string(CatObfuscation): SevMedium, "S5/" + string(CatDestructive): SevMedium,
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("%s at score 2 = %q, want %q", id, got[id], sev)
		}
	}
}
