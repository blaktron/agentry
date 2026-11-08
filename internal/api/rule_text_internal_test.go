package api

import (
	"testing"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// TestAFindingCarriesItsRulesText: a finding a bundle rule raised carries the
// rule's description and references in the report; one no bundle rule raised
// (a stage's own check) carries none, and nothing about the finding itself
// changes.
func TestAFindingCarriesItsRulesText(t *testing.T) {
	rule, ok := bundleRuleOf("S4/instruction-override-001")
	if !ok || rule.Description == "" {
		t.Fatalf("the embedded bundle does not hold instruction-override-001: %+v", rule)
	}
	f := findingToAPI(storegen.Finding{Scanner: "S4/instruction-override-001", Severity: "high", Confidence: "high", Title: "t", Verdict: "open"})
	if f.Description == nil || *f.Description != rule.Description {
		t.Fatalf("description = %v, want the rule's", f.Description)
	}
	if len(rule.References) > 0 && (f.References == nil || len(*f.References) != len(rule.References)) {
		t.Fatalf("references = %v, want %v", f.References, rule.References)
	}
	if f.Remediation != nil {
		t.Fatalf("remediation = %q for a rule that gives none", *f.Remediation)
	}
	if f.Scanner != "S4/instruction-override-001" || f.Severity != "high" || f.Title != "t" {
		t.Fatalf("the finding itself changed: %+v", f)
	}

	for _, scanner := range []string{"S1", "S2/gitleaks", "S4/no-such-rule", "S5/judge"} {
		g := findingToAPI(storegen.Finding{Scanner: scanner, Severity: "medium", Confidence: "high", Title: "t", Verdict: "open"})
		if g.Description != nil || g.References != nil || g.Remediation != nil {
			t.Fatalf("%s carries rule text: %+v", scanner, g)
		}
	}
}
