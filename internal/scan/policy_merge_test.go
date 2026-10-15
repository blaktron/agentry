package scan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
)

// TestMergeKeepsTheBaselineLicenseFloor: an organization's allowedLicenses
// can only narrow the baseline's. Each case states, without going through
// Merge, whether a submission under the merged policy is refused, and the
// baseline's own refusal is checked to hold under the merge.
func TestMergeKeepsTheBaselineLicenseFloor(t *testing.T) {
	cases := []struct {
		name          string
		baseline, org []string
		license       string
		public        bool
		refused       bool
	}{
		{"disjoint: the org's license", []string{"MIT"}, []string{"Apache-2.0"}, "Apache-2.0", true, true},
		{"disjoint: the baseline's license", []string{"MIT"}, []string{"Apache-2.0"}, "MIT", true, true},
		{"disjoint: a third license", []string{"MIT"}, []string{"Apache-2.0"}, "GPL-3.0-only", true, true},
		{"disjoint: private is out of scope", []string{"MIT"}, []string{"Apache-2.0"}, "Apache-2.0", false, false},
		{"overlap: the shared license", []string{"MIT", "Apache-2.0"}, []string{"Apache-2.0", "GPL-3.0-only"}, "Apache-2.0", true, false},
		{"overlap: baseline only", []string{"MIT", "Apache-2.0"}, []string{"Apache-2.0", "GPL-3.0-only"}, "MIT", true, true},
		{"overlap: org only", []string{"MIT", "Apache-2.0"}, []string{"Apache-2.0", "GPL-3.0-only"}, "GPL-3.0-only", true, true},
		{"same list", []string{"MIT"}, []string{"MIT"}, "MIT", true, false},
		{"case-equivalent: allowed", []string{"MIT"}, []string{"mit"}, "MIT", true, false},
		{"case-equivalent: other refused", []string{"MIT"}, []string{"mit"}, "Apache-2.0", true, true},
		{"expression: both sides allowed", []string{"MIT", "Apache-2.0"}, []string{"MIT", "Apache-2.0"}, "MIT OR Apache-2.0", true, false},
		{"expression: one side narrowed away", []string{"MIT", "Apache-2.0"}, []string{"Apache-2.0"}, "MIT OR Apache-2.0", true, true},
		{"expression: disjoint", []string{"MIT"}, []string{"Apache-2.0"}, "MIT AND Apache-2.0", true, true},
		{"no org list: baseline holds", []string{"MIT"}, nil, "Apache-2.0", true, true},
		{"no org list: baseline allows", []string{"MIT"}, nil, "MIT", true, false},
		{"empty org list: baseline holds", []string{"MIT"}, []string{}, "Apache-2.0", true, true},
		{"no baseline list: org narrows", nil, []string{"Apache-2.0"}, "MIT", true, true},
		{"no baseline list: org allows", nil, []string{"Apache-2.0"}, "Apache-2.0", true, false},
		{"no list anywhere", nil, nil, "GPL-3.0-only", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub := registry.PolicySubmission{Public: tc.public, License: tc.license}
			baseline := Policy{AllowedLicenses: tc.baseline}
			merged := Merge(baseline, Policy{AllowedLicenses: tc.org})
			got := len(CheckSubmissionPolicy(merged, sub)) > 0
			if got != tc.refused {
				t.Fatalf("refused = %v, want %v (merged %+v)", got, tc.refused, merged)
			}
			if len(CheckSubmissionPolicy(baseline, sub)) > 0 && !got {
				t.Fatalf("the merge allowed %q, which the baseline refuses", tc.license)
			}
		})
	}
}

// TestNoCommonLicenseSurvivesTheSnapshot: the merged policy is stored as JSON
// on every scan run and returned by the policy API. An empty intersection
// must come back from that JSON as "no license", never as an absent list.
func TestNoCommonLicenseSurvivesTheSnapshot(t *testing.T) {
	merged := Merge(Policy{AllowedLicenses: []string{"MIT"}}, Policy{AllowedLicenses: []string{"Apache-2.0"}})
	doc, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := ParsePolicy(doc)
	if err != nil {
		t.Fatalf("reload %s: %v", doc, err)
	}
	if !reloaded.NoPublicLicense {
		t.Fatalf("the reloaded policy %s lost noPublicLicense", doc)
	}
	sub := registry.PolicySubmission{Public: true, License: "Apache-2.0"}
	if len(CheckSubmissionPolicy(reloaded, sub)) == 0 {
		t.Fatalf("the reloaded policy %s allowed a public Apache-2.0 publish", doc)
	}
	// A document's own empty list still means any license.
	open, err := ParsePolicy([]byte(`{"allowedLicenses":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(CheckSubmissionPolicy(open, sub)) != 0 {
		t.Fatal(`a document's "allowedLicenses": [] refused a license`)
	}
	// And a document may refuse every public publish itself; the overlay
	// cannot clear it from the baseline.
	if len(CheckSubmissionPolicy(Merge(Policy{NoPublicLicense: true}, Policy{AllowedLicenses: []string{"Apache-2.0"}}), sub)) == 0 {
		t.Fatal("an overlay's allowedLicenses cleared the baseline's noPublicLicense")
	}
}

// TestMergeKeepsEveryReviewCondition: an organization's capability
// condition is added to the baseline's, not dropped for having the same
// rank. Expected merged conditions and gate outcomes are literal.
func TestMergeKeepsEveryReviewCondition(t *testing.T) {
	cases := []struct {
		name, baseline, org string
		want                string // the merged requireHumanReview
		reviewed            map[string]bool
	}{
		{
			name: "disjoint", baseline: `{"whenCapabilities":["exec"]}`, org: `{"whenCapabilities":["network"]}`,
			want:     `{"whenCapabilities":["exec","network"]}`,
			reviewed: map[string]bool{"": false, "exec": true, "network": true, "exec,network": true, "fs-write": false},
		},
		{
			name: "overlapping", baseline: `{"whenCapabilities":["exec","network"]}`, org: `{"whenCapabilities":["network","fs-write"]}`,
			want:     `{"whenCapabilities":["exec","network","fs-write"]}`,
			reviewed: map[string]bool{"": false, "exec": true, "network": true, "fs-write": true, "env": false},
		},
		{
			name: "same", baseline: `{"whenCapabilities":["exec"]}`, org: `{"whenCapabilities":["exec"]}`,
			want:     `{"whenCapabilities":["exec"]}`,
			reviewed: map[string]bool{"": false, "exec": true, "network": false},
		},
		{
			name: "baseline never", baseline: `"never"`, org: `{"whenCapabilities":["network"]}`,
			want:     `{"whenCapabilities":["network"]}`,
			reviewed: map[string]bool{"": false, "network": true, "exec": false},
		},
		{
			name: "org never", baseline: `{"whenCapabilities":["exec"]}`, org: `"never"`,
			want:     `{"whenCapabilities":["exec"]}`,
			reviewed: map[string]bool{"": false, "exec": true, "network": false},
		},
		{
			name: "baseline always", baseline: `"always"`, org: `{"whenCapabilities":["network"]}`,
			want:     `"always"`,
			reviewed: map[string]bool{"": true, "network": true},
		},
		{
			name: "org always", baseline: `{"whenCapabilities":["exec"]}`, org: `"always"`,
			want:     `"always"`,
			reviewed: map[string]bool{"": true, "exec": true},
		},
		{
			name: "both never", baseline: `"never"`, org: `"never"`,
			want:     `"never"`,
			reviewed: map[string]bool{"": false, "exec": false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged := Merge(
				Policy{RequireHumanReview: json.RawMessage(tc.baseline)},
				Policy{RequireHumanReview: json.RawMessage(tc.org)})
			if string(merged.RequireHumanReview) != tc.want {
				t.Fatalf("merged requireHumanReview = %s, want %s", merged.RequireHumanReview, tc.want)
			}
			for declared, wantReview := range tc.reviewed {
				caps := map[string]bool{}
				if declared != "" {
					for _, c := range strings.Split(declared, ",") {
						caps[c] = true
					}
				}
				got := Evaluate(GateInput{Policy: merged, DeclaredCapabilities: caps})
				if (got.Outcome == OutcomeNeedsReview) != wantReview {
					t.Errorf("declared %q: outcome %s (%s), want review=%v", declared, got.Outcome, got.Reason, wantReview)
				}
			}
		})
	}
}

// TestADifferentConditionIsNotALoosening: the policy API accepts an overlay
// whose condition names other capabilities than the baseline's, because the
// merge keeps both; going below the baseline's rank is still refused.
func TestADifferentConditionIsNotALoosening(t *testing.T) {
	exec := Policy{RequireHumanReview: json.RawMessage(`{"whenCapabilities":["exec"]}`)}
	network := Policy{RequireHumanReview: json.RawMessage(`{"whenCapabilities":["network"]}`)}
	if LoosensBaseline(exec, network) {
		t.Fatal("a different capability condition was called a loosening")
	}
	if !LoosensBaseline(exec, Policy{RequireHumanReview: json.RawMessage(`"never"`)}) {
		t.Fatal(`"never" under a capability condition was not called a loosening`)
	}
	if !LoosensBaseline(Policy{RequireHumanReview: json.RawMessage(`"always"`)}, network) {
		t.Fatal(`a capability condition under "always" was not called a loosening`)
	}
}
