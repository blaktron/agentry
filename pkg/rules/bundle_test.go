package rules

import (
	"os"
	"testing"
)

// rulesDir is the shipped rule bundle at the repo root, relative to this
// package. Tests load it via os.DirFS so they exercise the exact bytes that
// ship as ruleset_releases.
const rulesDir = "rules"

// loadShippedBundle loads the repo-root /rules bundle for tests.
func loadShippedBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := LoadBundle(os.DirFS("../.."), rulesDir)
	if err != nil {
		t.Fatalf("LoadBundle(../../rules): %v", err)
	}
	return b
}

func TestBundleLoads(t *testing.T) {
	b := loadShippedBundle(t)
	if b.Version() != "0.3.2" {
		t.Errorf("version = %q, want 0.3.2", b.Version())
	}
	if len(b.Rules()) == 0 {
		t.Fatal("bundle has no rules")
	}
}

// TestEveryFamilyHasRules asserts the §8.3 S4 families are all present with at
// least two rules each. "destructive" is the seventh: §8.3 names it only via
// S5's C6 category, but the Amazon Q wiper (Appendix A) was plain English that
// no other family matches, and an incident with a documented reproduction in
// the corpus needs a deterministic detector behind it.
func TestEveryFamilyHasRules(t *testing.T) {
	b := loadShippedBundle(t)
	want := []string{
		"instruction-override",
		"exfiltration",
		"tool-coercion",
		"credential-harvest",
		"persistence",
		"obfuscation",
		"destructive",
	}
	counts := map[string]int{}
	for _, r := range b.Rules() {
		counts[r.Family]++
	}
	for _, fam := range want {
		if counts[fam] < 2 {
			t.Errorf("family %q has %d rules, want >=2", fam, counts[fam])
		}
	}
	// No unexpected families.
	allowed := map[string]bool{}
	for _, fam := range want {
		allowed[fam] = true
	}
	for fam := range counts {
		if !allowed[fam] {
			t.Errorf("unexpected family %q", fam)
		}
	}
}

// TestRuleFixtures enforces the §8.3 requirement that every rule ships with
// tests: each match fixture MUST fire that rule and each nonMatch fixture MUST
// NOT. This is the guard that keeps the corpus honest and blocks a rule with
// no precision discipline from landing.
func TestRuleFixtures(t *testing.T) {
	b := loadShippedBundle(t)
	for _, r := range b.Rules() {
		wantID := "S4/" + r.ID
		for _, m := range r.Fixtures.Match {
			ids := b.MatchingRules(m)
			if !contains(ids, wantID) {
				t.Errorf("rule %s: match fixture did not fire %s: %q (fired: %v)", r.ID, wantID, m, ids)
			}
		}
		for _, nm := range r.Fixtures.NonMatch {
			ids := b.MatchingRules(nm)
			if contains(ids, wantID) {
				t.Errorf("rule %s: nonMatch fixture wrongly fired %s: %q", r.ID, wantID, nm)
			}
		}
	}
}

func TestDigestReproducible(t *testing.T) {
	a := loadShippedBundle(t)
	b := loadShippedBundle(t)
	if a.Digest() != b.Digest() {
		t.Errorf("digest not reproducible: %s != %s", a.Digest(), b.Digest())
	}
	if len(a.Digest()) != 64 {
		t.Errorf("digest is not a 32-byte hex sha256: %q", a.Digest())
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
