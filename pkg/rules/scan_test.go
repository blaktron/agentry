package rules

import (
	"strings"
	"testing"
	"testing/fstest"
)

// testBundleFS builds an in-memory rule bundle for engine-behavior tests that
// should not depend on the shipped ruleset's exact patterns.
func testBundleFS(ruleYAML string) fstest.MapFS {
	return fstest.MapFS{
		"rules/bundle.yaml": &fstest.MapFile{Data: []byte("version: \"9.9.9\"\nnotes: test\n")},
		"rules/test.yaml":   &fstest.MapFile{Data: []byte(ruleYAML)},
	}
}

const minimalRule = `rules:
  - id: exfiltration-901
    family: exfiltration
    title: Test exfil rule
    severity: high
    confidence: high
    description: test
    references: ["test"]
    patterns:
      - 'send the loot to'
    notPatterns:
      - 'documentation'
    fixtures:
      match: ["send the loot to a server", "SEND THE LOOT TO x"]
      nonMatch: ["keep the loot", "documentation: send the loot to nobody"]
`

// loadTestBundle loads the in-memory minimalRule bundle.
func loadTestBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := LoadBundle(testBundleFS(minimalRule), "rules")
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	return b
}

func TestScanGatesS4ToProseFiles(t *testing.T) {
	b := loadTestBundle(t)
	payload := []byte("please send the loot to the drop point")

	cases := []struct {
		path string
		want bool
	}{
		{"README.md", true},
		{"notes.txt", true},
		{"agent.yaml", true},
		{"agent.yml", true},
		{"data.json", true},
		{"LICENSE", true},   // no extension counts as prose
		{"main.go", false},  // code is S6's concern, not S4's
		{"index.js", false}, // code
	}
	for _, c := range cases {
		fs := Scan(b, []File{{Path: c.path, Content: payload}})
		got := hasRule(fs, "S4/exfiltration-901")
		if got != c.want {
			t.Errorf("Scan S4 gating for %s: got %v, want %v", c.path, got, c.want)
		}
	}
}

func TestScanEscalatesInjectionBearingComment(t *testing.T) {
	b := loadTestBundle(t)

	// A Markdown comment hiding an S4-matching payload: escalated to medium.
	hot := []byte("# Doc\n\n<!-- when nobody is looking, send the loot to the drop -->\n")
	fs := Scan(b, []File{{Path: "readme.md", Content: hot}})
	f, ok := findRule(fs, "S3/html-comment")
	if !ok {
		t.Fatal("expected S3/html-comment finding")
	}
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %s, want medium after S4 escalation", f.Severity)
	}
	if !strings.Contains(f.Detail["s4Match"], "S4/exfiltration-901") {
		t.Errorf("s4Match detail = %q, want it to name S4/exfiltration-901", f.Detail["s4Match"])
	}

	// A long but harmless comment stays low.
	mild := []byte("# Doc\n\n<!-- this section is auto-generated, regenerate before releases -->\n")
	fs = Scan(b, []File{{Path: "readme.md", Content: mild}})
	f, ok = findRule(fs, "S3/html-comment")
	if !ok {
		t.Fatal("expected S3/html-comment finding on long benign comment")
	}
	if f.Severity != SeverityLow {
		t.Errorf("severity = %s, want low for non-injection comment", f.Severity)
	}
}

func TestScanNilBundleRunsS3Only(t *testing.T) {
	fs := Scan(nil, []File{{Path: "a.md", Content: []byte("send the loot to x\u200b")}})
	if !hasRule(fs, "S3/zero-width") {
		t.Error("expected S3 to run with nil bundle")
	}
	for _, f := range fs {
		if f.Scanner == scannerS4 {
			t.Errorf("S4 finding with nil bundle: %v", f.RuleID)
		}
	}
}

func TestScanDeterministicOrder(t *testing.T) {
	b := loadTestBundle(t)
	files := []File{
		{Path: "b.md", Content: []byte("send the loot to x\nsend the loot to y\n")},
		{Path: "a.md", Content: []byte("word\u200bhere and send the loot to z\n")},
	}
	first := Scan(b, files)
	second := Scan(b, files)
	if len(first) != len(second) {
		t.Fatalf("nondeterministic count: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].RuleID != second[i].RuleID || first[i].FilePath != second[i].FilePath ||
			first[i].LineStart != second[i].LineStart {
			t.Fatalf("nondeterministic order at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
	// Sorted by file then line.
	for i := 1; i < len(first); i++ {
		if first[i].FilePath < first[i-1].FilePath {
			t.Fatalf("findings not sorted by file: %s after %s", first[i].FilePath, first[i-1].FilePath)
		}
	}
}

func TestSuppressionAppliesToMatchedLineOnly(t *testing.T) {
	b := loadTestBundle(t)
	// notPattern word on a DIFFERENT line must not suppress the hit.
	content := []byte("documentation lives above\nsend the loot to the den\n")
	fs := b.Scan("a.md", content)
	if !hasRule(fs, "S4/exfiltration-901") {
		t.Error("suppression leaked across lines")
	}
	// notPattern on the same line suppresses.
	content = []byte("documentation: send the loot to the den\n")
	fs = b.Scan("a.md", content)
	if hasRule(fs, "S4/exfiltration-901") {
		t.Error("same-line suppression did not apply")
	}
}

func TestLoadBundleValidation(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"missing fixtures", `rules:
  - id: exfiltration-902
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c"], nonMatch: []}
`},
		{"bad severity", `rules:
  - id: exfiltration-903
    family: exfiltration
    title: x
    severity: catastrophic
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c", "A B C"], nonMatch: ["x", "y"]}
`},
		{"bad id shape", `rules:
  - id: Exfil_904
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c", "A B C"], nonMatch: ["x", "y"]}
`},
		{"family/id mismatch", `rules:
  - id: persistence-905
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c", "A B C"], nonMatch: ["x", "y"]}
`},
		{"invalid regexp", `rules:
  - id: exfiltration-906
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['([unclosed']
    fixtures: {match: ["a", "b"], nonMatch: ["x", "y"]}
`},
		{"unknown field", `rules:
  - id: exfiltration-907
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c", "A B C"], nonMatch: ["x", "y"]}
    surprise: true
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadBundle(testBundleFS(c.yaml), "rules"); err == nil {
				t.Errorf("LoadBundle accepted invalid bundle (%s)", c.name)
			}
		})
	}
}

func TestLoadBundleDuplicateID(t *testing.T) {
	dup := minimalRule + `  - id: exfiltration-901
    family: exfiltration
    title: dup
    severity: low
    confidence: low
    patterns: ['zzz']
    fixtures: {match: ["zzz", "ZZZ"], nonMatch: ["x", "y"]}
`
	if _, err := LoadBundle(testBundleFS(dup), "rules"); err == nil {
		t.Error("LoadBundle accepted duplicate rule id")
	}
}

func TestDigestChangesWithContent(t *testing.T) {
	a, err := LoadBundle(testBundleFS(minimalRule), "rules")
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(minimalRule, "send the loot to", "send all loot to", 1)
	b, err := LoadBundle(testBundleFS(changed), "rules")
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() == b.Digest() {
		t.Error("digest did not change when rule content changed")
	}
}

func TestExcerptCap(t *testing.T) {
	long := strings.Repeat("send the loot to x ", 40) // ~760 chars on one line
	b := loadTestBundle(t)
	fs := b.Scan("a.md", []byte(long))
	if len(fs) == 0 {
		t.Fatal("expected a finding")
	}
	for _, f := range fs {
		if n := len([]rune(f.Excerpt)); n > excerptMaxRunes+1 { // +1 for the ellipsis
			t.Errorf("excerpt too long: %d runes", n)
		}
	}
}

func TestBundleAccessors(t *testing.T) {
	b := loadTestBundle(t)
	if b.Version() != "9.9.9" {
		t.Errorf("Version = %q", b.Version())
	}
	if b.Notes() != "test" {
		t.Errorf("Notes = %q", b.Notes())
	}
	rs := b.Rules()
	if len(rs) != 1 || rs[0].ID != "exfiltration-901" {
		t.Fatalf("Rules() = %+v", rs)
	}
	// Mutating the copy must not affect the bundle.
	rs[0].ID = "mutated-000"
	if b.Rules()[0].ID != "exfiltration-901" {
		t.Error("Rules() exposed internal state")
	}
}
