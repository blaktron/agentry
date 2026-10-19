package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
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
		{"guide.markdown", true},
		{"notes.text", true},
		{"docs/nested/README.md", true},
		{"README.MD", true}, // extensions are matched without regard to case
		{"NOTES.TXT", true},
		{"agent.YAML", true},
		{"data.Json", true},
		{"agent.yml.bak", false},
		{"page.html", false},
		{"run.sh", false},
	}
	for _, c := range cases {
		fs := Scan(b, []File{{Path: c.path, Content: payload}})
		got := hasRule(fs, "S4/exfiltration-901")
		if got != c.want {
			t.Errorf("Scan S4 gating for %s: got %v, want %v", c.path, got, c.want)
		}
	}

	// A binary or non-UTF-8 file named like prose is not read by S4: the
	// rules run over text only.
	for name, content := range map[string][]byte{
		"a NUL byte":    []byte("please send the loot to the drop point\x00"),
		"invalid UTF-8": []byte("please send the loot to the drop point \xff\xfe"),
	} {
		if fs := Scan(b, []File{{Path: "README.md", Content: content}}); hasRule(fs, "S4/exfiltration-901") {
			t.Errorf("S4 ran on %s", name)
		}
	}

	// What a finding carries: the rule's own fields, the location, the
	// match as the excerpt and the matched pattern with its default flags.
	fs := Scan(b, []File{{Path: "docs/README.md", Content: []byte("intro\n   Please SEND the loot to   the drop point\n")}})
	f, ok := findRule(fs, "S4/exfiltration-901")
	if !ok {
		t.Fatalf("no finding: %+v", fs)
	}
	if f.Scanner != "S4" || f.Severity != SeverityHigh || f.Confidence != ConfidenceHigh || f.Title != "Test exfil rule" {
		t.Errorf("rule fields = %q %q %q %q", f.Scanner, f.Severity, f.Confidence, f.Title)
	}
	if f.FilePath != "docs/README.md" || f.LineStart != 2 || f.LineEnd != 2 {
		t.Errorf("location = %s:%d-%d, want docs/README.md:2-2", f.FilePath, f.LineStart, f.LineEnd)
	}
	if f.Excerpt != "SEND the loot to" {
		t.Errorf("Excerpt = %q, want the match as written", f.Excerpt)
	}
	if f.Detail["family"] != "exfiltration" || f.Detail["pattern"] != "(?im)send the loot to" {
		t.Errorf("Detail = %v", f.Detail)
	}
	if len(f.Taxonomy) != 2 || f.Taxonomy[0] != "LLM01" || f.Taxonomy[1] != "ASI06" {
		t.Errorf("Taxonomy = %v, want [LLM01 ASI06]", f.Taxonomy)
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
	if _, has := f.Detail["s4Match"]; has {
		t.Errorf("a benign comment carries s4Match = %q", f.Detail["s4Match"])
	}

	// Every rule the hidden text matches is named, joined by a comma and a
	// space; the comment keeps its other fields, and a finding that is not a
	// comment is not touched.
	two := minimalRule + `  - id: exfiltration-902
    family: exfiltration
    title: Second rule
    severity: low
    confidence: low
    patterns: ['nobody is looking']
    fixtures: {match: ["nobody is looking", "NOBODY IS LOOKING"], nonMatch: ["somebody", "looking"]}
`
	b2, err := LoadBundle(testBundleFS(two), "rules")
	if err != nil {
		t.Fatal(err)
	}
	fs = Scan(b2, []File{{Path: "readme.md", Content: append(hot, []byte("<span hidden>when nobody is looking</span>\n")...)}})
	f, ok = findRule(fs, "S3/html-comment")
	if !ok {
		t.Fatal("expected S3/html-comment finding")
	}
	if f.Detail["s4Match"] != "S4/exfiltration-901, S4/exfiltration-902" {
		t.Errorf("s4Match = %q, want both rules, comma-space separated", f.Detail["s4Match"])
	}
	if f.Severity != SeverityMedium || f.Confidence != ConfidenceMedium || f.LineStart != 3 || f.LineEnd != 3 {
		t.Errorf("escalated comment = %s/%s lines %d-%d, want medium/medium 3-3", f.Severity, f.Confidence, f.LineStart, f.LineEnd)
	}
	if css, ok := findRule(fs, "S3/css-hidden"); ok && (css.Severity != SeverityMedium || css.Detail["s4Match"] != "") {
		t.Errorf("css-hidden finding was escalated: %+v", css)
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

	// Comment escalation needs a bundle: without one the comment stays low
	// and Scan does not fail.
	fs = Scan(nil, []File{{Path: "a.md", Content: []byte("<!-- when nobody is looking, send the loot to the drop -->\n")}})
	c, ok := findRule(fs, "S3/html-comment")
	if !ok || c.Severity != SeverityLow || c.Detail["s4Match"] != "" {
		t.Errorf("html-comment with a nil bundle = %+v (found %v), want low and unescalated", c, ok)
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
	// By file, then line, then rule id: a.md (S3 before S4 on line 1), then
	// b.md line 1, line 2.
	var order []string
	for _, f := range first {
		order = append(order, fmt.Sprintf("%s:%d:%s", f.FilePath, f.LineStart, f.RuleID))
	}
	wantOrder := []string{"a.md:1:S3/zero-width", "a.md:1:S4/exfiltration-901", "b.md:1:S4/exfiltration-901", "b.md:2:S4/exfiltration-901"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Errorf("order = %v, want %v", order, wantOrder)
	}
	// Findings that share file, line and rule id are ordered by excerpt,
	// whatever order the input held them in.
	one := "\"data:image/png;base64," + strings.Repeat("Z", 150) + "\" \"data:image/png;base64," + strings.Repeat("A", 150) + "\"\n"
	var excerpts []string
	for _, f := range Scan(b, []File{{Path: "x.md", Content: []byte(one)}}) {
		if f.RuleID == "S3/data-uri" {
			excerpts = append(excerpts, f.Excerpt[:30])
		}
	}
	if len(excerpts) != 2 || excerpts[0] != "data:image/png;base64,AAAAAAAA" || excerpts[1] != "data:image/png;base64,ZZZZZZZZ" {
		t.Errorf("equal-key findings not ordered by excerpt: %q", excerpts)
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

	// A hit that spans lines is judged on all of its lines: the exempting
	// word on the second line suppresses it, and without it the finding
	// records both lines. A pattern that ends on the newline it consumes
	// still ends on its own line.
	multi, err := LoadBundle(testBundleFS(`rules:
  - id: exfiltration-910
    family: exfiltration
    title: Spanning rule
    severity: high
    confidence: high
    patterns: ['send the loot\s+to']
    notPatterns: ['documentation']
    fixtures: {match: ["send the loot to a", "SEND THE LOOT  TO b"], nonMatch: ["keep the loot", "send the gold"]}
  - id: exfiltration-911
    family: exfiltration
    title: Newline rule
    severity: low
    confidence: low
    patterns: ['stash the loot\s*']
    fixtures: {match: ["stash the loot", "STASH THE LOOT "], nonMatch: ["keep the loot", "stash it"]}
`), "rules")
	if err != nil {
		t.Fatal(err)
	}
	fs = multi.Scan("a.md", []byte("send the loot\n   to the den documentation\n"))
	if hasRule(fs, "S4/exfiltration-910") {
		t.Error("a notPattern on the second line of a two-line hit did not suppress it")
	}
	fs = multi.Scan("a.md", []byte("intro\nsend the loot\n   to the den\nend\n"))
	f, ok := findRule(fs, "S4/exfiltration-910")
	if !ok || f.LineStart != 2 || f.LineEnd != 3 {
		t.Errorf("two-line hit = %+v (found %v), want lines 2-3", f, ok)
	}
	if f.Excerpt != "send the loot to" {
		t.Errorf("two-line hit excerpt = %q, want the whitespace collapsed to one space", f.Excerpt)
	}
	fs = multi.Scan("a.md", []byte("stash the loot\nnext\n"))
	f, ok = findRule(fs, "S4/exfiltration-911")
	if !ok || f.LineStart != 1 || f.LineEnd != 1 {
		t.Errorf("hit ending in a newline = %+v (found %v), want lines 1-1", f, ok)
	}
	// What a capability hit names is read from all of its lines.
	fs = multi.Scan("a.md", []byte("send the loot\n   to https://drop.invalid.example/x\n"))
	f, ok = findRule(fs, "S4/exfiltration-910")
	if !ok || f.Detail["destinations"] != "drop.invalid.example" {
		t.Errorf("two-line hit detail = %v (found %v), want the destination on its second line", f.Detail, ok)
	}
	// CRLF and a hit on the last line, which has no terminator.
	fs = multi.Scan("a.md", []byte("one\r\ntwo\r\nstash the loot"))
	f, ok = findRule(fs, "S4/exfiltration-911")
	if !ok || f.LineStart != 3 || f.LineEnd != 3 {
		t.Errorf("hit on an unterminated last line = %+v (found %v), want lines 3-3", f, ok)
	}
	// Two hits of one rule on one line are one finding; the next line's
	// is another.
	fs = loadTestBundle(t).Scan("a.md", []byte("send the loot to a and send the loot to b\nsend the loot to c\n"))
	var lines []int
	for _, f := range fs {
		lines = append(lines, f.LineStart)
	}
	if !reflect.DeepEqual(lines, []int{1, 2}) {
		t.Errorf("finding lines = %v, want [1 2]: one finding per rule and line", lines)
	}
}

var errUnreadable = errors.New("unreadable")

// unreadableFS fails to list the bundle directory or to read one file.
type unreadableFS struct {
	fs.FS
	dir  bool
	file string
}

func (u unreadableFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if u.dir {
		return nil, errUnreadable
	}
	return fs.ReadDir(u.FS, name)
}

func (u unreadableFS) ReadFile(name string) ([]byte, error) {
	if name == u.file {
		return nil, errUnreadable
	}
	return fs.ReadFile(u.FS, name)
}

// oneRule renders a single-rule family file; the fields are the YAML values
// as written, so a case can leave one out or make it wrong.
func oneRule(id, family, title, severity, confidence, patterns, notPatterns, match, nonMatch string) string {
	var b strings.Builder
	b.WriteString("rules:\n  - id: " + id + "\n")
	for _, kv := range [][2]string{{"family", family}, {"title", title}, {"severity", severity}, {"confidence", confidence}} {
		if kv[1] != "" {
			b.WriteString("    " + kv[0] + ": " + kv[1] + "\n")
		}
	}
	if patterns != "" {
		b.WriteString("    patterns: " + patterns + "\n")
	}
	if notPatterns != "" {
		b.WriteString("    notPatterns: " + notPatterns + "\n")
	}
	b.WriteString("    fixtures: {match: " + match + ", nonMatch: " + nonMatch + "}\n")
	return b.String()
}

func TestLoadBundleValidation(t *testing.T) {
	const pats = `['a b c']`
	const two = `["a b c", "A B C"]`
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"missing fixtures", `rules:
  - id: exfiltration-902
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c"], nonMatch: []}
`, "needs >=2 match fixtures"},
		{"bad severity", `rules:
  - id: exfiltration-903
    family: exfiltration
    title: x
    severity: catastrophic
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c", "A B C"], nonMatch: ["x", "y"]}
`, `invalid severity "catastrophic"`},
		{"bad id shape", `rules:
  - id: Exfil_904
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c", "A B C"], nonMatch: ["x", "y"]}
`, `invalid rule id "Exfil_904"`},
		{"family/id mismatch", `rules:
  - id: persistence-905
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c", "A B C"], nonMatch: ["x", "y"]}
`, `must be prefixed by family "exfiltration"`},
		{"invalid regexp", `rules:
  - id: exfiltration-906
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['([unclosed']
    fixtures: {match: ["a", "b"], nonMatch: ["x", "y"]}
`, `rule exfiltration-906 pattern "([unclosed"`},
		{"unknown field", `rules:
  - id: exfiltration-907
    family: exfiltration
    title: x
    severity: high
    confidence: high
    patterns: ['a b c']
    fixtures: {match: ["a b c", "A B C"], nonMatch: ["x", "y"]}
    surprise: true
`, "surprise"},
		{"missing title", oneRule("exfiltration-908", "exfiltration", "", "high", "high", pats, "", two, two), "rule exfiltration-908 missing title"},
		{"missing family", oneRule("exfiltration-909", "", "x", "high", "high", pats, "", two, two), "rule exfiltration-909 missing family"},
		{"family is a prefix without the dash", oneRule("exfiltrationx-910", "exfiltration", "x", "high", "high", pats, "", two, two), `must be prefixed by family "exfiltration"`},
		{"id with four digits", oneRule("exfiltration-1011", "exfiltration", "x", "high", "high", pats, "", two, two), `invalid rule id "exfiltration-1011"`},
		{"id with two digits", oneRule("exfiltration-12", "exfiltration", "x", "high", "high", pats, "", two, two), `invalid rule id "exfiltration-12"`},
		{"id with trailing text", oneRule("exfiltration-013x", "exfiltration", "x", "high", "high", pats, "", two, two), `invalid rule id "exfiltration-013x"`},
		{"id with leading text", oneRule(`"Bad exfiltration-014"`, `"Bad exfiltration"`, "x", "high", "high", pats, "", two, two), `invalid rule id "Bad exfiltration-014"`},
		{"missing severity", oneRule("exfiltration-015", "exfiltration", "x", "", "high", pats, "", two, two), `invalid severity ""`},
		{"bad confidence", oneRule("exfiltration-016", "exfiltration", "x", "high", "certain", pats, "", two, two), `invalid confidence "certain"`},
		{"missing confidence", oneRule("exfiltration-017", "exfiltration", "x", "high", "", pats, "", two, two), `invalid confidence ""`},
		{"no patterns", oneRule("exfiltration-018", "exfiltration", "x", "high", "high", "", "", two, two), "rule exfiltration-018 has no patterns"},
		{"one match fixture", oneRule("exfiltration-019", "exfiltration", "x", "high", "high", pats, "", `["a b c"]`, two), "rule exfiltration-019 needs >=2 match fixtures"},
		{"one nonMatch fixture", oneRule("exfiltration-020", "exfiltration", "x", "high", "high", pats, "", two, `["x"]`), "rule exfiltration-020 needs >=2 nonMatch fixtures"},
		{"no nonMatch fixtures", oneRule("exfiltration-021", "exfiltration", "x", "high", "high", pats, "", two, `[]`), "rule exfiltration-021 needs >=2 nonMatch fixtures"},
		{"invalid notPattern", oneRule("exfiltration-022", "exfiltration", "x", "high", "high", pats, `['([unclosed']`, two, two), `rule exfiltration-022 notPattern "([unclosed"`},
		{"a rule file with no rules", "rules: []\n", "contains no rules"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadBundle(testBundleFS(c.yaml), "rules")
			if err == nil {
				t.Fatalf("LoadBundle accepted invalid bundle (%s)", c.name)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, c.wantErr)
			}
		})
	}

	// The manifest and the directory are checked too.
	manifestCases := []struct {
		name    string
		fsys    fstest.MapFS
		wantErr string
	}{
		{"manifest without a version", fstest.MapFS{
			"rules/bundle.yaml": &fstest.MapFile{Data: []byte("notes: x\n")},
			"rules/test.yaml":   &fstest.MapFile{Data: []byte(minimalRule)},
		}, "bundle.yaml missing version"},
		{"manifest with an unknown key", fstest.MapFS{
			"rules/bundle.yaml": &fstest.MapFile{Data: []byte("version: \"1.0.0\"\nsurprise: true\n")},
			"rules/test.yaml":   &fstest.MapFile{Data: []byte(minimalRule)},
		}, "parsing bundle.yaml"},
		{"manifest notPattern that does not compile", fstest.MapFS{
			"rules/bundle.yaml": &fstest.MapFile{Data: []byte("version: \"1.0.0\"\nnotPatterns: ['([unclosed']\n")},
			"rules/test.yaml":   &fstest.MapFile{Data: []byte(minimalRule)},
		}, `bundle.yaml notPattern "([unclosed"`},
		{"no rule files", fstest.MapFS{
			"rules/bundle.yaml": &fstest.MapFile{Data: []byte("version: \"1.0.0\"\n")},
		}, "has no rules"},
		{"no manifest", fstest.MapFS{
			"rules/test.yaml": &fstest.MapFile{Data: []byte(minimalRule)},
		}, "reading bundle.yaml"},
		{"a rule file that is not YAML", fstest.MapFS{
			"rules/bundle.yaml": &fstest.MapFile{Data: []byte("version: \"1.0.0\"\n")},
			"rules/test.yaml":   &fstest.MapFile{Data: []byte("rules: [unterminated\n")},
		}, "parsing rules/test.yaml"},
	}
	for _, c := range manifestCases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadBundle(c.fsys, "rules")
			if err == nil {
				t.Fatalf("LoadBundle accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, c.wantErr)
			}
		})
	}

	// A file that cannot be read stops the load, whether it is the directory
	// listing or a rule file.
	for name, fsys := range map[string]fs.FS{
		"unreadable directory": unreadableFS{FS: testBundleFS(minimalRule), dir: true},
		"unreadable rule file": unreadableFS{FS: testBundleFS(minimalRule), file: "rules/test.yaml"},
	} {
		if _, err := LoadBundle(fsys, "rules"); err == nil || !strings.Contains(err.Error(), "reading") || !errors.Is(err, errUnreadable) {
			t.Errorf("%s: error = %v, want a reading error wrapping the cause", name, err)
		}
	}

	// Every severity and confidence in the vocabulary loads, with exactly the
	// two fixtures of each kind the minimum asks for; a pattern that opens
	// with its own flag group is compiled as written, the others
	// case-insensitive and multiline.
	var vocab strings.Builder
	vocab.WriteString("rules:\n")
	for i, sev := range []string{"info", "low", "medium", "high", "critical"} {
		conf := []string{"low", "medium", "high", "low", "medium"}[i]
		id := fmt.Sprintf("exfiltration-%03d", 30+i)
		vocab.WriteString("  - id: " + id + "\n    family: exfiltration\n    title: x\n    severity: " + sev + "\n    confidence: " + conf +
			"\n    patterns: ['a b c']\n    fixtures: {match: [\"a b c\", \"A B C\"], nonMatch: [\"x\", \"y\"]}\n")
	}
	vocab.WriteString(`  - id: exfiltration-040
    family: exfiltration
    title: Own flags
    severity: low
    confidence: low
    patterns: ['(?s)Case Sensitive.+end', '(?i)^anchored']
    fixtures: {match: ["Case Sensitive x end", "anchored text"], nonMatch: ["case sensitive x end", "an anchored"]}
  - id: exfiltration-041
    family: exfiltration
    title: Default flags
    severity: low
    confidence: low
    patterns: ['^line start', 'Mixed Case', 'Tail(?s)Head']
    fixtures: {match: ["line start", "x\nLINE START"], nonMatch: ["a line start", "mixed"]}
`)
	vb, err := LoadBundle(testBundleFS(vocab.String()), "rules")
	if err != nil {
		t.Fatalf("a rule in every severity and confidence did not load: %v", err)
	}
	var sevs []Severity
	for _, r := range vb.Rules()[:5] {
		sevs = append(sevs, r.Severity)
	}
	if !reflect.DeepEqual(sevs, []Severity{"info", "low", "medium", "high", "critical"}) {
		t.Errorf("severities = %v", sevs)
	}
	for text, want := range map[string]bool{
		"Case Sensitive x end":       true,
		"case sensitive x end":       false,
		"Case Sensitive x\nmore end": true, // (?s) lets the dot cross the newline
		"anchored":                   true,
		"not anchored":               false,
	} {
		ids := vb.MatchingRules(text)
		if got := contains(ids, "S4/exfiltration-040"); got != want {
			t.Errorf("explicit-flag rule on %q = %v, want %v (fired %v)", text, got, want, ids)
		}
	}
	for text, want := range map[string]bool{
		"line start":        true,
		"first\nLINE START": true, // ^ anchors at each line
		"not at line start": false,
		"MIXED CASE":        true,
		"a Mixed\nCase":     false,
		"TAILHEAD":          true, // a flag group inside a pattern does not switch the defaults off
	} {
		ids := vb.MatchingRules(text)
		if got := contains(ids, "S4/exfiltration-041"); got != want {
			t.Errorf("default-flag rule on %q = %v, want %v (fired %v)", text, got, want, ids)
		}
	}

	// Rule files are the *.yaml and *.yml files of the directory itself:
	// other files and sub-directories are not read, and the extension is
	// matched without regard to case. Changing one that is read changes the
	// digest; adding one that is not does not.
	base := fstest.MapFS{
		"rules/bundle.yaml": &fstest.MapFile{Data: []byte("version: \"1.0.0\"\n")},
		"rules/a.yaml":      &fstest.MapFile{Data: []byte(oneRule("exfiltration-050", "exfiltration", "a", "low", "low", pats, "", two, two))},
	}
	withExtras := fstest.MapFS{}
	for k, v := range base {
		withExtras[k] = v
	}
	withExtras["rules/README.md"] = &fstest.MapFile{Data: []byte("not a rule file: [")}
	withExtras["rules/notes.txt"] = &fstest.MapFile{Data: []byte("rules: [")}
	withExtras["rules/sub/deeper.yaml"] = &fstest.MapFile{Data: []byte("rules: [")}
	withExtras["rules/dir.yaml/inner.yaml"] = &fstest.MapFile{Data: []byte("rules: [")}
	plain, err := LoadBundle(base, "rules")
	if err != nil {
		t.Fatal(err)
	}
	extras, err := LoadBundle(withExtras, "rules")
	if err != nil {
		t.Fatalf("files that are not rule files were read: %v", err)
	}
	if plain.Digest() != extras.Digest() || len(extras.Rules()) != 1 {
		t.Errorf("ignored files changed the bundle: digest %s vs %s, %d rules", plain.Digest(), extras.Digest(), len(extras.Rules()))
	}
	withExtras["rules/b.yml"] = &fstest.MapFile{Data: []byte(oneRule("exfiltration-051", "exfiltration", "b", "low", "low", pats, "", two, two))}
	withExtras["rules/C.YAML"] = &fstest.MapFile{Data: []byte(oneRule("exfiltration-052", "exfiltration", "c", "low", "low", pats, "", two, two))}
	withExtras["rules/D.Yml"] = &fstest.MapFile{Data: []byte(oneRule("exfiltration-053", "exfiltration", "d", "low", "low", pats, "", two, two))}
	four, err := LoadBundle(withExtras, "rules")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range four.Rules() {
		ids = append(ids, r.ID)
	}
	if !reflect.DeepEqual(ids, []string{"exfiltration-050", "exfiltration-051", "exfiltration-052", "exfiltration-053"}) {
		t.Errorf("rule files read = %v, want the .yaml, .yml, .YAML and .Yml files", ids)
	}
	if four.Digest() == plain.Digest() {
		t.Error("digest did not change when rule files were added")
	}
	// A rule file's name is part of the bundle's identity.
	renamed := fstest.MapFS{
		"rules/bundle.yaml": base["rules/bundle.yaml"],
		"rules/z.yaml":      base["rules/a.yaml"],
	}
	rn, err := LoadBundle(renamed, "rules")
	if err != nil {
		t.Fatal(err)
	}
	if rn.Digest() == plain.Digest() {
		t.Error("digest did not change when a rule file was renamed")
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
	_, err := LoadBundle(testBundleFS(dup), "rules")
	if err == nil || !strings.Contains(err.Error(), `duplicate rule id "exfiltration-901"`) {
		t.Errorf("duplicate rule id in one file: error = %v", err)
	}
	// The same id in two files is a duplicate too.
	fsys := testBundleFS(minimalRule)
	fsys["rules/other.yaml"] = &fstest.MapFile{Data: []byte(minimalRule)}
	_, err = LoadBundle(fsys, "rules")
	if err == nil || !strings.Contains(err.Error(), `duplicate rule id "exfiltration-901" (in rules/test.yaml)`) {
		t.Errorf("duplicate rule id across files: error = %v", err)
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
	// The manifest is part of the identity: a new version, new notes or a new
	// bundle-level suppression is a new digest.
	for name, manifest := range map[string]string{
		"version":     "version: \"9.9.8\"\nnotes: test\n",
		"notes":       "version: \"9.9.9\"\nnotes: other\n",
		"notPatterns": "version: \"9.9.9\"\nnotes: test\nnotPatterns: ['x']\n",
	} {
		fsys := testBundleFS(minimalRule)
		fsys["rules/bundle.yaml"] = &fstest.MapFile{Data: []byte(manifest)}
		m, err := LoadBundle(fsys, "rules")
		if err != nil {
			t.Fatal(err)
		}
		if m.Digest() == a.Digest() {
			t.Errorf("digest did not change when the manifest's %s changed", name)
		}
	}
	// The same files give the same digest, and it is a lower-case hex sha256.
	again, err := LoadBundle(testBundleFS(minimalRule), "rules")
	if err != nil {
		t.Fatal(err)
	}
	if again.Digest() != a.Digest() || len(a.Digest()) != 64 || a.Digest() != strings.ToLower(a.Digest()) {
		t.Errorf("digest %q is not a reproducible lower-case sha256", a.Digest())
	}
	// Path and content boundaries are framed: moving bytes from one file's
	// name into its content must not give the same digest.
	f1 := testBundleFS(minimalRule)
	f2 := fstest.MapFS{"rules/bundle.yaml": f1["rules/bundle.yaml"], "rules/tes.yaml": &fstest.MapFile{Data: []byte(minimalRule)}}
	d1, err1 := LoadBundle(f1, "rules")
	d2, err2 := LoadBundle(f2, "rules")
	if err1 != nil || err2 != nil || d1.Digest() == d2.Digest() {
		t.Errorf("file names did not reach the digest: %v %v", err1, err2)
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

	// The cap itself: 200 runes, an ellipsis when something was cut, and the
	// escapes for invisible characters count towards it.
	if excerptMaxRunes != 200 {
		t.Fatalf("excerptMaxRunes = %d, want 200", excerptMaxRunes)
	}
	x200, x201 := strings.Repeat("x", 200), strings.Repeat("x", 201)
	if got := renderExcerpt(x200); got != x200 {
		t.Errorf("200 runes rendered as %d runes (%q...)", len([]rune(got)), got[:10])
	}
	if got := renderExcerpt(x201); got != x200+"\u2026" {
		t.Errorf("201 runes rendered as %d runes, want 200 and an ellipsis", len([]rune(got)))
	}
	zw25 := strings.Repeat("\u200b", 25) // 25 escapes of 8 runes: exactly 200
	if got := renderExcerpt(zw25); got != strings.Repeat("<U+200B>", 25) {
		t.Errorf("25 escapes rendered as %q", got)
	}
	if got, want := renderExcerpt(zw25+"\u200b"), strings.Repeat("<U+200B>", 25)+"\u2026"; got != want {
		t.Errorf("26 escapes rendered as %d runes, want 200 and an ellipsis", len([]rune(got)))
	}
	if got, want := renderExcerpt("x"+strings.Repeat("\u200b", 25)), "x"+strings.Repeat("<U+200B>", 24)+"<U+200B"+"\u2026"; got != want {
		t.Errorf("an escape cut by the cap rendered as %q, want %q", got, want)
	}
	// What is shown as it is and what is escaped.
	for in, want := range map[string]string{
		"a b":                    "a b",
		"caf\u00e9 \u65e5\u672c": "caf\u00e9 \u65e5\u672c",
		"a\u00a0b":               "a\u00a0b", // a no-break space is graphic
		"a\tb":                   "a<U+0009>b",
		"a\nb":                   "a<U+000A>b",
		"a\rb":                   "a<U+000D>b",
		"a\u0085b":               "a<U+0085>b",
		"a\u202eb":               "a<U+202E>b",
		"a\U000E0041b":           "a<U+E0041>b",
		"a\ufeffb":               "a<U+FEFF>b",
		"a\uE000b":               "a<U+E000>b",
		"a\xffb":                 "a<U+FFFD>b",
		"a\uFFFDb":               "a\uFFFDb", // a real U+FFFD is graphic
		"":                       "",
	} {
		if got := renderExcerpt(in); got != want {
			t.Errorf("renderExcerpt(%q) = %q, want %q", in, got, want)
		}
	}
	// An invalid byte counts as the 8 runes of its marker.
	if got, want := renderExcerpt(strings.Repeat("\xff", 26)), strings.Repeat("<U+FFFD>", 25)+"\u2026"; got != want {
		t.Errorf("26 invalid bytes rendered as %d runes", len([]rune(got)))
	}
	// A long data: URI is cut to 180 bytes before it is rendered.
	long180 := "data:image/png;base64," + strings.Repeat("A", 400)
	for _, f := range ScanS3("a.md", []byte("!["+"x"+"]("+long180+")")) {
		if f.RuleID == "S3/data-uri" && len(f.Excerpt) != 180 {
			t.Errorf("data-uri excerpt is %d bytes, want 180", len(f.Excerpt))
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

	// Rules come back ordered by id, whatever order the files hold them in,
	// and MatchingRules answers in that order.
	rev := `rules:
  - id: exfiltration-922
    family: exfiltration
    title: Second
    severity: low
    confidence: low
    patterns: ['gamma delta']
    fixtures: {match: ["gamma delta", "GAMMA DELTA"], nonMatch: ["gamma", "delta"]}
  - id: exfiltration-911
    family: exfiltration
    title: First
    severity: low
    confidence: low
    patterns: ['alpha beta']
    fixtures: {match: ["alpha beta", "ALPHA BETA"], nonMatch: ["alpha", "beta"]}
`
	rb, err := LoadBundle(testBundleFS(rev), "rules")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rb.Rules() {
		ids = append(ids, r.ID)
	}
	if !reflect.DeepEqual(ids, []string{"exfiltration-911", "exfiltration-922"}) {
		t.Errorf("Rules() order = %v", ids)
	}
	if got := rb.MatchingRules("gamma delta, then an alpha beta line"); !reflect.DeepEqual(got, []string{"S4/exfiltration-911", "S4/exfiltration-922"}) {
		t.Errorf("MatchingRules = %v", got)
	}
	// Scan results are ordered by line, not by the order the rules ran in.
	var hits []string
	for _, f := range rb.Scan("a.md", []byte("gamma delta\nalpha beta\n")) {
		hits = append(hits, fmt.Sprintf("%d:%s", f.LineStart, f.RuleID))
	}
	if !reflect.DeepEqual(hits, []string{"1:S4/exfiltration-922", "2:S4/exfiltration-911"}) {
		t.Errorf("Scan order = %v", hits)
	}
	if got := rb.MatchingRules("nothing"); len(got) != 0 {
		t.Errorf("MatchingRules on unrelated text = %v", got)
	}
	// The returned rules carry what the file said.
	first := rb.Rules()[0]
	if first.Title != "First" || first.Severity != SeverityLow || first.Confidence != ConfidenceLow || first.Family != "exfiltration" || len(first.Patterns) != 1 {
		t.Errorf("Rules()[0] = %+v", first)
	}
}
