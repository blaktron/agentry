package manifest

import (
	"flag"
	"os"
	"strings"
	"testing"
)

var updateRulesDoc = flag.Bool("update-rules-doc", false, "rewrite the rule table in docs/quickagents.md from the rule list")

const (
	rulesDocPath  = "../../docs/quickagents.md"
	rulesDocBegin = "<!-- manifest-rules: generated from pkg/manifest's rule table by TestDocsListEveryManifestRule; do not edit -->"
	rulesDocEnd   = "<!-- /manifest-rules -->"
)

// rulesDocTable is the table the package-format page lists the rules in.
func rulesDocTable() string {
	var b strings.Builder
	b.WriteString("| Rule | What it checks |\n|---|---|\n")
	for _, r := range Rules() {
		b.WriteString("| " + r.ID + " | " + r.Title + " |\n")
	}
	return b.String()
}

// TestDocsListEveryManifestRule holds the package-format page's rule table to
// the rule list, so every id an error cites is on the page with what it
// checks. go test ./pkg/manifest -run TestDocsListEveryManifestRule
// -update-rules-doc rewrites the table.
func TestDocsListEveryManifestRule(t *testing.T) {
	raw, err := os.ReadFile(rulesDocPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	head, rest, ok := strings.Cut(doc, rulesDocBegin)
	if !ok {
		t.Fatalf("%s has no %q marker", rulesDocPath, rulesDocBegin)
	}
	_, tail, ok := strings.Cut(rest, rulesDocEnd)
	if !ok {
		t.Fatalf("%s has no %q marker", rulesDocPath, rulesDocEnd)
	}
	want := head + rulesDocBegin + "\n\n" + rulesDocTable() + "\n" + rulesDocEnd + tail
	if want == doc {
		return
	}
	if *updateRulesDoc {
		if err := os.WriteFile(rulesDocPath, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("the rule table in %s differs from the rule list; run go test ./pkg/manifest -run TestDocsListEveryManifestRule -update-rules-doc", rulesDocPath)
}
