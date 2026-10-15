package scan

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/manifest"
)

// websiteTester is a website tester's manifest and instruction: about
// twenty browser tools named in the instruction, no browser line.
func websiteTester(t *testing.T, withBrowser bool) *Input {
	t.Helper()
	yml, err := os.ReadFile("../../pkg/toolgrant/testdata/website-test-plan-runner/agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	instr, err := os.ReadFile("../../pkg/toolgrant/testdata/website-test-plan-runner/AGENT.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(yml)
	if withBrowser {
		doc = strings.Replace(doc, "  dataAccess:", "  browser:\n    sites: [site]\n    secrets: [SITE_USER, SITE_PASSWORD]\n  dataAccess:", 1)
	}
	m, err := manifest.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := manifest.CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	return &Input{ManifestJSON: canonical, Files: []FileEntry{
		{Path: "agent.yaml", IsText: true, Content: []byte(doc)},
		{Path: "AGENT.md", IsText: true, Content: instr},
	}}
}

// An instruction that works a site through the browser tools, in a
// release with no browser line, is one high S6 finding naming the line to
// add, and the gate sends the version to a person rather than rejecting
// it. Declaring the browser clears it.
func TestS6ReportsTheBrowserToolsAReleaseDoesNotGrant(t *testing.T) {
	res := S6Scripts{}.Run(testStageContext(t), websiteTester(t, false))
	var got []Finding
	for _, f := range res.Findings {
		if f.Scanner == scannerUngrantedTool {
			got = append(got, f)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want one ungranted-tool finding, got %+v", res.Findings)
	}
	f := got[0]
	tools, _ := f.Detail["tools"].([]string)
	if f.Severity != SevHigh || f.Confidence != ConfHigh || f.FilePath != "AGENT.md" || f.LineStart < 1 ||
		f.Detail["path"] != "capabilities.browser" || f.Detail["grant"] != "browser" ||
		!slices.Contains(tools, "browser_click") || slices.Contains(tools, "browser_pdf_save") ||
		!strings.Contains(f.Title, "capabilities.browser") {
		t.Errorf("finding = %+v", f)
	}
	dec := Evaluate(GateInput{Findings: res.Findings, Policy: DefaultBaseline()})
	if dec.Outcome != OutcomeNeedsReview {
		t.Errorf("gate = %s (%s), want needs_review", dec.Outcome, dec.Reason)
	}

	res = S6Scripts{}.Run(testStageContext(t), websiteTester(t, true))
	for _, f := range res.Findings {
		if f.Scanner == scannerUngrantedTool {
			t.Errorf("a declared browser still reports %+v", f)
		}
	}
}

// One finding per grant missing, in the order the instruction first
// calls for each; a v1 prompt-agent's instruction is found among its
// candidates.
func TestS6ReportsEachGrantOnce(t *testing.T) {
	in := &Input{
		ManifestJSON: []byte(`{"schemaVersion":"2","modes":["autonomous"],"entrypoints":{"instruction":"RUN.md"},"capabilities":{"network":{"egress":"none"},"exec":"none"}}`),
		Files:        []FileEntry{{Path: "RUN.md", IsText: true, Content: []byte("Call the `fetch` tool.\nThen run_command jq, and fetch again.\nUse `run_command` for wc.\n")}},
	}
	var got []string
	for _, f := range (S6Scripts{}).Run(testStageContext(t), in).Findings {
		if f.Scanner == scannerUngrantedTool {
			got = append(got, f.Detail["path"].(string))
		}
	}
	if !slices.Equal(got, []string{"capabilities.network.egress", "capabilities.exec.commands"}) {
		t.Errorf("got %v", got)
	}

	v1 := &Input{
		ManifestJSON: []byte(`{"schemaVersion":"1","kind":"prompt-agent","capabilities":{}}`),
		Files:        []FileEntry{{Path: "PROMPT.md", IsText: true, Content: []byte("Open the page with browser_navigate.\n")}},
	}
	if fs := (S6Scripts{}).Run(testStageContext(t), v1).Findings; len(fs) != 1 || fs[0].Scanner != scannerUngrantedTool {
		t.Errorf("v1 prompt-agent: got %+v", fs)
	}
}
