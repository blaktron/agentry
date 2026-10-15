package toolgrant_test

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/pkg/manifest"
	"github.com/blaktron/agentry/pkg/toolgrant"
)

// caps parses a capabilities block as agent.yaml writes it.
func caps(t *testing.T, block string) manifest.Capabilities {
	t.Helper()
	doc := "schemaVersion: \"2\"\nname: x\nnamespace: y\nmodes: [autonomous]\nversion: 0.1.0\nsummary: s\npublish:\n  include: [agent.yaml]\n"
	if block != "" {
		doc += "capabilities:\n" + block
	}
	m, err := manifest.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m.Capabilities
}

func tools(ms []toolgrant.Missing) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Tool)
	}
	return out
}

func TestAWebsiteTesterWithoutABrowserLineIsMissingTheBrowser(t *testing.T) {
	yml, err := os.ReadFile("testdata/website-test-plan-runner/agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	instr, err := os.ReadFile("testdata/website-test-plan-runner/AGENT.md")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(yml)
	if err != nil {
		t.Fatal(err)
	}
	got := toolgrant.Check(m.Capabilities, string(instr))
	if len(got) == 0 {
		t.Fatal("no tool reported for an instruction that works a site through the browser tools")
	}
	for _, g := range got {
		if g.Grant != toolgrant.GrantBrowser || g.Path != "capabilities.browser" || g.Line < 1 || g.Reason == "" {
			t.Errorf("unexpected missing tool %+v", g)
		}
	}
	names := tools(got)
	for _, want := range []string{"browser_resize", "browser_navigate", "browser_snapshot", "browser_click", "browser_take_screenshot", "browser_verify_value"} {
		if !slices.Contains(names, want) {
			t.Errorf("%s not reported; got %v", want, names)
		}
	}
	// "This is the report export, not `browser_pdf_save`": named only to
	// be turned away.
	if slices.Contains(names, "browser_pdf_save") {
		t.Errorf("browser_pdf_save is named only as the tool not to use; got %v", names)
	}
	for _, n := range []string{"write_report", "export_pdf", "scratch_write", "knowledge_list", "read_input"} {
		if slices.Contains(names, n) {
			t.Errorf("%s needs no contract line; got %v", n, names)
		}
	}

	// The same package with its browser line declared needs nothing more.
	fixed := strings.Replace(string(yml), "  dataAccess:", "  browser:\n    sites: [site]\n    secrets: [SITE_USER, SITE_PASSWORD]\n  dataAccess:", 1)
	m2, err := manifest.Parse([]byte(fixed))
	if err != nil {
		t.Fatalf("parse the declared variant: %v", err)
	}
	if got := toolgrant.Check(m2.Capabilities, string(instr)); len(got) != 0 {
		t.Errorf("a declared browser still reports %v", got)
	}
}

func TestEachGrantIsReportedWhenMissingAndNotWhenDeclared(t *testing.T) {
	cases := []struct {
		name, instr, without, with string
		want                       []string
		grant                      toolgrant.Grant
	}{
		{"exec", "Run `run_command` with `jq` on each file.", "  exec: none\n", "  exec:\n    commands: [jq]\n", []string{"run_command"}, toolgrant.GrantExec},
		{"fetch", "Use the `fetch` tool to read the API.", "  network:\n    egress: none\n", "  network:\n    egress: [api.example.com]\n", []string{"fetch"}, toolgrant.GrantEgress},
		{"target hosts", "Check the disk with host_run, then read /etc/fstab with host_read.", "", "  targetHosts: [server]\n", []string{"host_run", "host_read"}, toolgrant.GrantTargetHosts},
		{"filesystem read", "List the workspace with fs_list and read each file with fs_read.", "  filesystem:\n    read: none\n    write: none\n", "  filesystem:\n    read: workspace\n", []string{"fs_list", "fs_read"}, toolgrant.GrantFSRead},
		{"filesystem write", "Save the fixed file with fs_write.", "  filesystem:\n    read: workspace\n    write: none\n", "  filesystem:\n    write:\n      paths: [out]\n", []string{"fs_write"}, toolgrant.GrantFSWrite},
		{"browser family", "Drive the site with the browser_* tools.", "", "  browser:\n    scope: public\n", []string{"browser_*"}, toolgrant.GrantBrowser},
		{"harness prefix", "Call mcp__gateway__fetch for each URL.", "", "  network:\n    egress: [example.com]\n", []string{"fetch"}, toolgrant.GrantEgress},
		{"mcp server", "File the result with github__create_issue.", "", "  mcpServers:\n    - npm: \"@modelcontextprotocol/server-github\"\n      version: 1.0.0\n", []string{"github__create_issue"}, toolgrant.GrantMCPServer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toolgrant.Check(caps(t, tc.without), tc.instr)
			if !slices.Equal(tools(got), tc.want) {
				t.Fatalf("without the grant: got %v, want %v", tools(got), tc.want)
			}
			for _, g := range got {
				if g.Grant != tc.grant || g.Path != tc.grant.Path() || g.Line != 1 {
					t.Errorf("got %+v", g)
				}
			}
			if got := toolgrant.Check(caps(t, tc.with), tc.instr); len(got) != 0 {
				t.Errorf("with the grant: got %v", tools(got))
			}
		})
	}
}

func TestToolsTheInstructionTurnsAwayAreNotNeeds(t *testing.T) {
	for _, instr := range []string{
		"Do not use `fetch`, `run_command` or `fs_write`.",
		"Never call browser_click.",
		"This is the report export, not `browser_pdf_save`, which would print the website.",
		"If you have `run_command`, use it to count lines.",
		"Work without host_run; read only what the inputs hold.",
		"Do not\nuse `fetch` for anything.",
		"Write the report instead of browser_pdf_save.",
	} {
		if got := toolgrant.Check(caps(t, ""), instr); len(got) != 0 {
			t.Errorf("%q: got %v", instr, tools(got))
		}
	}
}

func TestProseWordsAreNotToolNames(t *testing.T) {
	for _, instr := range []string{
		"Open the site in a browser and fetch the page it links to.",
		"Fetch the latest figures from the attached spreadsheet.",
		"Screenshots appear as browser_snapshot.png in reports/browser/.",
		"Name files like run_command_log.txt or host_runbook.md.",
		"Python's __init__ and self.__dict__ are not tools.",
		"Read the docs at https://example.com/browser_click and email ops@fs_read.example.",
		"Write every finding with write_report and export it with export_pdf.",
		"In the page's script, `fetch(url, {method: \"HEAD\"})` each link.",
		"Prefer no tool, then the QuickAgent's own `fetch` to a few exact hosts.",
		"A QuickAgent with a target host works it through the host tools (`host_run`).",
		"3. Choose the tools a QuickAgent needs. Prefer what needs no key:\n   the browser the runner gives, `fetch` to an open API.",
	} {
		if got := toolgrant.Check(caps(t, ""), instr); len(got) != 0 {
			t.Errorf("%q: got %v", instr, tools(got))
		}
	}
}

// An instruction that calls itself a QuickAgent is speaking of its own
// run; only a paragraph about another package is left out.
func TestAQuickAgentSpeakingOfItselfStillNeedsItsTools(t *testing.T) {
	for _, instr := range []string{
		"You are a QuickAgent that tests sites. Use `browser_click` on each button.",
		"This QuickAgent opens the page with browser_navigate.",
	} {
		if got := toolgrant.Check(caps(t, ""), instr); len(got) != 1 {
			t.Errorf("%q: got %v", instr, tools(got))
		}
	}
}

// Prohibitions written with a colon, across a CRLF file, or with the
// negation further back than the tool before it, are still prohibitions;
// a blank line ends what a list carries.
func TestProhibitionsInOtherShapes(t *testing.T) {
	for _, instr := range []string{
		"Never use any of these tools: browser_click, `fetch`.",
		"Do not call fetch or run_command.",
		"Do not use `fetch`,\r\n`run_command` or `fs_write`.",
	} {
		if got := toolgrant.Check(caps(t, ""), instr); len(got) != 0 {
			t.Errorf("%q: got %v", instr, tools(got))
		}
	}
	for instr, want := range map[string][]string{
		"A QuickAgent reviewer reads this.\r\n\r\nUse `browser_click` here.": {"browser_click"},
		"Never call `fetch`.\n\n`run_command` counts the lines.":             {"run_command"},
		"Never submit real orders: use browser_click only on test items.":    {"browser_click"},
	} {
		if got := toolgrant.Check(caps(t, ""), instr); !slices.Equal(tools(got), want) {
			t.Errorf("%q: got %v, want %v", instr, tools(got), want)
		}
	}
}

func TestAListItemAfterANegationIsJudgedAlone(t *testing.T) {
	instr := "Never submit real payments.\n- Use `browser_click` to press each button.\n- Do not use browser_evaluate."
	got := toolgrant.Check(caps(t, ""), instr)
	if !slices.Equal(tools(got), []string{"browser_click"}) || got[0].Line != 2 {
		t.Fatalf("got %+v", got)
	}
	got = toolgrant.Check(caps(t, ""), "If `browser_click` does not work, use `browser_press_key`.")
	if !slices.Equal(tools(got), []string{"browser_click", "browser_press_key"}) {
		t.Fatalf("got %v", tools(got))
	}
}

func TestBrowserEvaluateIsNotGivenToABrowserThatTypesSecrets(t *testing.T) {
	c := caps(t, "  secrets: [SITE_PASSWORD]\n  browser:\n    sites: [site]\n    secrets: [SITE_PASSWORD]\n")
	got := toolgrant.Check(c, "Read the total with browser_evaluate.")
	if !slices.Equal(tools(got), []string{"browser_evaluate"}) || got[0].Grant != toolgrant.GrantBrowser || got[0].Path != "capabilities.browser.secrets" {
		t.Fatalf("got %+v", got)
	}
	if got := toolgrant.Check(c, "Click with browser_click."); len(got) != 0 {
		t.Fatalf("got %v", tools(got))
	}
}

func TestADeclaredServerIsMatchedByItsName(t *testing.T) {
	c := caps(t, "  mcpServers:\n    - npm: \"@modelcontextprotocol/server-github\"\n      version: 1.0.0\n    - url: https://mcp.linear.app/mcp\n      auth: oauth\n")
	for _, instr := range []string{"Call github__create_issue.", "Call server-github__list_issues.", "Call linear__create_issue."} {
		if got := toolgrant.Check(c, instr); len(got) != 0 {
			t.Errorf("%q: got %v", instr, tools(got))
		}
	}
	if got := toolgrant.Check(c, "Call jira__create_issue."); !slices.Equal(tools(got), []string{"jira__create_issue"}) {
		t.Errorf("got %v", tools(got))
	}
}

func TestTheTableNamesEachRunnerToolOnce(t *testing.T) {
	table := toolgrant.Table()
	for _, n := range toolgrant.NotContract() {
		if _, ok := table[n]; ok {
			t.Errorf("%s is both granted by the contract and given by the runner", n)
		}
	}
	for _, g := range toolgrant.Grants() {
		if g.Path() == "" {
			t.Errorf("%s has no manifest path", g)
		}
	}
	for g, n := range map[toolgrant.Grant]int{
		toolgrant.GrantBrowser: 29, toolgrant.GrantTargetHosts: 9, toolgrant.GrantFSRead: 2,
		toolgrant.GrantFSWrite: 1, toolgrant.GrantEgress: 1, toolgrant.GrantExec: 1,
	} {
		if got := len(toolgrant.ToolsOf(g)); got != n {
			t.Errorf("%s gives %d tools, want %d", g, got, n)
		}
		if g.Path() == "" {
			t.Errorf("%s has no manifest path", g)
		}
	}
}

// A megabyte of instruction in one paragraph, naming a tool fifty thousand
// times, is read in time linear in its length: the reading runs inside the
// publication scan, on text an author controls.
func TestALargeInstructionIsReadInLinearTime(t *testing.T) {
	instr := strings.Repeat("then use browser_click and ", 40000) + "\n" + strings.Repeat("x", 1<<20)
	start := time.Now()
	got := toolgrant.Check(caps(t, ""), instr)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %s", d)
	}
	if !slices.Equal(tools(got), []string{"browser_click"}) {
		t.Fatalf("got %v", tools(got))
	}
}

// The answer is bounded however the instruction is written: a name past
// MaxNameBytes is not a tool, and at most MaxMissing tools are reported.
func TestTheAnswerIsBounded(t *testing.T) {
	var b strings.Builder
	for i := range 500 {
		fmt.Fprintf(&b, "Call s%d__t%d. ", i, i)
	}
	if got := toolgrant.Check(caps(t, ""), b.String()); len(got) != toolgrant.MaxMissing {
		t.Fatalf("got %d entries", len(got))
	}
	long := "Call " + strings.Repeat("x", toolgrant.MaxNameBytes) + "__tool."
	if got := toolgrant.Check(caps(t, ""), long); len(got) != 0 {
		t.Fatalf("a name past the bound: %v", tools(got))
	}
}
