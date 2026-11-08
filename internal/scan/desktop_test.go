package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/manifestcaps"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/pkg/manifest"
)

// The person's computer in the pipeline. capabilities.desktop is two
// policy tokens of its own (desktop, and computerUse when it does computer
// use); an application's server it uses counts as network, since the
// registry cannot know what that server reaches from the person's computer;
// S7 names each such application as not covered and asks no advisory
// database; S9 reports what a release newly does on the person's computer;
// and S6 ties an application's <server>__<tool> names to the line.

const blenderLine = `{"servers":[{"id":"blender"}]}`

func desktopManifest(line string) string {
	return `{"schemaVersion":"2","name":"scene-builder","summary":"Builds a scene in Blender",` +
		`"capabilities":{"network":{"egress":"none"},"exec":"none","desktop":` + line + `}}`
}

func TestTheDesktopLineIsTwoPolicyTokens(t *testing.T) {
	got := declaredCaps([]byte(desktopManifest(blenderLine)))
	if !got["desktop"] || got["computerUse"] || !got["network"] || got["exec"] {
		t.Fatalf("declaredCaps = %v; want desktop, and network for the server's unknown reach", got)
	}
	got = declaredCaps([]byte(desktopManifest(`{"computerUse":"app"}`)))
	if !got["desktop"] || !got["computerUse"] || got["network"] {
		t.Fatalf("computer use alone: declaredCaps = %v", got)
	}
	// A line that does not read is held the strict way.
	got = declaredCaps([]byte(desktopManifest(`{"servers":"blender"}`)))
	if !got["desktop"] || !got["computerUse"] {
		t.Fatalf("a line that does not read: declaredCaps = %v", got)
	}
	if unrestrictedNetwork([]byte(desktopManifest(blenderLine))) {
		t.Fatal("a desktop line reads as unrestricted network")
	}
	if d := declarationOf([]byte(desktopManifest(blenderLine))); d.EgressAny || len(d.Egress) != 0 {
		t.Fatalf("S4's declaration reads the server's reach as the agent's own: %+v", d)
	}
	// An application used through its windows alone runs no server of the
	// run's, so it is no network.
	got = declaredCaps([]byte(desktopManifest(`{"servers":[{"id":"kdenlive","use":"computer"}],"computerUse":"app"}`)))
	if !got["desktop"] || !got["computerUse"] || got["network"] {
		t.Fatalf("windows alone: declaredCaps = %v", got)
	}
	// Nor does it name a host S9 would count.
	if hosts := manifestcapsServerEgress(t, desktopManifest(blenderLine)); len(hosts) != 0 {
		t.Fatalf("the line names hosts: %v", hosts)
	}
}

// A desktop line of an odd shape leaves every other line declared.
func TestADesktopLineOfAnOddShapeLeavesTheRestDeclared(t *testing.T) {
	doc := `{"schemaVersion":"2","name":"x","capabilities":{"exec":{"commands":["git"]},"secrets":["TOKEN"],"desktop":[1,2]}}`
	got := declaredCaps([]byte(doc))
	for _, c := range []string{"exec", "env", "desktop", "computerUse"} {
		if !got[c] {
			t.Fatalf("declaredCaps = %v; %s is missing", got, c)
		}
	}
}

func TestAPolicyCanBlockTheDesktopOrComputerUse(t *testing.T) {
	withUse := registry.PolicySubmission{ManifestJSON: []byte(desktopManifest(`{"servers":[{"id":"blender"}],"computerUse":"app"}`))}
	for _, token := range []string{"desktop", "computerUse"} {
		issues := CheckSubmissionPolicy(Policy{BlockedCapabilities: []string{token}}, withUse)
		if len(issues) != 1 || !strings.Contains(issues[0].Error(), `"`+token+`"`) {
			t.Fatalf("a policy blocking %s: %v", token, issues)
		}
	}
	// Blocking computer use leaves a line without it alone.
	servers := registry.PolicySubmission{ManifestJSON: []byte(desktopManifest(blenderLine))}
	if issues := CheckSubmissionPolicy(Policy{BlockedCapabilities: []string{"computerUse"}}, servers); len(issues) != 0 {
		t.Fatalf("a policy blocking computerUse refuses a line without it: %v", issues)
	}
	// Under the baseline the line routes nothing to review; a policy may
	// ask for review of it by name.
	decl := declaredCaps(withUse.ManifestJSON)
	if d := Evaluate(GateInput{Policy: DefaultBaseline(), DeclaredCapabilities: decl}); d.Outcome != OutcomePublish {
		t.Fatalf("a desktop line under the baseline: %+v", d)
	}
	strict := DefaultBaseline()
	strict.RequireHumanReview = json.RawMessage(`{"whenCapabilities":["computerUse"]}`)
	if d := Evaluate(GateInput{Policy: strict, DeclaredCapabilities: decl}); d.Outcome != OutcomeNeedsReview || !strings.Contains(d.Reason, "computerUse") {
		t.Fatalf("a policy that names computerUse: %+v", d)
	}
}

// S7 asks no advisory database about an application on the person's
// computer: which server answers for it is known only there. It names each
// application whose server the line uses as not covered, with why, and the
// version's server join holds nothing the sweep would look up.
func TestS7NamesEachApplicationAsNotCovered(t *testing.T) {
	for _, c := range []struct {
		name, line string
		refs       []string
	}{
		{"an application the registry has never seen", `{"servers":[{"id":"my-cad"}]}`, []string{"desktop:my-cad"}},
		{"two applications", `{"servers":[{"id":"blender"},{"id":"unreal","tools":["list_toolsets"]}]}`, []string{"desktop:blender", "desktop:unreal"}},
		{"an application the person chooses", `{"servers":[{"choose":true}]}`, []string{"desktop:(an application the person chooses)"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			osv := &fakeOSV{}
			res := S7MCPServers{}.Run(s7ctx(osv, &MemoryMCPScanCache{}), &Input{ManifestJSON: []byte(desktopManifest(c.line))})
			if osv.calls != 0 {
				t.Fatalf("OSV was asked %d times", osv.calls)
			}
			got := findScanner(res.Findings, scannerOSVNoData)
			text := fmt.Sprint(got)
			if len(got) != 1 || got[0].Severity != SevMedium || !strings.Contains(text, noDataDesktop) {
				t.Fatalf("findings %+v", res.Findings)
			}
			for _, ref := range c.refs {
				if !strings.Contains(text, ref) {
					t.Fatalf("%s is not named: %+v", ref, got)
				}
			}
			if servers := DeclaredMCPServers([]byte(desktopManifest(c.line))); len(servers) != 0 {
				t.Fatalf("the sweep would look up %+v", servers)
			}
		})
	}
	// Computer use alone, and an application's windows alone, use no server.
	for _, line := range []string{`{"computerUse":"app"}`, `{"servers":[{"id":"kdenlive","use":"computer"}],"computerUse":"app"}`} {
		osv := &fakeOSV{}
		res := S7MCPServers{}.Run(s7ctx(osv, &MemoryMCPScanCache{}), &Input{ManifestJSON: []byte(desktopManifest(line))})
		if osv.calls != 0 || len(res.Findings) != 0 {
			t.Fatalf("%s: calls %d, findings %+v", line, osv.calls, res.Findings)
		}
	}
}

func s9Desktop(t *testing.T, prev, cur string) []Finding {
	t.Helper()
	return findScanner(s9ManifestDiff(&Input{PrevManifestJSON: []byte(prev), ManifestJSON: []byte(cur)}), scannerNewDesktop)
}

// S9 reports new-desktop on a first declaration and on each widening, in
// the consent's words, and nothing on the same line or a narrower one.
func TestS9ReportsWhatAReleaseNewlyDoesOnThePersonsComputer(t *testing.T) {
	none := `{"schemaVersion":"2","name":"scene-builder","capabilities":{}}`
	got := s9Desktop(t, none, desktopManifest(`{"servers":[{"id":"blender"}],"computerUse":"app"}`))
	if len(got) != 2 || got[0].Severity != SevMedium || !strings.Contains(got[0].Title, "uses the application blender on your computer") ||
		!strings.Contains(got[1].Title, "can see and use the windows of blender") {
		t.Fatalf("a first declaration: %+v", got)
	}
	for _, f := range s9ManifestDiff(&Input{PrevManifestJSON: []byte(none), ManifestJSON: []byte(desktopManifest(blenderLine))}) {
		if f.Scanner == "S9/capability-widened" && (f.Detail["capability"] == "desktop" || f.Detail["capability"] == "computerUse") {
			t.Fatalf("the bare token is reported beside new-desktop: %+v", f)
		}
	}
	narrow := desktopManifest(`{"servers":[{"id":"blender","tools":["look"]}]}`)
	got = s9Desktop(t, narrow, desktopManifest(blenderLine))
	if len(got) != 1 || !strings.Contains(got[0].Title, "lifts the tool narrowing of the application blender") {
		t.Fatalf("a lifted narrowing: %+v", got)
	}
	got = s9Desktop(t, narrow, desktopManifest(`{"servers":[{"id":"blender","tools":["look","execute_blender_code"]}]}`))
	if len(got) != 1 || !strings.Contains(got[0].Title, "adds tool execute_blender_code of the application blender") {
		t.Fatalf("a tool added: %+v", got)
	}
	got = s9Desktop(t, desktopManifest(`{"computerUse":"app"}`), desktopManifest(`{"computerUse":"screen"}`))
	if len(got) != 1 || !strings.Contains(got[0].Title, "whole screen") {
		t.Fatalf("app to screen: %+v", got)
	}
	if got := s9Desktop(t, desktopManifest(blenderLine), desktopManifest(blenderLine)); len(got) != 0 {
		t.Fatalf("the same line: %+v", got)
	}
	if got := s9Desktop(t, desktopManifest(blenderLine), narrow); len(got) != 0 {
		t.Fatalf("a narrower line: %+v", got)
	}
	if got := s9Desktop(t, none, desktopManifest(`7`)); len(got) != 1 || !strings.Contains(got[0].Title, "does not read") {
		t.Fatalf("a line that does not read: %+v", got)
	}
}

// sceneBuilder is a release whose instruction calls Blender's tools, with
// or without the desktop line.
func sceneBuilder(t *testing.T, line string) *Input {
	t.Helper()
	yml, err := os.ReadFile("../../pkg/toolgrant/testdata/website-test-plan-runner/agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(yml)
	if line != "" {
		doc = strings.Replace(doc, "  dataAccess:", line+"  dataAccess:", 1)
	}
	m, err := manifest.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := manifest.CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	instr := "# Scene builder\n\nRead the scene with `blender__get_scene_info`, then build the props by calling blender__execute_blender_code.\n"
	return &Input{ManifestJSON: canonical, Files: []FileEntry{
		{Path: "agent.yaml", IsText: true, Content: []byte(doc)},
		{Path: "AGENT.md", IsText: true, Content: []byte(instr)},
	}}
}

func ungranted(t *testing.T, in *Input) []Finding {
	t.Helper()
	return findScanner(S6Scripts{}.Run(testStageContext(t), in).Findings, scannerUngrantedTool)
}

// S6 refuses a blender__execute_blender_code call in a release that does
// not declare blender (read as a declared MCP server's, since the registry
// holds no list of applications), and in one whose narrowing leaves the
// tool out; the line that gives it clears it.
func TestS6TiesApplicationToolsToTheDesktopLine(t *testing.T) {
	got := ungranted(t, sceneBuilder(t, ""))
	if len(got) != 1 || got[0].Detail["path"] != "capabilities.mcpServers" || got[0].Detail["grant"] != "mcpServers" ||
		!slices.Equal(got[0].Detail["tools"].([]string), []string{"blender__get_scene_info", "blender__execute_blender_code"}) {
		t.Fatalf("no desktop line: %+v", got)
	}
	if d := Evaluate(GateInput{Findings: got, Policy: DefaultBaseline()}); d.Outcome != OutcomeNeedsReview {
		t.Fatalf("gate = %s (%s), want needs_review", d.Outcome, d.Reason)
	}
	got = ungranted(t, sceneBuilder(t, "  desktop:\n    servers:\n      - id: blender\n        tools: [get_scene_info]\n"))
	if len(got) != 1 || !slices.Equal(got[0].Detail["tools"].([]string), []string{"blender__execute_blender_code"}) {
		t.Fatalf("a narrowing without the code tool: %+v", got)
	}
	if got := ungranted(t, sceneBuilder(t, "  desktop:\n    servers:\n      - id: blender\n")); len(got) != 0 {
		t.Fatalf("a declared blender still reports %+v", got)
	}
}

// manifestcapsServerEgress is the hosts S9 counts as server egress.
func manifestcapsServerEgress(t *testing.T, doc string) map[string]string {
	t.Helper()
	c, ok := manifestcaps.Read([]byte(doc))
	if !ok {
		t.Fatal("the manifest does not read")
	}
	return c.ServerEgress()
}
