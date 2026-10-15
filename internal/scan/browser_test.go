package scan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
)

// The browser in the pipeline.
// capabilities.browser is its own capability token, never
// network; a site-scoped browser publishes under the baseline as a target
// host does; a browser on any public site is held as "*" egress is, under
// the policy's wildcardEgress.

// browserManifest is a canonical manifest that declares a browser line.
func browserManifest(browser string) string {
	return `{"schemaVersion":"2","name":"site-tester","summary":"Tests the website you name",` +
		`"intake":[{"id":"site","prompt":"Which site should I test?","type":"url","required":true}],` +
		`"capabilities":{"browser":` + browser + `}}`
}

const (
	siteBrowser   = `{"sites":["site"],"hosts":["fonts.googleapis.com"]}`
	publicBrowser = `{"sites":["site"],"scope":"public"}`
)

// TestABrowserIsItsOwnPolicyTokenNotNetwork: the gate and policy read the
// browser as its own capability, and S4's declaration does not read it as
// egress, so a script's own call to a host stays undeclared.
func TestABrowserIsItsOwnPolicyTokenNotNetwork(t *testing.T) {
	for _, b := range []string{siteBrowser, publicBrowser} {
		got := declaredCaps([]byte(browserManifest(b)))
		if !got["browser"] || got["network"] || len(got) != 1 {
			t.Fatalf("%s: declaredCaps = %v; want browser alone", b, got)
		}
		if d := declarationOf([]byte(browserManifest(b))); d.EgressAny || len(d.Egress) != 0 {
			t.Fatalf("%s: S4's declaration reads the browser as egress: %+v", b, d)
		}
	}
	if got := declaredCaps([]byte(browserManifest(`null`))); got["browser"] {
		t.Fatalf("a null browser is declared: %v", got)
	}
}

// TestABrowserOfAnOddShapeLeavesTheRestDeclared: a browser value that
// does not decode is still a
// browser, and the other capabilities still read.
func TestABrowserOfAnOddShapeLeavesTheRestDeclared(t *testing.T) {
	mj := []byte(`{"schemaVersion":"2","name":"x","capabilities":{"browser":{"scope":7},` +
		`"network":{"egress":["api.example.com"]},"secrets":["API_KEY"],"exec":{"commands":["jq"]}}}`)
	got := declaredCaps(mj)
	for _, c := range []string{"browser", "network", "env", "exec"} {
		if !got[c] {
			t.Fatalf("declaredCaps = %v; want %s among them", got, c)
		}
	}
	if d := declarationOf(mj); len(d.Egress) != 1 || len(d.Secrets) != 1 {
		t.Fatalf("S4's declaration lost the other lines: %+v", d)
	}
}

// TestS6StillFlagsAScriptsOwnCallWithABrowserDeclared: the browser reaches
// its sites through the runner's browse proxy; a support script that calls
// the same host itself is still the release's own network.
func TestS6StillFlagsAScriptsOwnCallWithABrowserDeclared(t *testing.T) {
	files := map[string]string{
		"AGENT.md":  "# Site tester\n\nRun check.sh first.\n",
		"check.sh":  "#!/bin/sh\ncurl -s https://fonts.googleapis.com/css2?family=Inter\n",
		"README.md": "Tests a website.\n",
	}
	got := s6Run(t, browserManifest(siteBrowser), files)
	if f, ok := got["S6/undeclared-network"]; !ok || f.Severity != SevHigh {
		t.Fatalf("undeclared-network = %+v (ok %v); a browser host must not clear a script's own curl", f, ok)
	}
}

// TestUnrestrictedNetworkIsWildcardEgressOrAPublicBrowser: what the
// orchestrator hands the gate as WildcardEgress.
func TestUnrestrictedNetworkIsWildcardEgressOrAPublicBrowser(t *testing.T) {
	for _, c := range []struct {
		manifest string
		want     bool
	}{
		{browserManifest(siteBrowser), false},
		{browserManifest(publicBrowser), true},
		{browserManifest(`{"sites":["site"],"scope":"site"}`), false},
		{`{"schemaVersion":"2","name":"x","capabilities":{"network":{"egress":["*"]}}}`, true},
		{`{"schemaVersion":"2","name":"x","capabilities":{"network":{"egress":["api.example.com"]}}}`, false},
		{`{"schemaVersion":"2","name":"x","capabilities":{"network":{"egress":"none"}}}`, false},
		{`not json`, false},
		// A browser line that does not read is held the strict way.
		{browserManifest(`"public"`), true},
		{browserManifest(`{"scope":7}`), true},
	} {
		if got := unrestrictedNetwork([]byte(c.manifest)); got != c.want {
			t.Errorf("unrestrictedNetwork(%s) = %v; want %v", c.manifest, got, c.want)
		}
	}
}

// TestAPublicBrowserIsHeldAsWildcardEgress: under the baseline a
// site-scoped browser publishes and a public one goes to review; a policy
// that rejects "*" egress rejects it; a policy may name browser in
// whenCapabilities.
func TestAPublicBrowserIsHeldAsWildcardEgress(t *testing.T) {
	gate := func(p Policy, manifest string) GateDecision {
		mj := []byte(manifest)
		return Evaluate(GateInput{Policy: p, DeclaredCapabilities: declaredCaps(mj), WildcardEgress: unrestrictedNetwork(mj)})
	}
	if d := gate(DefaultBaseline(), browserManifest(siteBrowser)); d.Outcome != OutcomePublish {
		t.Fatalf("a site-scoped browser under the baseline: %+v", d)
	}
	d := gate(DefaultBaseline(), browserManifest(publicBrowser))
	if d.Outcome != OutcomeNeedsReview || d.branch != branchWildcardEgressReview || !strings.Contains(d.Reason, "any public site") {
		t.Fatalf("a public browser under the baseline: %+v", d)
	}
	reject := DefaultBaseline()
	reject.WildcardEgress = "reject"
	if d := gate(reject, browserManifest(publicBrowser)); d.Outcome != OutcomeRejected || d.branch != branchWildcardEgressReject {
		t.Fatalf("a public browser under wildcardEgress: reject: %+v", d)
	}
	strict := DefaultBaseline()
	strict.RequireHumanReview = json.RawMessage(`{"whenCapabilities":["browser"]}`)
	if d := gate(strict, browserManifest(siteBrowser)); d.Outcome != OutcomeNeedsReview || !strings.Contains(d.Reason, "browser") {
		t.Fatalf("a policy that names browser: %+v", d)
	}
}

// TestABrowserIsAWideningAndAPolicyCanBlockIt: a release that adds a
// browser after one without draws S9's capability-widened finding, and a
// namespace whose policy blocks browser refuses the submission.
func TestABrowserIsAWideningAndAPolicyCanBlockIt(t *testing.T) {
	in := &Input{
		PrevManifestJSON: []byte(`{"schemaVersion":"2","name":"site-tester","capabilities":{}}`),
		ManifestJSON:     []byte(browserManifest(siteBrowser)),
	}
	var widened []Finding
	for _, f := range s9ManifestDiff(in) {
		if f.Scanner == "S9/capability-widened" {
			widened = append(widened, f)
		}
	}
	if len(widened) != 1 || widened[0].Detail["capability"] != "browser" || widened[0].Severity != SevMedium {
		t.Fatalf("S9 on an added browser: %+v", widened)
	}

	sub := registry.PolicySubmission{ManifestJSON: []byte(browserManifest(siteBrowser))}
	if issues := CheckSubmissionPolicy(Policy{BlockedCapabilities: []string{"browser"}}, sub); len(issues) != 1 || !strings.Contains(issues[0].Error(), `"browser"`) {
		t.Fatalf("a policy blocking browser: %v", issues)
	}
	if issues := CheckSubmissionPolicy(Policy{BlockedCapabilities: []string{"network"}}, sub); len(issues) != 0 {
		t.Fatalf("a policy blocking network refuses a browser: %v", issues)
	}
}
