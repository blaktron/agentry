package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
)

// Target hosts in the pipeline.
// A declared target host is not a finding and does not route a release to
// review; the scanners' bar for SSH the release makes itself does not move;
// and an exec declaration naming an SSH client is pointed at targetHosts,
// low.

// targetHostManifest is a canonical manifest that declares one target host
// and the given exec block.
func targetHostManifest(exec string) string {
	return `{"schemaVersion":"2","name":"server-helper","summary":"Sets up and manages a Linux server",` +
		`"intake":[{"id":"server","prompt":"The server to set up","type":"host","required":true}],` +
		`"capabilities":{"targetHosts":["server"],"exec":` + exec + `}}`
}

// TestS6StillFlagsAScriptsOwnSSHWithATargetHostDeclared: a support script
// that runs ssh, scp or sftp is the release making its own connection, so
// a declared target host changes nothing S6 reports.
func TestS6StillFlagsAScriptsOwnSSHWithATargetHostDeclared(t *testing.T) {
	files := map[string]string{
		"AGENT.md":  "# Server helper\n\nRun deploy.sh to push the config.\n",
		"deploy.sh": "#!/bin/sh\nscp ./site.conf prod.example.com:/etc/nginx/\nssh -l admin prod.example.com 'systemctl reload nginx'\n",
	}
	got := s6Run(t, targetHostManifest(`"none"`), files)
	for _, want := range []string{"S6/script-without-exec", "S6/undeclared-network"} {
		if f, ok := got[want]; !ok || f.Severity != SevHigh {
			t.Fatalf("%s = %+v (ok %v); a target host must not clear a script's own ssh", want, f, ok)
		}
	}
	if f := got["S6/undeclared-network"]; !strings.Contains(f.Title, "prod.example.com") {
		t.Fatalf("undeclared-network = %+v", f)
	}

	got = s6Run(t, targetHostManifest(`{"commands":["sh"]}`), files)
	if f, ok := got["S6/undeclared-network"]; !ok || f.Severity != SevHigh {
		t.Fatalf("with exec declared, undeclared-network = %+v (ok %v)", f, ok)
	}
}

// TestATargetHostIsItsOwnPolicyTokenNotNetwork: the gate and policy read
// targetHosts as its own capability, never as network egress.
func TestATargetHostIsItsOwnPolicyTokenNotNetwork(t *testing.T) {
	got := declaredCaps([]byte(targetHostManifest(`"none"`)))
	if !got["targetHosts"] || got["network"] || got["exec"] {
		t.Fatalf("declaredCaps = %v; want targetHosts alone", got)
	}
	if d := declarationOf([]byte(targetHostManifest(`"none"`))); d.EgressAny || len(d.Egress) != 0 {
		t.Fatalf("S4's declaration reads a target host as egress: %+v", d)
	}
}

// TestDeclaringATargetHostDoesNotRouteToReview: under the platform
// baseline a release whose only notable declaration is a target host
// publishes, as "*" egress would not; a policy may still ask for review of
// it by name.
func TestDeclaringATargetHostDoesNotRouteToReview(t *testing.T) {
	decl := declaredCaps([]byte(targetHostManifest(`"none"`)))
	d := Evaluate(GateInput{Policy: DefaultBaseline(), DeclaredCapabilities: decl, WildcardEgress: egressSet([]byte(targetHostManifest(`"none"`)))["*"]})
	if d.Outcome != OutcomePublish {
		t.Fatalf("a declared target host under the baseline: %+v", d)
	}
	strict := DefaultBaseline()
	strict.RequireHumanReview = json.RawMessage(`{"whenCapabilities":["targetHosts"]}`)
	if d := Evaluate(GateInput{Policy: strict, DeclaredCapabilities: decl}); d.Outcome != OutcomeNeedsReview || !strings.Contains(d.Reason, "targetHosts") {
		t.Fatalf("a policy that names targetHosts: %+v", d)
	}
}

// TestS1PointsAnSSHClientInExecAtTargetHosts: exec naming ssh, scp, sftp or
// rsync draws one low finding naming them; any other exec draws none.
func TestS1PointsAnSSHClientInExecAtTargetHosts(t *testing.T) {
	run := func(exec string) []Finding {
		in := &Input{Dir: t.TempDir(), ManifestJSON: []byte(targetHostManifest(exec))}
		var out []Finding
		for _, f := range (S1Inventory{}).Run(stageContext{ctx: context.Background()}, in).Findings {
			if f.Scanner == scannerExecRemoteClient {
				out = append(out, f)
			}
		}
		return out
	}
	got := run(`{"commands":["git","ssh","rsync"]}`)
	if len(got) != 1 || got[0].Severity != SevLow || !strings.Contains(got[0].Title, "ssh, rsync") || !strings.Contains(got[0].Title, "capabilities.targetHosts") {
		t.Fatalf("exec ssh, rsync: %+v", got)
	}
	// It points at the manifest, names the commands and the target hosts
	// already declared, and is certain of what it says.
	if got[0].FilePath != "agent.yaml" || got[0].Confidence != ConfHigh || fmt.Sprint(got[0].Detail["commands"]) != "[ssh rsync]" || fmt.Sprint(got[0].Detail["declaredTargetHosts"]) != "[server]" {
		t.Fatalf("exec ssh, rsync: %s %s %+v", got[0].FilePath, got[0].Confidence, got[0].Detail)
	}
	for _, exec := range []string{`"none"`, `{"commands":["git","sshpass-free"]}`} {
		if got := run(exec); len(got) != 0 {
			t.Fatalf("exec %s: %+v", exec, got)
		}
	}
}

// TestATargetHostIsAWideningAndAPolicyCanBlockIt: a release that adds a
// target host after one without draws S9's capability-widened finding, as
// any newly declared capability does, and a namespace whose policy blocks
// targetHosts refuses the submission.
func TestATargetHostIsAWideningAndAPolicyCanBlockIt(t *testing.T) {
	in := &Input{
		PrevManifestJSON: []byte(`{"schemaVersion":"2","name":"server-helper","capabilities":{}}`),
		ManifestJSON:     []byte(targetHostManifest(`"none"`)),
	}
	var widened []Finding
	for _, f := range s9ManifestDiff(in) {
		if f.Scanner == "S9/capability-widened" {
			widened = append(widened, f)
		}
	}
	if len(widened) != 1 || widened[0].Detail["capability"] != "targetHosts" || widened[0].Severity != SevMedium {
		t.Fatalf("S9 on an added target host: %+v", widened)
	}

	issues := CheckSubmissionPolicy(Policy{BlockedCapabilities: []string{"targetHosts"}}, registry.PolicySubmission{ManifestJSON: []byte(targetHostManifest(`"none"`))})
	if len(issues) != 1 || !strings.Contains(issues[0].Error(), `"targetHosts"`) {
		t.Fatalf("a policy blocking targetHosts: %v", issues)
	}
	if issues := CheckSubmissionPolicy(Policy{BlockedCapabilities: []string{"network"}}, registry.PolicySubmission{ManifestJSON: []byte(targetHostManifest(`"none"`))}); len(issues) != 0 {
		t.Fatalf("a policy blocking network refuses a target host: %v", issues)
	}
}
