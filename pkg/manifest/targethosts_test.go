package manifest

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// Target hosts (V14): an intake question of type host, listed in
// capabilities.targetHosts, declares that the release takes a machine
// the person names at run time. These tests pin the one-to-one rule
// between the two, the bound, that choices are refused on a host
// question, that the line is part of the contract (canonical JSON, the
// capability diff), the exec hint, and the schema.

// targetHostsManifest is v2YAML with a host question and its contract line.
func targetHostsManifest(t *testing.T) *Manifest {
	t.Helper()
	y := strings.Replace(v2YAML, "\ninteractive:", `  - id: server
    prompt: "The server to set up"
    type: host
    required: true

interactive:`, 1)
	y = strings.Replace(y, "  secrets: [PAGERDUTY_TOKEN]\n", "  secrets: [PAGERDUTY_TOKEN]\n  targetHosts: [server]\n", 1)
	return mustParse(t, y)
}

// targetHostIssues are Validate's blocking issues and its V14 warnings.
func targetHostIssues(errs []error) (blocking, warnings []*Issue) {
	for _, err := range errs {
		is, ok := AsIssue(err)
		switch {
		case !ok:
			continue
		case is.Severity == SeverityError:
			blocking = append(blocking, is)
		case is.Rule == "V14":
			warnings = append(warnings, is)
		}
	}
	return blocking, warnings
}

func TestATargetHostParsesAndValidates(t *testing.T) {
	m := targetHostsManifest(t)
	hq := m.HostQuestions()
	if len(hq) != 1 || hq[0].ID != "server" || hq[0].Type != IntakeHost || !hq[0].Required {
		t.Fatalf("host questions = %+v", hq)
	}
	if hq[0].Type.IsSource() {
		t.Fatal("a host question is not an input source: it is inside the contract")
	}
	if got := m.Capabilities.TargetHosts; !slices.Equal(got, []string{"server"}) {
		t.Fatalf("targetHosts = %v", got)
	}
	if b, w := targetHostIssues(Validate(m)); len(b) != 0 || len(w) != 0 {
		t.Fatalf("a declared target host is refused or warned: %v %v", b, w)
	}
	if b := publishIssues(t, m); len(b) != 0 {
		t.Fatalf("a declared target host is refused at publish: %v", b)
	}
}

// TestV14RefusesWhatTheTwoHalvesDoNotAgreeOn: every host question is
// listed, every listed id is a host question, once, and four at most.
func TestV14RefusesWhatTheTwoHalvesDoNotAgreeOn(t *testing.T) {
	hostQ := func(id string) IntakeQuestion { return IntakeQuestion{ID: id, Prompt: "The server", Type: IntakeHost} }
	for _, c := range []struct {
		name    string
		intake  []IntakeQuestion
		targets []string
		rule    string
		path    string
		says    string
	}{
		{"a host question not listed", []IntakeQuestion{hostQ("server")}, nil,
			"V14", "intake[0].type", "not listed in capabilities.targetHosts"},
		{"an entry with no question", nil, []string{"server"},
			"V14", "capabilities.targetHosts[0]", "names no intake question of type host"},
		{"an entry naming a text question", []IntakeQuestion{{ID: "server", Prompt: "p"}}, []string{"server"},
			"V14", "capabilities.targetHosts[0]", "names no intake question of type host"},
		{"a duplicate entry", []IntakeQuestion{hostQ("server")}, []string{"server", "server"},
			"V14", "capabilities.targetHosts[1]", "duplicate target host"},
		{"five target hosts", []IntakeQuestion{hostQ("a"), hostQ("b"), hostQ("c"), hostQ("d"), hostQ("e")}, []string{"a", "b", "c", "d", "e"},
			"V14", "capabilities.targetHosts", "the maximum is 4"},
		{"choices on a host question", []IntakeQuestion{{ID: "server", Prompt: "p", Type: IntakeHost, Choices: []string{"a.example"}}}, []string{"server"},
			"V10", "intake[0].choices", "only valid for type choice"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := validV2Manifest(t)
			m.Intake = c.intake
			m.Capabilities.TargetHosts = c.targets
			errs := Validate(m)
			wantIssue(t, errs, c.rule, SeverityError, c.path)
			for _, err := range errs {
				if is, _ := AsIssue(err); is.Rule == c.rule && is.Path == c.path && strings.Contains(is.Message, c.says) {
					return
				}
			}
			t.Fatalf("no %s issue at %s saying %q:%s", c.rule, c.path, c.says, issueStrings(errs))
		})
	}

	m := validV2Manifest(t)
	m.Intake = []IntakeQuestion{hostQ("a"), hostQ("b"), hostQ("c"), hostQ("d")}
	m.Capabilities.TargetHosts = []string{"a", "b", "c", "d"}
	if b, _ := targetHostIssues(Validate(m)); len(b) != 0 {
		t.Fatalf("four target hosts are refused: %v", b)
	}
}

func TestTargetHostsIsAV2Field(t *testing.T) {
	m := validV2Manifest(t)
	m.SchemaVersion = "1"
	m.Capabilities.TargetHosts = []string{"server"}
	wantIssue(t, Validate(m), "V1", SeverityError, "capabilities.targetHosts")
}

// TestV14PointsAnSSHClientInExecAtTargetHosts: a release whose exec names
// ssh, scp, sftp or rsync would make its own connection; V14 warns, without
// failing, and says what to declare instead. The hint holds with a target
// host declared too: exec ssh is still the agent's own session.
func TestV14PointsAnSSHClientInExecAtTargetHosts(t *testing.T) {
	for _, withHost := range []bool{false, true} {
		m := validV2Manifest(t)
		if withHost {
			m = targetHostsManifest(t)
		}
		m.Capabilities.Exec = ExecCapability{Commands: []string{"git", "ssh", "/usr/bin/RSYNC", "scp", "sftp", "sshpass"}}
		b, w := targetHostIssues(Validate(m))
		if len(b) != 0 {
			t.Fatalf("an SSH client in exec is refused: %v", b)
		}
		var paths []string
		for _, is := range w {
			paths = append(paths, is.Path)
			if !strings.Contains(is.Message, "capabilities.targetHosts") {
				t.Fatalf("the hint does not name targetHosts: %v", is)
			}
		}
		want := []string{"capabilities.exec.commands[1]", "capabilities.exec.commands[2]", "capabilities.exec.commands[3]", "capabilities.exec.commands[4]"}
		if !slices.Equal(paths, want) {
			t.Fatalf("with a target host %v: hints at %v; want %v", withHost, paths, want)
		}
		if got := RemoteShellCommands(m.Capabilities); !slices.Equal(got, []string{"ssh", "/usr/bin/RSYNC", "scp", "sftp"}) {
			t.Fatalf("RemoteShellCommands = %v", got)
		}
	}
}

// TestTargetHostsIsInTheContract: the canonical JSON the registry stores
// carries the line, so the contract a person consents to, search and the
// judge's declared capabilities all read it.
func TestTargetHostsIsInTheContract(t *testing.T) {
	m := targetHostsManifest(t)
	if got := m.Contract().TargetHosts; !slices.Equal(got, []string{"server"}) {
		t.Fatalf("Contract().TargetHosts = %v", got)
	}
	raw, err := CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Capabilities struct {
			TargetHosts []string `json:"targetHosts"`
		} `json:"capabilities"`
		Intake []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"intake"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(doc.Capabilities.TargetHosts, []string{"server"}) {
		t.Fatalf("canonical capabilities.targetHosts = %v in %s", doc.Capabilities.TargetHosts, raw)
	}
	if n := len(doc.Intake); n == 0 || doc.Intake[n-1].Type != "host" {
		t.Fatalf("canonical intake = %+v", doc.Intake)
	}
	var back Manifest
	if err := json.Unmarshal(raw, &back); err != nil || !slices.Equal(back.Capabilities.TargetHosts, []string{"server"}) {
		t.Fatalf("the canonical form does not read back: %v %v", err, back.Capabilities.TargetHosts)
	}
}

// TestDiffCapabilitiesTargetHosts: an added target host is a widening, so
// an upgrade that adds one asks again; a dropped one narrows.
func TestDiffCapabilitiesTargetHosts(t *testing.T) {
	d := DiffCapabilities(Capabilities{}, Capabilities{TargetHosts: []string{"server"}})
	if !d.HasWidened() || !slices.Equal(d.Widened, []string{"asks for a target host when it runs, and can run any command on it: server"}) {
		t.Fatalf("adding a target host: %+v", d)
	}
	d = DiffCapabilities(Capabilities{TargetHosts: []string{"server"}}, Capabilities{TargetHosts: []string{"server", "backup"}})
	if !d.HasWidened() || len(d.Widened) != 1 || !strings.HasSuffix(d.Widened[0], ": backup") {
		t.Fatalf("a second target host: %+v", d)
	}
	d = DiffCapabilities(Capabilities{TargetHosts: []string{"server"}}, Capabilities{})
	if d.HasWidened() || !slices.Equal(d.Narrowed, []string{"no longer asks for a target host: server"}) {
		t.Fatalf("dropping a target host: %+v", d)
	}
	if d := DiffCapabilities(Capabilities{TargetHosts: []string{"server"}}, Capabilities{TargetHosts: []string{"server"}}); !d.Empty() {
		t.Fatalf("the same target host: %+v", d)
	}
}

// TestV2SchemaTargetHostsShape pins the JSON schema beside the Go rule.
func TestV2SchemaTargetHostsShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Capabilities struct {
				Properties map[string]struct {
					Type        string `json:"type"`
					UniqueItems bool   `json:"uniqueItems"`
					MaxItems    int    `json:"maxItems"`
					Items       struct {
						Pattern string `json:"pattern"`
					} `json:"items"`
				} `json:"properties"`
			} `json:"capabilities"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	got, ok := schema.Properties.Capabilities.Properties["targetHosts"]
	if !ok {
		t.Fatal("the v2 schema has no capabilities.targetHosts")
	}
	if got.Type != "array" || !got.UniqueItems || got.MaxItems != MaxTargetHosts || got.Items.Pattern != intakeIDRE.String() {
		t.Fatalf("targetHosts = %+v; want an array of unique intake ids, at most %d", got, MaxTargetHosts)
	}
}
