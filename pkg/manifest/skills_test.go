package manifest

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A QuickAgent that ships skills: capabilities.skills (V20) with its
// skills/ folder. These tests pin the key's refusals and passes, the
// folder and frontmatter checks, and that the key is in the contract and
// the capability diff.

const skillsYAML = `schemaVersion: "2"
name: triage
namespace: alice
version: 1.0.0
summary: "Triages the issues you give it"
license: MIT
modes: [autonomous]

capabilities:
  network:
    egress: none
  skills: true

publish:
  include: [agent.yaml, README.md, AGENT.md, LICENSE, skills/**]
`

func skillsManifest(t *testing.T) *Manifest {
	t.Helper()
	return mustParse(t, skillsYAML)
}

// skillsContext is a publish context under which skillsManifest validates
// with no issue at all; files replaces or, with "", removes a file.
func skillsContext(files map[string]string) Context {
	all := map[string]string{
		"agent.yaml":                "x",
		"README.md":                 "# Triage",
		"AGENT.md":                  "Triage each issue with the triage skill.",
		"LICENSE":                   "MIT",
		"skills/triage/SKILL.md":    "---\nname: triage\ndescription: Sort an issue into bug, feature or question, with a priority\n---\nRead the issue, then...",
		"skills/triage/labels.md":   "bug, feature, question",
		"skills/reproduce/SKILL.md": "---\nname: reproduce\ndescription: \"Reproduce a reported bug: steps, expected, actual\"\n---\nWrite the steps.",
	}
	for k, v := range files {
		if v == "" {
			delete(all, k)
			continue
		}
		all[k] = v
	}
	var infos []FileInfo
	for p, c := range all {
		infos = append(infos, FileInfo{Path: p, Size: int64(len(c)), IsText: true})
	}
	return Context{
		Namespace: "alice", Name: "triage", Public: true, Files: infos,
		ReadFile: func(p string) ([]byte, error) {
			if c, ok := all[p]; ok {
				return []byte(c), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

func TestAReleaseThatShipsSkillsParsesValidatesAndRoundTrips(t *testing.T) {
	m := skillsManifest(t)
	if !m.Capabilities.Skills || !m.ShipsSkills() {
		t.Fatalf("capabilities.skills not read: %+v", m.Capabilities)
	}
	wantClean(t, Validate(m))
	wantClean(t, ValidateInContext(m, skillsContext(nil)))

	canon, err := CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(canon), `"skills":true`) {
		t.Fatalf("canonical form drops the key: %s", canon)
	}
	var back Manifest
	if err := json.Unmarshal(canon, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Capabilities.Skills {
		t.Fatal("the key does not survive the canonical round trip")
	}
	if !m.Contract().Skills {
		t.Fatal("the contract leaves the key out")
	}
}

func TestAReleaseWithoutTheKeyEncodesAsBefore(t *testing.T) {
	m := skillsManifest(t)
	m.Capabilities.Skills = false
	canon, err := CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canon), `"skills":`) {
		t.Fatalf("an undeclared key is written: %s", canon)
	}
	if m.ShipsSkills() {
		t.Fatal("ShipsSkills without either key")
	}
}

func TestV20RefusesTheKeyWhereItCannotMeanAnything(t *testing.T) {
	// A v1 manifest has no such field.
	m := skillsManifest(t)
	m.SchemaVersion = "1"
	m.Modes, m.Kind = nil, v1KindPromptAgent
	wantIssue(t, Validate(m), "V1", SeverityError, "capabilities.skills")

	// A persistent agent declares its skills in its own block, and never
	// in both places.
	p := persistentManifest(t)
	p.Capabilities.Skills = true
	errs := Validate(p)
	wantIssue(t, errs, "V20", SeverityError, "capabilities.skills")
	if !strings.Contains(issueStrings(errs), "both") {
		t.Fatalf("declaring both is not named as such:%s", issueStrings(errs))
	}

	p = persistentManifest(t)
	p.Capabilities.Skills, p.Capabilities.Persistent.Skills = true, false
	errs = Validate(p)
	wantIssue(t, errs, "V20", SeverityError, "capabilities.skills")
	if !strings.Contains(issueStrings(errs), "capabilities.persistent.skills") {
		t.Fatalf("the refusal does not name the persistent key:%s", issueStrings(errs))
	}
	if !p.ShipsSkills() {
		t.Fatal("ShipsSkills ignores capabilities.skills")
	}
	if !persistentManifest(t).ShipsSkills() {
		t.Fatal("ShipsSkills ignores capabilities.persistent.skills")
	}
}

func TestV20WarnsOfASkillsFolderWithoutTheKey(t *testing.T) {
	m := skillsManifest(t)
	m.Capabilities.Skills = false
	errs := ValidateInContext(m, skillsContext(nil))
	wantIssue(t, errs, "V20", SeverityWarning, "publish.include")
	if len(Blocking(errs)) != 0 {
		t.Fatalf("a folder without the key blocks: %s", issueStrings(errs))
	}
	if !strings.Contains(issueStrings(errs), "capabilities.skills") {
		t.Fatalf("the warning does not name the key:%s", issueStrings(errs))
	}

	// A folder the include leaves out is not shipped and not reported.
	m.Publish.Include = []string{"agent.yaml", "README.md", "AGENT.md", "LICENSE"}
	for _, err := range ValidateInContext(m, skillsContext(nil)) {
		if is, _ := AsIssue(err); is != nil && is.Rule == "V20" {
			t.Fatalf("a skills/ folder the archive does not ship is reported: %v", is)
		}
	}
}

func TestV20RefusesASkillTheRunnerCouldNotList(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		says  string
	}{
		{"a skill without SKILL.md", map[string]string{"skills/triage/SKILL.md": ""}, "skills/triage/ has no SKILL.md"},
		{"a file beside the folders", map[string]string{"skills/README.md": "x"}, "skills/README.md"},
		{"no frontmatter", map[string]string{"skills/triage/SKILL.md": "Read the issue."}, "skills/triage/SKILL.md has no frontmatter"},
		{"frontmatter that does not parse", map[string]string{"skills/triage/SKILL.md": "---\nname: [triage\n---\nx"}, "skills/triage/SKILL.md"},
		{"frontmatter never closed", map[string]string{"skills/triage/SKILL.md": "---\nname: triage\n"}, "skills/triage/SKILL.md"},
		{"a name that differs from its folder", map[string]string{"skills/triage/SKILL.md": "---\nname: sort\ndescription: Sort\n---\nx"}, `name "sort" differs from its folder "triage"`},
		{"no name", map[string]string{"skills/triage/SKILL.md": "---\ndescription: Sort\n---\nx"}, `name "" differs from its folder "triage"`},
		{"no description", map[string]string{"skills/triage/SKILL.md": "---\nname: triage\n---\nx"}, "skills/triage/SKILL.md has no description"},
		{"a description too long", map[string]string{"skills/triage/SKILL.md": "---\nname: triage\ndescription: " + strings.Repeat("a", MaxSkillDescriptionBytes+1) + "\n---\nx"}, "description"},
		{"a description with an escape", map[string]string{"skills/triage/SKILL.md": "---\nname: triage\ndescription: \"Sort\\e[31m\"\n---\nx"}, "U+001B"},
		{"a description over two lines", map[string]string{"skills/triage/SKILL.md": "---\nname: triage\ndescription: |\n  Sort\n  issues\n---\nx"}, "U+000A"},
		{"a folder name the runner cannot list", map[string]string{"skills/Triage_Bot/SKILL.md": "---\nname: Triage_Bot\ndescription: Sort\n---\nx"}, `"Triage_Bot"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := ValidateInContext(skillsManifest(t), skillsContext(c.files))
			wantIssue(t, errs, "V20", SeverityError, "publish.include")
			if !strings.Contains(issueStrings(errs), c.says) {
				t.Fatalf("the refusal does not say %q:%s", c.says, issueStrings(errs))
			}
		})
	}

	// A skills/ folder the include leaves out is named as such.
	m := skillsManifest(t)
	m.Publish.Include = []string{"agent.yaml", "README.md", "AGENT.md", "LICENSE"}
	errs := ValidateInContext(m, skillsContext(nil))
	wantIssue(t, errs, "V20", SeverityError, "publish.include")
	if !strings.Contains(issueStrings(errs), "leaves skills/ out") {
		t.Fatalf("a folder left out of the include is not named:%s", issueStrings(errs))
	}

	// The key with no skill in the archive grants nothing.
	errs = ValidateInContext(skillsManifest(t), skillsContext(map[string]string{
		"skills/triage/SKILL.md": "", "skills/triage/labels.md": "", "skills/reproduce/SKILL.md": "",
	}))
	wantIssue(t, errs, "V20", SeverityError, "capabilities.skills")

	// At most MaxShippedSkills.
	many := map[string]string{}
	for i := 0; i <= MaxShippedSkills; i++ {
		name := "s" + strings.Repeat("x", i)
		many["skills/"+name+"/SKILL.md"] = "---\nname: " + name + "\ndescription: One more\n---\nx"
	}
	errs = ValidateInContext(skillsManifest(t), skillsContext(many))
	wantIssue(t, errs, "V20", SeverityError, "publish.include")
	if !strings.Contains(issueStrings(errs), "the maximum is") {
		t.Fatalf("too many skills is not refused as such:%s", issueStrings(errs))
	}
}

func TestV20LeavesAPersistentAgentsSkillsToV16(t *testing.T) {
	// A persistent agent's skill without frontmatter is V16's business as
	// it was: no V20 issue, and no new refusal.
	errs := ValidateInContext(persistentManifest(t), persistentContext(map[string]string{
		"skills/weekly-plan/SKILL.md": "Plan the week.",
	}))
	for _, err := range errs {
		if is, _ := AsIssue(err); is != nil && is.Rule == "V20" {
			t.Fatalf("V20 reads a persistent agent's skills: %v", is)
		}
	}
	wantClean(t, errs)
}

func TestTheDiffAsksAgainForSkills(t *testing.T) {
	without := skillsManifest(t)
	without.Capabilities.Skills = false
	with := skillsManifest(t)

	d := DiffCapabilities(without.Contract(), with.Contract())
	if !d.HasWidened() || !strings.Contains(strings.Join(d.Widened, "\n"), ShippedSkillsWords) {
		t.Fatalf("adding skills does not ask again in their words: %+v", d)
	}
	d = DiffCapabilities(with.Contract(), without.Contract())
	if d.HasWidened() || len(d.Narrowed) != 1 {
		t.Fatalf("dropping skills: %+v", d)
	}
	if d := DiffCapabilities(with.Contract(), with.Contract()); !d.Empty() {
		t.Fatalf("the same contract differs: %+v", d)
	}
}
