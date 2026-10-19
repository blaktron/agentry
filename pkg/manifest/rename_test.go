package manifest

import (
	"strings"
	"testing"
)

func TestRenameSetsTheNamespaceAndNameAndKeepsTheRest(t *testing.T) {
	raw := []byte(`# A comment the fork keeps.
schemaVersion: "2"
name: summarize
namespace: alice
modes: [autonomous]
version: 1.2.0
summary: "Summarizes: politely"
entrypoints:
  instruction: SKILL.md
`)
	out, err := Rename(raw, "bob", "summarize-fork")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(out)
	if err != nil {
		t.Fatalf("the renamed manifest does not parse: %v\n%s", err, out)
	}
	if m.Namespace != "bob" || m.Name != "summarize-fork" {
		t.Fatalf("got %s/%s, want bob/summarize-fork", m.Namespace, m.Name)
	}
	if m.Version != "1.2.0" || m.Summary != "Summarizes: politely" || m.SchemaVersion != "2" {
		t.Fatalf("the rest changed: %+v", m)
	}
	if len(m.Modes) != 1 || m.Modes[0] != ModeAutonomous || m.Entrypoints.Instruction != "SKILL.md" {
		t.Fatalf("modes or the instruction entrypoint changed: %+v %+v", m.Modes, m.Entrypoints)
	}
	if !strings.Contains(string(out), "# A comment the fork keeps.") {
		t.Fatalf("the comment is gone:\n%s", out)
	}
}

func TestRenameAddsAMissingKeyInOrder(t *testing.T) {
	out, err := Rename([]byte("schemaVersion: \"2\"\nversion: 1.0.0\n"), "bob", "x")
	if err != nil {
		t.Fatal(err)
	}
	want := "schemaVersion: \"2\"\nnamespace: bob\nname: x\nversion: 1.0.0\n"
	if string(out) != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
}

func TestRenameQuotesAValueYAMLWouldReadOtherwise(t *testing.T) {
	// A name of digits would read back as a number without the string tag.
	out, err := Rename([]byte("schemaVersion: \"2\"\nnamespace: a\nname: b\n"), "bob", "1234")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(out)
	if err != nil {
		t.Fatalf("does not parse: %v\n%s", err, out)
	}
	if m.Name != "1234" {
		t.Fatalf("name is %q", m.Name)
	}
	// Parse fills a string from a bare number too, so the quoting is only
	// visible in the text itself.
	if !strings.Contains(string(out), "\nname: \"1234\"\n") {
		t.Fatalf("an existing digit-only name is not quoted:\n%s", out)
	}
	// An inserted key is quoted the same way.
	out, err = Rename([]byte("schemaVersion: \"2\"\nversion: 1.0.0\n"), "5678", "1234")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "\nnamespace: \"5678\"\n") || !strings.Contains(string(out), "\nname: \"1234\"\n") {
		t.Fatalf("an inserted digit-only namespace or name is not quoted:\n%s", out)
	}
}

func TestRenameRefusesWhatIsNotAMapping(t *testing.T) {
	for _, raw := range []string{"- a\n- b\n", "just text\n"} {
		if _, err := Rename([]byte(raw), "bob", "x"); err == nil {
			t.Errorf("%q: renamed", raw)
		}
	}
}
