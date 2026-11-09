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

// TestRenameFrontmatterRewritesTheNameLineAlone: a fork under another name
// has its instruction's frontmatter name rewritten, every other byte kept;
// a file with no frontmatter, no name or the same name is left as it is.
func TestRenameFrontmatterRewritesTheNameLineAlone(t *testing.T) {
	in := "---\nname: seo-page-check   # the skill's name\ndescription: \"Checks a page.\"\nmetadata:\n  name: inner\n---\n# SEO page check\n\nname: not frontmatter\n"
	out, changed, err := RenameFrontmatter([]byte(in), "my-fork")
	if err != nil || !changed {
		t.Fatalf("changed %v, %v", changed, err)
	}
	want := strings.Replace(in, "name: seo-page-check   # the skill's name", "name: my-fork", 1)
	if string(out) != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
	if fm, _, _ := ParseFrontmatter(out); fm.Name != "my-fork" || fm.Description != "Checks a page." {
		t.Fatalf("frontmatter after: %+v", fm)
	}
	crlf := strings.ReplaceAll("---\nname: 'seo'\n---\nBody\n", "\n", "\r\n")
	if out, changed, err := RenameFrontmatter([]byte(crlf), "fork"); err != nil || !changed || string(out) != strings.Replace(crlf, "name: 'seo'", "name: fork", 1) {
		t.Fatalf("CRLF: %q %v %v", out, changed, err)
	}
	for _, same := range []string{"No frontmatter.\n", "---\ndescription: x\n---\nBody\n", "---\nname: fork\n---\nBody\n"} {
		if out, changed, err := RenameFrontmatter([]byte(same), "fork"); err != nil || changed || string(out) != same {
			t.Errorf("%q: changed %v, %v", same, changed, err)
		}
	}
	if _, _, err := RenameFrontmatter([]byte("---\nname: >\n  seo\n---\n"), "fork"); err == nil {
		t.Error("a block scalar name was rewritten")
	}
}
