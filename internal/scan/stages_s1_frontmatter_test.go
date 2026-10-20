package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestS1FrontmatterFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: other-skill\ndescription: Wipes the disk\n---\n# hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := &Input{Dir: dir, ManifestJSON: []byte(`{"name":"hello","summary":"Says hello politely","entrypoints":{"skill":"SKILL.md"}}`)}
	res := S1Inventory{}.Run(stageContext{ctx: context.Background()}, in)
	var name, desc bool
	for _, f := range res.Findings {
		switch f.Scanner {
		case "S1/frontmatter-name-mismatch":
			name = f.Detail["frontmatter"] == "other-skill" && f.FilePath == "SKILL.md"
		case "S1/frontmatter-description-differs":
			desc = f.Excerpt == "Wipes the disk"
		}
	}
	if !name || !desc {
		t.Fatalf("expected both frontmatter findings: %+v", res.Findings)
	}

	// Consistent frontmatter, or none: no findings.
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: hello\ndescription: says HELLO politely\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res = S1Inventory{}.Run(stageContext{ctx: context.Background()}, in)
	for _, f := range res.Findings {
		if f.Scanner == "S1/frontmatter-name-mismatch" || f.Scanner == "S1/frontmatter-description-differs" {
			t.Fatalf("consistent frontmatter must be clean: %+v", f)
		}
	}

	// Who is flagged, how severely, where, and with what evidence; which file
	// is the entry; and what is never compared.
	check := func(manifestJSON string, files ...FileEntry) []Finding {
		return s1Frontmatter(&Input{ManifestJSON: []byte(manifestJSON), Files: files})
	}
	text := func(path, content string) FileEntry {
		return FileEntry{Path: path, IsText: true, Content: []byte(content)}
	}
	const mismatch = "---\nname: other-skill\ndescription: Wipes the disk\n---\nbody\n"
	v1 := `{"name":"hello","summary":"Says hello politely","entrypoints":{"skill":"SKILL.md"}}`
	got := check(v1, text("SKILL.md", mismatch))
	if len(got) != 2 {
		t.Fatalf("v1 skill: %+v", got)
	}
	for _, f := range got {
		if f.FilePath != "SKILL.md" || f.LineStart != 1 || f.LineEnd != 1 || f.Confidence != ConfHigh {
			t.Errorf("%s: place %s:%d-%d, confidence %s", f.Scanner, f.FilePath, f.LineStart, f.LineEnd, f.Confidence)
		}
		switch f.Scanner {
		case "S1/frontmatter-name-mismatch":
			if f.Severity != SevMedium || f.Detail["frontmatter"] != "other-skill" || f.Detail["manifest"] != "hello" {
				t.Errorf("name mismatch = %s %+v", f.Severity, f.Detail)
			}
		case "S1/frontmatter-description-differs":
			if f.Severity != SevLow || f.Excerpt != "Wipes the disk" || f.Detail["summary"] != "Says hello politely" {
				t.Errorf("description differs = %s %q %+v", f.Severity, f.Excerpt, f.Detail)
			}
		default:
			t.Errorf("unexpected finding %s", f.Scanner)
		}
	}

	// A schema 2 manifest reads AGENT.md unless it names another instruction
	// file, and only the file it names, by its exact path.
	v2 := `{"schemaVersion":"2","name":"hello","summary":"Says hello politely"}`
	if got := check(v2, text("AGENT.md", mismatch)); len(got) != 2 || got[0].FilePath != "AGENT.md" {
		t.Errorf("v2 default instruction: %+v", got)
	}
	if got := check(v2, text("docs/AGENT.md", mismatch)); len(got) != 0 {
		t.Errorf("a file merely ending in AGENT.md was read: %+v", got)
	}
	named := `{"schemaVersion":"2","name":"hello","summary":"Says hello politely","entrypoints":{"instruction":"docs/INSTR.md"}}`
	if got := check(named, text("AGENT.md", mismatch), text("docs/INSTR.md", mismatch)); len(got) != 2 || got[0].FilePath != "docs/INSTR.md" {
		t.Errorf("named instruction: %+v", got)
	}
	if got := check(named, text("AGENT.md", mismatch)); len(got) != 0 {
		t.Errorf("AGENT.md was read although the manifest names another file: %+v", got)
	}
	if got := check(named, text("a/docs/INSTR.md", mismatch)); len(got) != 0 {
		t.Errorf("a file merely ending in the entry's path was read: %+v", got)
	}
	// Schema 1 reads the skill entry only: with none declared, nothing is read.
	if got := check(`{"name":"hello","summary":"s"}`, text("SKILL.md", mismatch)); len(got) != 0 {
		t.Errorf("a v1 manifest with no skill entry: %+v", got)
	}

	// Only a field the file sets is compared; a file that is not text, a
	// block that is not closed and a file with no block say nothing.
	if got := check(v1, text("SKILL.md", "---\ndescription: Says hello politely\n---\n")); len(got) != 0 {
		t.Errorf("a frontmatter without a name was compared: %+v", got)
	}
	if got := check(v1, text("SKILL.md", "---\nname: hello\n---\n")); len(got) != 0 {
		t.Errorf("a frontmatter without a description was compared: %+v", got)
	}
	if got := check(v1, text("SKILL.md", "---\nname: other-skill\ndescription: Wipes the disk\n")); len(got) != 0 {
		t.Errorf("an unterminated block was compared: %+v", got)
	}
	if got := check(v1, text("SKILL.md", "name: other-skill\n")); len(got) != 0 {
		t.Errorf("a file with no block was compared: %+v", got)
	}
	if got := check(v1, FileEntry{Path: "SKILL.md", IsText: false, Content: []byte(mismatch)}); len(got) != 0 {
		t.Errorf("a file that is not text was compared: %+v", got)
	}
	if got := check("{", text("SKILL.md", mismatch)); len(got) != 0 {
		t.Errorf("an unreadable manifest produced findings: %+v", got)
	}
}
