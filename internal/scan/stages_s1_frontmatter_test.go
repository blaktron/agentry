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
	in := &Input{Dir: dir, Kind: "skill", ManifestJSON: []byte(`{"name":"hello","summary":"Says hello politely","entrypoints":{"skill":"SKILL.md"}}`)}
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
}
