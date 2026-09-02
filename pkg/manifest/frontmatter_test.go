package manifest

import (
	"errors"
	"strings"
	"testing"
)

func TestParseFrontmatter(t *testing.T) {
	fm, ok, err := ParseFrontmatter([]byte("---\nname: other\ndescription: |\n  Does the thing.\nextra: 1\n---\n# body\n"))
	if err != nil || !ok || fm.Name != "other" || fm.Description != "Does the thing." || strings.Join(fm.Keys, ",") != "description,extra,name" {
		t.Fatalf("%+v %v %v", fm, ok, err)
	}
	if _, ok, _ := ParseFrontmatter([]byte("# no frontmatter\n---\nname: x\n")); ok {
		t.Fatal("frontmatter must open the file")
	}
	if _, ok, err := ParseFrontmatter([]byte("---\nname: x\n\nno terminator\n")); !ok || err == nil {
		t.Fatal("unterminated block must be reported")
	}
	if _, ok, err := ParseFrontmatter([]byte("---\n: : :\n---\n")); !ok || err == nil {
		t.Fatal("invalid yaml must be reported")
	}
	if fm, ok, err := ParseFrontmatter([]byte("\xef\xbb\xbf---\r\nname: bom\r\n---\r\n")); err != nil || !ok || fm.Name != "bom" {
		t.Fatalf("BOM/CRLF: %+v %v %v", fm, ok, err)
	}
}

func v9Context(files map[string]string) Context {
	var infos []FileInfo
	for p, c := range files {
		infos = append(infos, FileInfo{Path: p, Size: int64(len(c))})
	}
	return Context{
		Namespace: "acme", Name: "hello", Files: infos,
		ReadFile: func(p string) ([]byte, error) {
			c, ok := files[p]
			if !ok {
				return nil, errors.New("missing")
			}
			return []byte(c), nil
		},
	}
}

func v9Manifest() *Manifest {
	m, err := Parse([]byte("schemaVersion: \"1\"\nname: hello\nnamespace: acme\nkind: skill\nversion: 1.0.0\nsummary: \"Says hello politely\"\nentrypoints:\n  skill: SKILL.md\npublish:\n  include: [agent.yaml, SKILL.md]\n"))
	if err != nil {
		panic(err)
	}
	return m
}

func v9Issues(list []error) []*Issue {
	var out []*Issue
	for _, e := range list {
		if i, ok := AsIssue(e); ok && i.Rule == "V9" {
			out = append(out, i)
		}
	}
	return out
}

func TestV9FrontmatterContradictsManifest(t *testing.T) {
	m := v9Manifest()
	// Name mismatch: blocking. Description mismatch: warning.
	got := v9Issues(ValidateInContext(m, v9Context(map[string]string{
		"agent.yaml": "x", "SKILL.md": "---\nname: totally-different\ndescription: Deletes everything\n---\n# hello\n",
	})))
	if len(got) != 2 || IsWarning(got[0]) || !IsWarning(got[1]) {
		t.Fatalf("expected a V9 error (name) and a V9 warning (description): %+v", got)
	}
	// Matching frontmatter (modulo wrapping/case) is clean.
	got = v9Issues(ValidateInContext(m, v9Context(map[string]string{
		"agent.yaml": "x", "SKILL.md": "---\nname: hello\ndescription: |\n  Says hello\n  politely\n---\n",
	})))
	if len(got) != 0 {
		t.Fatalf("matching frontmatter must be clean: %+v", got)
	}
	// No frontmatter, or no reader: nothing to say.
	if got := v9Issues(ValidateInContext(m, v9Context(map[string]string{"agent.yaml": "x", "SKILL.md": "# hello\n"}))); len(got) != 0 {
		t.Fatalf("no frontmatter: %+v", got)
	}
	ctx := v9Context(map[string]string{"agent.yaml": "x", "SKILL.md": "---\nname: nope\n---\n"})
	ctx.ReadFile = nil
	if got := v9Issues(ValidateInContext(m, ctx)); len(got) != 0 {
		t.Fatalf("no reader must skip V9: %+v", got)
	}
	// Malformed block: warning, not a rejection.
	got = v9Issues(ValidateInContext(m, v9Context(map[string]string{"agent.yaml": "x", "SKILL.md": "---\nname: x\nnever closed\n"})))
	if len(got) != 1 || !IsWarning(got[0]) {
		t.Fatalf("malformed block: %+v", got)
	}
}
