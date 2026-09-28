package draftcheck

import (
	"errors"
	"strings"
	"testing"
)

const yml = "schemaVersion: \"2\"\nname: brief\nnamespace: draft\nversion: 0.1.0\nsummary: s\nlicense: Apache-2.0\n" +
	"modes: [autonomous]\nentrypoints:\n  instruction: AGENT.md\n"

func TestReadTakesTheManifestTheInstructionAndEveryFileInOrder(t *testing.T) {
	mj, ships, instruction, files, err := Read(Package{Files: []File{
		{Path: "agent.yaml", Content: yml}, {Path: "README.md", Content: "# r"}, {Path: "AGENT.md", Content: "# i"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(mj), "{") || !strings.Contains(string(mj), `"name":"brief"`) || ships != nil || instruction != "# i" {
		t.Fatalf("read: %s %v %q", mj, ships, instruction)
	}
	var paths []string
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	if strings.Join(paths, ",") != "AGENT.md,README.md,agent.yaml" {
		t.Fatalf("files: %v", paths)
	}
}

func TestReadRefusesWhatIsNotADraftOrPastItsBounds(t *testing.T) {
	good := []File{{Path: "agent.yaml", Content: yml}, {Path: "AGENT.md", Content: "# i"}}
	for name, c := range map[string]struct {
		files    []File
		notDraft bool
	}{
		"no agent.yaml":            {[]File{{Path: "AGENT.md", Content: "x"}}, true},
		"an agent.yaml of nothing": {[]File{{Path: "agent.yaml", Content: "- not a manifest"}, {Path: "AGENT.md", Content: "x"}}, true},
		"no instruction":           {good[:1], true},
		"an absolute path":         {append(good, File{Path: "/etc/x", Content: "x"}), false},
		"a path out":               {append(good, File{Path: "../x", Content: "x"}), false},
		"an unclean path":          {append(good, File{Path: "a/../b", Content: "x"}), false},
		"a path twice":             {append(good, File{Path: "AGENT.md", Content: "x"}), false},
		"not UTF-8":                {append(good, File{Path: "x.md", Content: "\xff\xfe"}), false},
		"past the bytes":           {append(good, File{Path: "x.md", Content: strings.Repeat("x", MaxBytes)}), false},
		"past the files":           {append(good, make([]File, MaxFiles)...), false},
	} {
		_, _, _, _, err := Read(Package{Files: c.files})
		if err == nil || errors.Is(err, ErrNotADraft) != c.notDraft {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(err.Error(), "\xff") || strings.Contains(err.Error(), "not a manifest") {
			t.Fatalf("%s: the refusal quotes the package: %v", name, err)
		}
	}
}
