package draftcheck

import (
	"errors"
	"strings"
	"testing"
)

const yml = "schemaVersion: \"2\"\nname: brief\nnamespace: draft\nversion: 0.1.0\nsummary: s\nlicense: Apache-2.0\n" +
	"modes: [autonomous]\nentrypoints:\n  instruction: AGENT.md\n"

func TestReadTakesTheManifestTheInstructionAndEveryFileInOrder(t *testing.T) {
	rd, err := Read(Package{Files: []File{
		{Path: "agent.yaml", Content: yml}, {Path: "README.md", Content: "# r"}, {Path: "AGENT.md", Content: "# i"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(rd.ManifestJSON), "{") || !strings.Contains(string(rd.ManifestJSON), `"name":"brief"`) || rd.Ships != nil || rd.Instruction != "# i" {
		t.Fatalf("read: %+v", rd)
	}
	var paths []string
	for _, f := range rd.Files {
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
		tooLarge bool
	}{
		"no agent.yaml":            {[]File{{Path: "AGENT.md", Content: "x"}}, true, false},
		"an agent.yaml of nothing": {[]File{{Path: "agent.yaml", Content: "- not a manifest"}, {Path: "AGENT.md", Content: "x"}}, true, false},
		"no instruction":           {good[:1], true, false},
		"an absolute path":         {append(good, File{Path: "/etc/x", Content: "x"}), false, false},
		"a path out":               {append(good, File{Path: "../x", Content: "x"}), false, false},
		"an unclean path":          {append(good, File{Path: "a/../b", Content: "x"}), false, false},
		"a path twice":             {append(good, File{Path: "AGENT.md", Content: "x"}), false, false},
		"not UTF-8":                {append(good, File{Path: "x.md", Content: "\xff\xfe"}), false, false},
		"past the bytes":           {append(good, File{Path: "x.md", Content: strings.Repeat("x", MaxBytes)}), false, true},
		"past the files":           {append(good, make([]File, MaxFiles)...), false, true},
	} {
		_, err := Read(Package{Files: c.files})
		if err == nil || errors.Is(err, ErrNotADraft) != c.notDraft || errors.Is(err, ErrTooLarge) != c.tooLarge {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(err.Error(), "\xff") || strings.Contains(err.Error(), "not a manifest") {
			t.Fatalf("%s: the refusal quotes the package: %v", name, err)
		}
	}
}
