package scan

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/blaktron/agentry/pkg/manifest"
	"github.com/blaktron/agentry/pkg/toolgrant"
)

// scannerUngrantedTool is S6's finding for runner tools the instruction
// calls for that the manifest does not grant; high, so the version goes to
// a person, and weighed at medium by a rescan (rescanSeverity).
const scannerUngrantedTool = "S6/ungranted-tool"

// s6UngrantedTools reads the instruction the manifest names, and a
// persistent release's persona, against the capabilities it declares: one
// finding per file and grant missing, in the order the file first calls
// for each. A manifest that does not decode, or a file not in the archive
// or not text, gives none for it: S1 reports both.
func s6UngrantedTools(in *Input) []Finding {
	var m manifest.Manifest
	if err := json.Unmarshal(in.ManifestJSON, &m); err != nil {
		return nil
	}
	out := ungrantedIn(&m, instructionFile(&m, in.Files), "instruction")
	return append(out, ungrantedIn(&m, textFile(m.PersonaFile(), in.Files), "persona")...)
}

// ungrantedIn is s6UngrantedTools for one file, which the findings call
// what; none for a nil file.
func ungrantedIn(m *manifest.Manifest, file *FileEntry, what string) []Finding {
	if file == nil {
		return nil
	}
	missing := toolgrant.CheckRelease(m, string(file.Content))
	// One finding per manifest line to change, in the order the
	// file first calls for each.
	var order []string
	byPath := map[string][]toolgrant.Missing{}
	for _, x := range missing {
		if _, ok := byPath[x.Path]; !ok {
			order = append(order, x.Path)
		}
		byPath[x.Path] = append(byPath[x.Path], x)
	}
	var out []Finding
	for _, p := range order {
		xs := byPath[p]
		tools := make([]string, len(xs))
		lines := make([]int, len(xs))
		for i, x := range xs {
			tools[i], lines[i] = x.Tool, x.Line
		}
		out = append(out, Finding{
			Scanner: scannerUngrantedTool, Severity: SevHigh, Confidence: ConfHigh,
			Title:    "The " + what + " calls for runner tools a run of this release does not have (" + p + "): " + truncateStr(strings.Join(tools, ", "), 160),
			FilePath: file.Path, LineStart: lines[0], LineEnd: lines[0],
			Detail: map[string]any{"grant": string(xs[0].Grant), "path": p, "tools": tools, "lines": lines},
		})
	}
	return out
}

// textFile is the archive's text file at p, or nil when p is empty or the
// file is absent or not text.
func textFile(p string, files []FileEntry) *FileEntry {
	if p == "" {
		return nil
	}
	for i := range files {
		if files[i].Path == p {
			if !files[i].IsText || files[i].Content == nil {
				return nil
			}
			return &files[i]
		}
	}
	return nil
}

// instructionFile is the archive's text file the manifest names as its
// instruction (the first candidate present, for a v1 prompt-agent), or nil.
func instructionFile(m *manifest.Manifest, files []FileEntry) *FileEntry {
	for _, c := range m.InstructionCandidates() {
		if i := slices.IndexFunc(files, func(f FileEntry) bool { return f.Path == c }); i >= 0 {
			return textFile(c, files[i:i+1])
		}
	}
	return nil
}
