package scan

import (
	"encoding/json"
	"strings"

	"github.com/blaktron/agentry/pkg/manifest"
	"github.com/blaktron/agentry/pkg/toolgrant"
)

// scannerUngrantedTool is S6's finding for runner tools the instruction
// calls for that the manifest does not grant; high, so the version goes to
// a person, and weighed at medium by a rescan (rescanSeverity).
const scannerUngrantedTool = "S6/ungranted-tool"

// s6UngrantedTools reads the instruction the manifest names against the
// capabilities it declares, one finding per grant missing, in the order
// the instruction first calls for each. A manifest that does not decode,
// or an instruction file not in the archive or not text, gives none:
// S1 reports both.
func s6UngrantedTools(in *Input) []Finding {
	var m manifest.Manifest
	if err := json.Unmarshal(in.ManifestJSON, &m); err != nil {
		return nil
	}
	file := instructionFile(&m, in.Files)
	if file == nil {
		return nil
	}
	missing := toolgrant.Check(m.Capabilities, string(file.Content))
	var order []toolgrant.Grant
	byGrant := map[toolgrant.Grant][]toolgrant.Missing{}
	for _, x := range missing {
		if _, ok := byGrant[x.Grant]; !ok {
			order = append(order, x.Grant)
		}
		byGrant[x.Grant] = append(byGrant[x.Grant], x)
	}
	var out []Finding
	for _, g := range order {
		xs := byGrant[g]
		tools := make([]string, len(xs))
		lines := make([]int, len(xs))
		for i, x := range xs {
			tools[i], lines[i] = x.Tool, x.Line
		}
		out = append(out, Finding{
			Scanner: scannerUngrantedTool, Severity: SevHigh, Confidence: ConfHigh,
			Title:    "The instruction calls for tools the manifest does not grant (" + g.Path() + "): " + truncateStr(strings.Join(tools, ", "), 160),
			FilePath: file.Path, LineStart: lines[0], LineEnd: lines[0],
			Detail: map[string]any{
				"grant": string(g), "add": g.Path(), "tools": tools, "lines": lines,
				"reason": xs[0].Reason,
			},
		})
	}
	return out
}

// instructionFile is the archive's text file the manifest names as its
// instruction (the first candidate present, for a v1 prompt-agent), or nil.
func instructionFile(m *manifest.Manifest, files []FileEntry) *FileEntry {
	for _, c := range m.InstructionCandidates() {
		for i := range files {
			if files[i].Path == c {
				if !files[i].IsText || files[i].Content == nil {
					return nil
				}
				return &files[i]
			}
		}
	}
	return nil
}
