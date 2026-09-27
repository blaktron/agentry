package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/blaktron/agentry/pkg/manifest"
)

// SK — the knowledge packs a release ships (plan knowledge.md §4.6, D12,
// D19; agentry#594). A pack travels in the archive under knowledge/<name>/
// and enters the agent's context at run time, so it is scanned with the
// version, by the same reading the registry gives a pack it stores
// (ScanPack): S2, S3, S4 and S8's URL reputation over every page and
// source, then AI Review over sources/ and over wiki/ in chunks no larger
// than the judge reads. Its findings are the release's, gated like any
// other; a pack the scan could not read in full fails the stage, which
// sends the version to a person. The release's own stages read the
// release's own files: a pack's tree is this stage's, since S5 would read
// it in one call past what the judge takes, and S1's 1 MiB text cap would
// cut a pack's long source short.

// knowledgeStageID is the stage's id and its findings' scanner prefix.
const knowledgeStageID = "SK"

// ShippedPackScan is what the scan of one shipped pack read and found, in
// the terms a stored pack's report uses (the findings without excerpts,
// placed by half and chunk; the same findings are the version's, whole).
type ShippedPackScan struct {
	Name   string     `json:"name"`
	Report PackReport `json:"report"`
}

// SKKnowledge adapts the pack scan into a stage. It holds the orchestrator,
// whose pack reading it runs, and the packs the manifest ships.
type SKKnowledge struct {
	o     *Orchestrator
	ships []string
}

// ID implements Stage.
func (SKKnowledge) ID() string { return knowledgeStageID }

// Run implements Stage: one pack scan per shipped pack, over the files S1
// inventoried under the pack's wiki/ and sources/, read whole off disk.
func (s SKKnowledge) Run(sc stageContext, in *Input) StageResult {
	res := StageResult{Scanner: knowledgeStageID}
	byPack := map[string][]PackFile{}
	var errs []error
	for _, f := range in.Files {
		name, ok := manifest.ShippedPackFile(s.ships, f.Path)
		if !ok {
			continue
		}
		data, err := readArchiveFile(in.Dir, f.Path)
		if err != nil {
			errs = append(errs, fmt.Errorf("knowledge pack %s: %s could not be read: %w", name, f.Path, err))
			continue
		}
		byPack[name] = append(byPack[name], PackFile{Path: strings.TrimPrefix(f.Path, manifest.KnowledgeDir+"/"+name+"/"), Content: data})
	}
	for _, name := range s.ships {
		files := byPack[name]
		if len(files) == 0 {
			// V11 refuses a submission without it; a rescan of an archive
			// that lacks it has nothing to stand behind.
			errs = append(errs, fmt.Errorf("knowledge pack %s: the archive holds none of its files", name))
			continue
		}
		report, hits := s.o.scanPack(sc.Context(), files)
		for _, h := range hits {
			f := h.finding
			if f.FilePath != "" {
				f.FilePath = manifest.KnowledgeDir + "/" + name + "/" + f.FilePath
			}
			f.Scanner = knowledgeStageID + "/" + f.Scanner
			detail := map[string]any{"pack": name, "part": string(h.part)}
			for k, v := range f.Detail {
				detail[k] = v
			}
			if h.chunk > 0 {
				detail["chunk"] = h.chunk
			}
			f.Detail = detail
			res.Findings = append(res.Findings, f)
			report.Findings = append(report.Findings, PackFinding{
				Scanner: h.finding.Scanner, Severity: f.Severity, Confidence: f.Confidence, Title: f.Title,
				Part: h.part, File: h.finding.FilePath, Line: f.LineStart, Chunk: h.chunk,
			})
		}
		if u := report.Review.Usage; u != nil {
			if res.JudgeUsage == nil {
				res.JudgeUsage = &JudgeUsage{}
			}
			res.JudgeUsage.PromptTokens += u.PromptTokens
			res.JudgeUsage.CompletionTokens += u.CompletionTokens
			// Token use is the run's measurement, not the signed report's
			// (see JudgeUsage).
			report.Review.Usage = nil
		}
		if !report.Complete() {
			errs = append(errs, fmt.Errorf("knowledge pack %s: the scan did not read all of it (%s)", name, incompleteWhy(report)))
		}
		res.Knowledge = append(res.Knowledge, ShippedPackScan{Name: name, Report: report})
	}
	if len(errs) > 0 {
		res.Err = errors.Join(errs...)
	}
	return res
}

// incompleteWhy names what an incomplete pack scan did not finish.
func incompleteWhy(r PackReport) string {
	var why []string
	for _, st := range r.Stages {
		if st.Failed {
			why = append(why, st.ID+" failed")
		}
	}
	if r.Review.Failed > 0 {
		why = append(why, fmt.Sprintf("the judge failed on %d chunks", r.Review.Failed))
	}
	return strings.Join(why, ", ")
}

// shippedPacks reads the names of the packs a manifest ships from its
// canonical JSON, sorted; none for a manifest without the block.
func shippedPacks(manifestJSON []byte) []string {
	var m struct {
		Knowledge struct {
			Ships []struct {
				Name string `json:"name"`
			} `json:"ships"`
		} `json:"knowledge"`
	}
	if len(manifestJSON) == 0 || json.Unmarshal(manifestJSON, &m) != nil {
		return nil
	}
	var out []string
	for _, s := range m.Knowledge.Ships {
		if manifest.ValidKnowledgePackName(s.Name) {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

// withoutShippedTrees drops the files of shipped packs' trees from an
// inventory: what the release's own stages read.
func withoutShippedTrees(files []FileEntry, ships []string) []FileEntry {
	if len(ships) == 0 {
		return files
	}
	out := make([]FileEntry, 0, len(files))
	for _, f := range files {
		if _, ok := manifest.ShippedPackFile(ships, f.Path); !ok {
			out = append(out, f)
		}
	}
	return out
}

// withoutTruncatedPackFiles drops S1's text-scan-truncated findings on a
// shipped pack's files: SK reads them whole, so nothing past the cap goes
// unread.
func withoutTruncatedPackFiles(findings []Finding, ships []string) []Finding {
	if len(ships) == 0 {
		return findings
	}
	out := findings[:0:0]
	for _, f := range findings {
		if _, ok := manifest.ShippedPackFile(ships, f.FilePath); ok && f.Scanner == "S1/text-scan-truncated" {
			continue
		}
		out = append(out, f)
	}
	return out
}
