package scan

import (
	"encoding/json"
	"errors"
	"fmt"
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
// release's own files and a pack's files that are not text (an image, a
// PDF source's original), which S1 and S3's image reading cover as
// anywhere else; a pack's text is this stage's, since S5 would read it in
// one call past what the judge takes, and S1's 1 MiB text cap would cut a
// pack's long source short. A pack file S1 took for text that the pack
// scan cannot read (not UTF-8) is a finding, so nothing in a pack goes
// unread without one.

// KnowledgeStageID is the stage's id and its findings' scanner prefix.
const KnowledgeStageID = "SK"

// packUnreadText is a shipped pack's text the pack scan could not read; as
// SK/unread-text the gate forces review on it.
const packUnreadText = "unread-text"

// knowledgeRecordKey is where SK's record sits in its stage row's detail.
const knowledgeRecordKey = "knowledge"

// DecodeKnowledgeRecord reads SK's record out of its stage row's detail
// into into (a slice of ShippedPackScan, or the API's shape of it); a
// detail without one leaves into as it is.
func DecodeKnowledgeRecord(detail []byte, into any) error {
	var d map[string]json.RawMessage
	if err := json.Unmarshal(detail, &d); err != nil {
		return err
	}
	raw, ok := d[knowledgeRecordKey]
	if !ok {
		return nil
	}
	return json.Unmarshal(raw, into)
}

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
func (SKKnowledge) ID() string { return KnowledgeStageID }

// Run implements Stage: one pack scan per shipped pack, over the text
// files S1 inventoried under the pack's wiki/ and sources/, read whole off
// disk.
func (s SKKnowledge) Run(sc stageContext, in *Input) StageResult {
	res := StageResult{Scanner: KnowledgeStageID}
	byPack := map[string][]PackFile{}
	var errs []error
	for _, f := range in.Files {
		name, ok := packText(s.ships, f)
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
			errs = append(errs, fmt.Errorf("knowledge pack %s: the archive holds none of its text", name))
			continue
		}
		report, hits := s.o.scanPack(sc.Context(), files)
		for _, p := range report.Read.NotRead {
			// S1 took it for text; the pack scan cannot read it as such.
			hits = append(hits, packHit{part: partOf(p), finding: Finding{
				Scanner: packUnreadText, Severity: SevMedium, Confidence: ConfHigh,
				Title:    "A text file in a shipped knowledge pack is not UTF-8 and was not read",
				FilePath: p,
				Detail:   map[string]any{"reason": "content no stage read cannot be cleared automatically"},
			}})
		}
		for _, h := range hits {
			pf := h.packFinding()
			f := h.finding
			if f.FilePath != "" {
				f.FilePath = manifest.KnowledgeDir + "/" + name + "/" + f.FilePath
			}
			f.Scanner = KnowledgeStageID + "/" + f.Scanner
			detail := map[string]any{"pack": name, "part": string(h.part)}
			for k, v := range f.Detail {
				detail[k] = v
			}
			if h.chunk > 0 {
				detail["chunk"] = h.chunk
			}
			f.Detail = detail
			res.Findings = append(res.Findings, f)
			report.Findings = append(report.Findings, pf)
		}
		// Token use is the run's measurement, not the signed report's (see
		// JudgeUsage).
		report.Review.Usage.add(&res.JudgeUsage)
		report.Review.Usage = nil
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
// canonical JSON (manifest.ShippedPacksOf).
func shippedPacks(manifestJSON []byte) []string { return manifest.ShippedPacksOf(manifestJSON) }

// packText says whether f is SK's to read: a text file (as S1 classified
// it) of a shipped pack's tree, and which pack.
func packText(ships []string, f FileEntry) (string, bool) {
	if !f.IsText {
		return "", false
	}
	return manifest.ShippedPackFile(ships, f.Path)
}

// partOf is the half of a pack a path in it belongs to.
func partOf(p string) PackPart {
	if strings.HasPrefix(p, string(PartWiki)+"/") {
		return PartWiki
	}
	return PartSources
}

// withoutShippedTrees drops the text of shipped packs' trees from an
// inventory: what the release's own stages read.
func withoutShippedTrees(files []FileEntry, ships []string) []FileEntry {
	if len(ships) == 0 {
		return files
	}
	out := make([]FileEntry, 0, len(files))
	for _, f := range files {
		if _, ok := packText(ships, f); !ok {
			out = append(out, f)
		}
	}
	return out
}

// withoutTruncatedPackFiles drops S1's text-scan-truncated findings on a
// shipped pack's text: SK reads it whole, or reports it unread.
func withoutTruncatedPackFiles(findings []Finding, inv []FileEntry, ships []string) []Finding {
	if len(ships) == 0 {
		return findings
	}
	text := map[string]bool{}
	for _, f := range inv {
		if _, ok := packText(ships, f); ok {
			text[f.Path] = true
		}
	}
	out := findings[:0:0]
	for _, f := range findings {
		if f.Scanner == scannerTextTruncated && text[f.FilePath] {
			continue
		}
		out = append(out, f)
	}
	return out
}
