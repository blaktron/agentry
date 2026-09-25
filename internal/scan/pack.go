package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/blaktron/agentry/pkg/archive"
)

// The knowledge pack scan (plan knowledge.md §4.4, D19, D27; agentry#593).
// A pack is not a version: it has no manifest, no code and no listing, so
// it is read by the stages that read prose — S2's secrets, S3's hidden
// content, S4's signatures and S8's URL reputation — over every text file
// of its tree, and by AI Review twice: over the documents it was compiled
// from (sources/), then over the wiki that was compiled from them (wiki/),
// each in chunks no larger than the judge provider declares it reads. The
// report is a record, never a gate: a pack is ready after its scan with
// its findings shown (D27).

// PackFile is one file of a pack's tree, by its slash path in the pack
// ("sources/report.pdf.txt", "wiki/topics/figures.md").
type PackFile struct {
	Path    string
	Content []byte
}

// PackPart is which half of a pack a file or a chunk belongs to.
type PackPart string

// The two halves of a pack's tree.
const (
	PartSources PackPart = "sources"
	PartWiki    PackPart = "wiki"
)

// AIReviewNotConfigured is the review's note on a deployment whose judge
// provider is none.
const AIReviewNotConfigured = "AI Review not configured"

// PackReportSchema names the report's shape.
const PackReportSchema = "agentry.knowledge-scan/v1"

// PackReport is what a pack's scan read and found.
type PackReport struct {
	Schema   string        `json:"schema"`
	Stages   []PackStage   `json:"stages"`
	Read     PackRead      `json:"read"`
	Review   PackReview    `json:"review"`
	Findings []PackFinding `json:"findings"`
}

// PackStage is one stage that read the pack.
type PackStage struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PackRead counts what the scan read: the text files of each half and
// their bytes, and the files it could not read as text — a source's
// original, whose extracted text beside it is read in its place.
type PackRead struct {
	Sources int      `json:"sources"`
	Wiki    int      `json:"wiki"`
	Bytes   int64    `json:"bytes"`
	NotRead []string `json:"notRead"`
}

// PackReview is AI Review's record: which provider and model, under which
// rubric, in chunks of how many bytes, how many chunks of each half, and
// how many of them the judge failed on.
type PackReview struct {
	Configured   bool        `json:"configured"`
	Note         string      `json:"note,omitempty"`
	Provider     string      `json:"provider"`
	Model        string      `json:"model,omitempty"`
	RubricHash   string      `json:"rubricHash,omitempty"`
	ChunkBytes   int         `json:"chunkBytes,omitempty"`
	SourceChunks int         `json:"sourceChunks"`
	WikiChunks   int         `json:"wikiChunks"`
	Failed       int         `json:"failed,omitempty"`
	Error        string      `json:"error,omitempty"`
	Usage        *JudgeUsage `json:"usage,omitempty"`
}

// PackFinding is one finding, placed in the half and, for AI Review, the
// chunk it came from (1-based within its half). It carries no excerpt: the
// report is kept in the clear beside a tree kept sealed, so it names where
// a finding is, never the words there (the owner, who holds the tree, can
// read them).
type PackFinding struct {
	Scanner    string     `json:"scanner"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Title      string     `json:"title"`
	Part       PackPart   `json:"part"`
	File       string     `json:"file,omitempty"`
	Line       int        `json:"line,omitempty"`
	Chunk      int        `json:"chunk,omitempty"`
}

// Complete says whether every chunk of AI Review was read (or none was to
// be, with no judge configured).
func (r PackReport) Complete() bool { return r.Review.Failed == 0 }

// packRuleStages are the stages that read a pack, in the order they run.
var packRuleStages = []PackStage{
	{ID: "S2", Name: "secrets"},
	{ID: "S3", Name: "hidden content"},
	{ID: "S4", Name: "signatures"},
	{ID: "S8", Name: "URL reputation"},
}

// ScanPack reads a pack's tree. It never fails: a judge that fails on a
// chunk is counted on the review (Complete reports it) and the rule
// stages' findings stand.
func (o *Orchestrator) ScanPack(ctx context.Context, files []PackFile) PackReport {
	r := PackReport{Schema: PackReportSchema, Stages: append([]PackStage(nil), packRuleStages...), Findings: []PackFinding{}}
	r.Read.NotRead = []string{}
	in := &Input{}
	part := map[string]PackPart{}
	sorted := append([]PackFile(nil), files...)
	sort.Slice(sorted, func(i, k int) bool { return sorted[i].Path < sorted[k].Path })
	for _, f := range sorted {
		p := PartSources
		if strings.HasPrefix(f.Path, string(PartWiki)+"/") {
			p = PartWiki
		}
		head := f.Content
		if len(head) > 512 {
			head = head[:512]
		}
		if !archive.LooksText(head) || !utf8.Valid(f.Content) {
			r.Read.NotRead = append(r.Read.NotRead, f.Path)
			continue
		}
		part[f.Path] = p
		in.Files = append(in.Files, FileEntry{Path: f.Path, Size: int64(len(f.Content)), IsText: true, Content: f.Content})
		r.Read.Bytes += int64(len(f.Content))
		if p == PartWiki {
			r.Read.Wiki++
		} else {
			r.Read.Sources++
		}
	}

	sc := stageContext{ctx: ctx, bundle: o.bundle, judge: o.judge, log: o.log}
	var found []Finding
	found = append(found, o.runStage(sc, S2Secrets{}, in).Findings...)
	found = append(found, o.runStage(sc, S3S4Content{}, in).Findings...)
	found = append(found, s8URLReputation(in)...)
	for _, f := range found {
		r.Findings = append(r.Findings, PackFinding{
			Scanner: f.Scanner, Severity: f.Severity, Confidence: f.Confidence, Title: f.Title,
			Part: part[f.FilePath], File: f.FilePath, Line: f.LineStart,
		})
	}

	o.reviewPack(ctx, &r, in.Files, part)
	return r
}

// reviewPack runs AI Review over the sources, then over the wiki.
func (o *Orchestrator) reviewPack(ctx context.Context, r *PackReport, files []FileEntry, part map[string]PackPart) {
	j := o.judge
	r.Review.Provider = j.Name()
	r.Review.Model = j.ModelID()
	limit := j.InputLimit()
	if limit <= 0 {
		r.Review.Note = AIReviewNotConfigured
		return
	}
	r.Stages = append(r.Stages, PackStage{ID: "S5", Name: "AI Review"})
	r.Review.Configured = true
	r.Review.ChunkBytes = limit
	for _, half := range []PackPart{PartSources, PartWiki} {
		var of []FileEntry
		for _, f := range files {
			if part[f.Path] == half {
				of = append(of, f)
			}
		}
		chunks := judgeChunks(of, limit)
		if half == PartSources {
			r.Review.SourceChunks = len(chunks)
		} else {
			r.Review.WikiChunks = len(chunks)
		}
		for i, chunk := range chunks {
			// Content is data (§8.4.1): a pack declares no capabilities.
			verdict, err := j.Judge(ctx, JudgeContent{ManifestJSON: []byte(`{}`), Files: chunk.files})
			if err != nil {
				// The report says where; the provider's own words stay in
				// the log, since the report goes to the pack's owner.
				r.Review.Failed++
				if r.Review.Error == "" {
					r.Review.Error = fmt.Sprintf("the judge failed on %s chunk %d of %d", half, i+1, len(chunks))
				}
				o.log.WarnContext(ctx, "knowledge: AI Review failed on a chunk", "part", string(half), "chunk", i+1, "provider", j.Name(), "err", err)
				continue
			}
			if r.Review.RubricHash == "" {
				r.Review.RubricHash = verdictPromptHash(j, verdict)
				if verdict.Model != "" && r.Review.Model == "" {
					r.Review.Model = verdict.Model
				}
			}
			if verdict.Usage != nil {
				if r.Review.Usage == nil {
					r.Review.Usage = &JudgeUsage{}
				}
				r.Review.Usage.PromptTokens += verdict.Usage.PromptTokens
				r.Review.Usage.CompletionTokens += verdict.Usage.CompletionTokens
			}
			for _, f := range verdictFindings(verdict) {
				r.Findings = append(r.Findings, PackFinding{
					Scanner: f.Scanner, Severity: f.Severity, Confidence: f.Confidence, Title: f.Title,
					Part: half, File: chunk.file(), Chunk: i + 1,
				})
			}
		}
	}
}

// judgeChunk is one Judge call's files and the pack file each came from.
type judgeChunk struct {
	files []JudgeFile
	from  []string
}

// file is the one pack file a chunk reads, or "" for a chunk of several.
func (c judgeChunk) file() string {
	for _, p := range c.from {
		if p != c.from[0] {
			return ""
		}
	}
	return c.from[0]
}

// judgeChunks packs files, in order, into chunks of at most limit bytes of
// content; a file longer than limit goes in pieces of whole lines where it
// can ("<path> (part i of n)"), so every byte is read.
func judgeChunks(files []FileEntry, limit int) []judgeChunk {
	var chunks []judgeChunk
	var cur judgeChunk
	size := 0
	for _, f := range files {
		pieces := splitLines(string(f.Content), limit)
		for i, p := range pieces {
			path := f.Path
			if len(pieces) > 1 {
				path = fmt.Sprintf("%s (part %d of %d)", f.Path, i+1, len(pieces))
			}
			if size+len(p) > limit && len(cur.files) > 0 {
				chunks = append(chunks, cur)
				cur, size = judgeChunk{}, 0
			}
			cur.files = append(cur.files, JudgeFile{Path: path, Content: p})
			cur.from = append(cur.from, f.Path)
			size += len(p)
		}
	}
	if len(cur.files) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

// splitLines cuts s into pieces of at most n bytes, each ending at a line's
// end where one falls in its second half, else at a rune boundary.
func splitLines(s string, n int) []string {
	var out []string
	for len(s) > n {
		cut := strings.LastIndexByte(s[:n], '\n') + 1
		if cut < n/2 {
			cut = n
			for cut > 0 && !utf8.RuneStart(s[cut]) {
				cut--
			}
		}
		out = append(out, s[:cut])
		s = s[cut:]
	}
	return append(out, s)
}
