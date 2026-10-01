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

// PackStage is one stage that read the pack, or that failed to (a
// timeout, a panic): a failed stage is named, its findings are not
// trusted to be all there are, and the scan is not complete.
type PackStage struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Failed bool   `json:"failed,omitempty"`
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

// Complete says whether every stage finished and every chunk of AI Review
// was read (or none was to be, with no judge configured).
func (r PackReport) Complete() bool {
	for _, st := range r.Stages {
		if st.Failed {
			return false
		}
	}
	return r.Review.Failed == 0
}

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
	r, hits := o.scanPack(ctx, files)
	for _, h := range hits {
		r.Findings = append(r.Findings, h.packFinding())
	}
	return r
}

// packHit is one finding of a pack's scan, whole, with where it is: the
// half, and for AI Review the chunk (1-based within its half) and, when
// the chunk read one file, that file.
type packHit struct {
	finding Finding
	part    PackPart
	chunk   int
}

// packFinding is the hit as a pack's report places it: by half, file and
// line, or chunk, with no excerpt.
func (h packHit) packFinding() PackFinding {
	f := h.finding
	return PackFinding{
		Scanner: f.Scanner, Severity: f.Severity, Confidence: f.Confidence, Title: f.Title,
		Part: h.part, File: f.FilePath, Line: f.LineStart, Chunk: h.chunk,
	}
}

// ScanProse reads text files with the rule stages a pack's scan runs (S2,
// S3, S4, S8) and no AI Review: a Writing Voice's review asks a question
// set of its own (agentry#809), since the release rubric reads a voice's
// instructions about writing as instructions to the reader. Its findings
// carry no excerpt, as a pack's do.
func (o *Orchestrator) ScanProse(ctx context.Context, files []PackFile) PackReport {
	r, hits, _, _ := o.scanPackRules(ctx, files)
	for _, h := range hits {
		r.Findings = append(r.Findings, h.packFinding())
	}
	return r
}

// scanPack is ScanPack's reading: the report without its findings, and
// the findings whole — excerpts included — for a caller that keeps them
// where excerpts belong (a release's own report, ScanShipped).
func (o *Orchestrator) scanPack(ctx context.Context, files []PackFile) (PackReport, []packHit) {
	r, hits, read, part := o.scanPackRules(ctx, files)
	return r, append(hits, o.reviewPack(ctx, &r, read, part)...)
}

// scanPackRules runs the rule stages over the text files: the report
// without findings or review, the findings, the files read and the half
// each is in.
func (o *Orchestrator) scanPackRules(ctx context.Context, files []PackFile) (PackReport, []packHit, []FileEntry, map[string]PackPart) {
	r := PackReport{Schema: PackReportSchema, Stages: append([]PackStage(nil), packRuleStages...), Findings: []PackFinding{}}
	r.Read.NotRead = []string{}
	in := &Input{}
	part := map[string]PackPart{}
	sorted := append([]PackFile(nil), files...)
	sort.Slice(sorted, func(i, k int) bool { return sorted[i].Path < sorted[k].Path })
	for _, f := range sorted {
		p := partOf(f.Path)
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
	failed := map[string]bool{}
	for _, st := range []Stage{S2Secrets{}, S3S4Content{}} {
		res := o.runStage(sc, st, in)
		if res.Err != nil {
			// S3S4 is two of the report's stages; a failure fails both.
			for _, id := range []string{"S2", "S3", "S4"} {
				if strings.Contains(st.ID(), id) {
					failed[id] = true
				}
			}
		}
		found = append(found, res.Findings...)
	}
	found = append(found, s8URLReputation(in)...)
	for i := range r.Stages {
		r.Stages[i].Failed = failed[r.Stages[i].ID]
	}
	hits := make([]packHit, 0, len(found))
	for _, f := range found {
		hits = append(hits, packHit{finding: f, part: part[f.FilePath]})
	}

	return r, hits, in.Files, part
}

// reviewPack runs AI Review over the sources, then over the wiki.
func (o *Orchestrator) reviewPack(ctx context.Context, r *PackReport, files []FileEntry, part map[string]PackPart) []packHit {
	j := o.judge
	r.Review.Provider = j.Name()
	r.Review.Model = j.ModelID()
	limit := j.InputLimit()
	if limit <= 0 {
		r.Review.Note = AIReviewNotConfigured
		return nil
	}
	var hits []packHit
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
			verdict.Usage.add(&r.Review.Usage)
			for _, f := range verdictFindings(verdict) {
				f.FilePath = chunk.file()
				hits = append(hits, packHit{finding: f, part: half, chunk: i + 1})
			}
		}
	}
	return hits
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
