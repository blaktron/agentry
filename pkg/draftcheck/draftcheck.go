// Package draftcheck is AI Review's check of a finished draft (plan
// builder-simplify.md §5.2 step 4, D6; agentry#708): before a draft is
// handed back, AI Review reads its rendered package with the release
// rubric that stage S5 of the pipeline will ask at publish, so the person
// knows before Submit what AI Review will flag, and asks the draft
// question set (pkg/judge DraftQuestions) about whether the draft does the
// task it was drafted for.
//
// The registry's POST /model-input/check asks through this package with
// the deployment's key, for a hosted draft's job credential or platform
// staff; the CLI asks through it with the person's own key for a local
// draft, so both ask exactly what the pipeline asks. It reads the package
// as the pipeline does: the manifest as its canonical JSON (read as
// agent.yaml), the packs it ships declared beside the content, and every
// text file.
package draftcheck

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/blaktron/agentry/pkg/judge"
	"github.com/blaktron/agentry/pkg/manifest"
)

// Bounds on a package the check reads: a draft is a manifest, an
// instruction of about a screen, a README and a licence.
const (
	MaxFiles = 32
	// MaxBytes is the most text the check reads over every file: eight of
	// the rubric's 8 KiB chunks, the scan route's own bound. A check asks
	// about every chunk and the manifest's, up to three times each, so the
	// bound is what keeps one call's judge requests near thirty.
	MaxBytes = 8 * judge.ChunkSize
)

// File is one text file of the rendered package.
type File struct {
	Path    string
	Content string
}

// Package is a finished draft as the check reads it: the person's
// description, and every text file of the rendered package, agent.yaml
// among them.
type Package struct {
	Description string
	Files       []File
}

// The refusals of a package the check will not read. Their texts name
// what is wrong and never quote the package.
var (
	// ErrNotADraft: no agent.yaml, one that does not parse, or no
	// instruction file.
	ErrNotADraft = errors.New("draftcheck: not a draft package")
	// ErrTooLarge: more than MaxFiles files or MaxBytes bytes of text.
	ErrTooLarge = errors.New("draftcheck: the package is past the check's bounds")
)

// Reading is a package as the check reads it.
type Reading struct {
	// ManifestJSON is the canonical manifest, read as agent.yaml.
	ManifestJSON []byte
	// Ships is the valid names of the packs the manifest ships.
	Ships []string
	// Instruction is the text of the instruction file the manifest names.
	Instruction string
	// Files is every file, sorted by path.
	Files []judge.RubricFile
}

// Finding is one rubric question S5 would record as a finding at publish:
// its id, its score, the file whose chunk scored highest, and the severity
// the gate would give it. A high one holds the version for a person; a
// medium one is a note, shown on the report of a version that publishes
// (ruleset 0.3.0, agentry#773).
type Finding struct {
	ID       string
	Score    int
	Path     string
	Severity string
}

// Rubric is the release rubric's answer about the package.
type Rubric struct {
	// Verdict is pass, flagged (some finding is high, which the gate sends
	// to a person), or not scanned (the judge could not answer for the whole
	// package). A pass may carry medium findings: notes the report shows.
	Verdict judge.Verdict
	// Scores are per rubric id, 0 to 3; empty when not scanned.
	Scores   map[string]int
	Findings []Finding
	// Hash is the rubric hash S5 records under the same model and shape.
	Hash string
	// Failure is a Failure word when not scanned; Err what went wrong,
	// for the caller's own log. Err never travels.
	Failure string
	Err     error
}

// Result is the check's answer.
type Result struct {
	Rubric Rubric
	// Draft is the draft set's answer.
	Draft judge.DraftResult
	// Model is the pinned model id both answers came from.
	Model string
	// Usage is both halves' requests and tokens, for the record; never a
	// price (DEV-150: AI Review is 1 credit a draft).
	Usage judge.Usage
}

// Checker asks both halves of the check. It is safe for concurrent use.
type Checker struct {
	rubric *judge.RubricScanner
	draft  *judge.DraftScanner
}

// New builds a Checker over an Asker: a *judge.Client, the registry's
// paced one, or a fake.
func New(a judge.Asker) *Checker {
	return &Checker{rubric: judge.NewRubricScanner(a), draft: judge.NewDraftScanner(a)}
}

// Model is the pinned model id the answers come from.
func (c *Checker) Model() string { return c.rubric.Model() }

// RubricHash is the release rubric's hash, the one S5 records.
func (c *Checker) RubricHash() string { return c.rubric.Hash() }

// QuestionSet is the draft set's hash.
func (c *Checker) QuestionSet() string { return c.draft.QuestionSet() }

// Read turns a package into what the check reads. It refuses a package
// past the bounds (ErrTooLarge), one that is not a draft (ErrNotADraft),
// and one with a path that is not relative and clean, named twice, or a
// file that is not UTF-8.
func Read(p Package) (Reading, error) {
	if len(p.Files) > MaxFiles {
		return Reading{}, fmt.Errorf("%w: %d files, at most %d", ErrTooLarge, len(p.Files), MaxFiles)
	}
	total := 0
	byPath := make(map[string]string, len(p.Files))
	for _, f := range p.Files {
		clean := path.Clean(f.Path)
		if f.Path == "" || clean != f.Path || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." {
			return Reading{}, errors.New("draftcheck: a file path must be relative and clean")
		}
		if _, dup := byPath[clean]; dup {
			return Reading{}, errors.New("draftcheck: a file path is named twice")
		}
		if !utf8.ValidString(f.Content) {
			return Reading{}, errors.New("draftcheck: a file is not UTF-8 text")
		}
		total += len(f.Content)
		byPath[clean] = f.Content
	}
	if total > MaxBytes {
		return Reading{}, fmt.Errorf("%w: %d bytes of text, at most %d", ErrTooLarge, total, MaxBytes)
	}
	yml, ok := byPath["agent.yaml"]
	if !ok {
		return Reading{}, fmt.Errorf("%w: it has no agent.yaml", ErrNotADraft)
	}
	m, err := manifest.Parse([]byte(yml))
	if err != nil {
		return Reading{}, fmt.Errorf("%w: its agent.yaml does not parse", ErrNotADraft)
	}
	canonical, err := manifest.CanonicalJSON(m)
	if err != nil {
		return Reading{}, fmt.Errorf("%w: its manifest has no canonical form", ErrNotADraft)
	}
	instruction, ok := byPath[m.Entrypoints.Instruction]
	if m.Entrypoints.Instruction == "" || !ok {
		return Reading{}, fmt.Errorf("%w: its instruction file is not in the package", ErrNotADraft)
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	files := make([]judge.RubricFile, len(paths))
	for i, p := range paths {
		files[i] = judge.RubricFile{Path: p, Content: byPath[p]}
	}
	return Reading{ManifestJSON: canonical, Ships: manifest.ShippedPacksOf(canonical), Instruction: instruction, Files: files}, nil
}

// Check reads a finished draft with the release rubric and the draft set.
// Its error is Read's, for a package it will not read; a judge that
// cannot answer is a verdict of not scanned on the half it failed, never
// an error.
func (c *Checker) Check(ctx context.Context, p Package) (Result, error) {
	rd, err := Read(p)
	if err != nil {
		return Result{}, err
	}
	res := Result{Model: c.Model()}
	res.Rubric = c.askRubric(ctx, rd, &res.Usage)
	res.Draft = c.draft.Scan(ctx, judge.DraftInput{Description: p.Description, ManifestJSON: rd.ManifestJSON, Instruction: rd.Instruction})
	res.Usage.Add(res.Draft.Usage)
	return res, nil
}

func (c *Checker) askRubric(ctx context.Context, rd Reading, usage *judge.Usage) Rubric {
	out := Rubric{Hash: c.rubric.Hash()}
	axes, u, err := c.rubric.Scan(ctx, rd.ManifestJSON, rd.Ships, rd.Files)
	usage.Add(u)
	if err != nil {
		out.Verdict, out.Err, out.Failure = judge.VerdictNotScanned, err, judge.FailureOf(ctx, err)
		return out
	}
	out.Verdict = judge.VerdictPass
	out.Scores = make(map[string]int, len(axes))
	for _, q := range judge.RubricQuestions() {
		a := axes[q.ID]
		sc := judge.ScoreFromProbability(a.Best)
		out.Scores[q.ID] = sc
		// S5 records a finding from the medium score up; only a high one
		// holds the version, so only a high one flags the draft.
		sev := judge.RubricSeverity(q.ID, sc)
		if sev == "" {
			continue
		}
		out.Findings = append(out.Findings, Finding{ID: q.ID, Score: sc, Path: a.Path, Severity: sev})
		if sev == "high" {
			out.Verdict = judge.VerdictFlagged
		}
	}
	return out
}
