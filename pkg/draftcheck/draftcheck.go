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
	// MaxBytes is the most text the check reads over every file: sixteen
	// of the rubric's 8 KiB chunks.
	MaxBytes = 16 * judge.ChunkSize
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

// ErrNotADraft is the refusal of a package the check cannot read as a
// draft: no agent.yaml, one that does not parse, or no instruction file.
// Its text names what is missing and never quotes the package.
var ErrNotADraft = errors.New("draftcheck: not a draft package")

// Finding is one rubric question AI Review would flag at publish: its id,
// its score, and the file whose chunk scored highest.
type Finding struct {
	ID    string
	Score int
	Path  string
}

// Rubric is the release rubric's answer about the package.
type Rubric struct {
	// Verdict is pass, flagged (some question scored the gate's medium or
	// more, which S5 records as a finding and sends to review), or not
	// scanned (the judge could not answer for the whole package).
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

// Read turns a package into what the check reads: the canonical manifest
// JSON, the packs it ships, the instruction's text and every file sorted
// by path. It refuses a package past the bounds, and one that is not a
// draft (ErrNotADraft).
func Read(p Package) (manifestJSON []byte, ships []string, instruction string, files []judge.RubricFile, err error) {
	if len(p.Files) > MaxFiles {
		return nil, nil, "", nil, fmt.Errorf("draftcheck: %d files, at most %d", len(p.Files), MaxFiles)
	}
	total := 0
	byPath := make(map[string]string, len(p.Files))
	for _, f := range p.Files {
		clean := path.Clean(f.Path)
		if f.Path == "" || clean != f.Path || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." {
			return nil, nil, "", nil, fmt.Errorf("draftcheck: a file path must be relative and clean")
		}
		if _, dup := byPath[clean]; dup {
			return nil, nil, "", nil, fmt.Errorf("draftcheck: a file path is named twice")
		}
		if !utf8.ValidString(f.Content) {
			return nil, nil, "", nil, fmt.Errorf("draftcheck: a file is not UTF-8 text")
		}
		total += len(f.Content)
		byPath[clean] = f.Content
	}
	if total > MaxBytes {
		return nil, nil, "", nil, fmt.Errorf("draftcheck: %d bytes of text, at most %d", total, MaxBytes)
	}
	yml, ok := byPath["agent.yaml"]
	if !ok {
		return nil, nil, "", nil, fmt.Errorf("%w: it has no agent.yaml", ErrNotADraft)
	}
	m, perr := manifest.Parse([]byte(yml))
	if perr != nil {
		return nil, nil, "", nil, fmt.Errorf("%w: its agent.yaml does not parse", ErrNotADraft)
	}
	canonical, cerr := manifest.CanonicalJSON(m)
	if cerr != nil {
		return nil, nil, "", nil, fmt.Errorf("%w: its manifest has no canonical form", ErrNotADraft)
	}
	instruction, ok = byPath[m.Entrypoints.Instruction]
	if m.Entrypoints.Instruction == "" || !ok {
		return nil, nil, "", nil, fmt.Errorf("%w: its instruction file is not in the package", ErrNotADraft)
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	files = make([]judge.RubricFile, len(paths))
	for i, p := range paths {
		files[i] = judge.RubricFile{Path: p, Content: byPath[p]}
	}
	return canonical, manifest.ShippedPacksOf(canonical), instruction, files, nil
}

// Check reads a finished draft with the release rubric and the draft set.
// Its error is Read's, for a package it will not read; a judge that
// cannot answer is a verdict of not scanned on the half it failed, never
// an error.
func (c *Checker) Check(ctx context.Context, p Package) (Result, error) {
	manifestJSON, ships, instruction, files, err := Read(p)
	if err != nil {
		return Result{}, err
	}
	res := Result{Model: c.Model()}
	res.Rubric = c.askRubric(ctx, manifestJSON, ships, files, &res.Usage)
	res.Draft = c.draft.Scan(ctx, judge.DraftInput{Description: p.Description, ManifestJSON: manifestJSON, Instruction: instruction})
	res.Usage.Add(res.Draft.Usage)
	return res, nil
}

func (c *Checker) askRubric(ctx context.Context, manifestJSON []byte, ships []string, files []judge.RubricFile, usage *judge.Usage) Rubric {
	out := Rubric{Hash: c.rubric.Hash()}
	axes, u, err := c.rubric.Scan(ctx, manifestJSON, ships, files)
	usage.Add(u)
	if err != nil {
		out.Verdict, out.Err, out.Failure = judge.VerdictNotScanned, err, judge.FailureJudgeError
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			out.Failure = judge.FailureTimeout
		}
		return out
	}
	out.Verdict = judge.VerdictPass
	out.Scores = make(map[string]int, len(axes))
	for _, q := range judge.RubricQuestions() {
		a := axes[q.ID]
		sc := judge.ScoreFromProbability(a.Best)
		out.Scores[q.ID] = sc
		// The gate counts S5's findings from the medium score up, as a
		// model-input scan withholds from it.
		if sc >= judge.WithholdScore {
			out.Findings = append(out.Findings, Finding{ID: q.ID, Score: sc, Path: a.Path})
		}
	}
	if len(out.Findings) > 0 {
		out.Verdict = judge.VerdictFlagged
	}
	return out
}
