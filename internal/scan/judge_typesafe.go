package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blaktron/agentry/pkg/judge"
)

// TypeSafeJudge is the `typesafe` provider:
// TypeSafe AI's Jev, a typed-decision model behind
// POST /v1/systemone, asked the six rubric axes as yes/no questions ("Nouls")
// that answer with a probability. It reads the manifest and every text file
// of the version, one chunk of one file per request, and takes the highest
// probability over the chunks as the version's score on each axis.
//
// It is not an LLM judge: it returns numbers, no text, so there is nothing
// in which a manipulated-judge symptom could show, and it has no
// temperature or seed, so two identical requests may answer differently.
// The record compensates: the model id is pinned in configuration,
// checked against every response and in the rubric hash with everything
// else that changes a verdict; an answer in the borderline band is asked
// twice more and the maximum is taken, never the mean (disagreement
// escalates, never averages away), with every sample on the
// finding for an appeal to read.
//
// The question texts are constants. Nothing from the version — not the
// manifest, not a path, not a line of content — is rendered into them:
// the content and the manifest's declared capabilities travel in the
// request's `state`, the data the questions are asked about, so an
// attacker-authored manifest can no more rewrite the question than a
// SKILL.md can (content is data).
type TypeSafeJudge struct {
	// client is the one Jev client (pkg/judge): the
	// registry's model-input scan and a person's local scan ask through the
	// same code, so the transport, the retry, the model pin and the key's
	// redaction are one implementation.
	client *judge.Client
	model  string
	// err is why the client could not be built (no key, an unpinned
	// model); every verdict then fails closed with it. BuildJudgeProvider
	// refuses both before this is ever built at startup.
	err error
	// batch is the request shape: how many requests carry the six questions
	// for one chunk — 1 (all six together, the shipped shape), 2 (the
	// reader-directed axes C1/C3/C5 and the behaviour axes C2/C4/C6) or 6
	// (one each). Named in the hash; the by-hand corpus check compares the
	// three.
	batch int
}

const (
	typesafeDefaultBaseURL = judge.DefaultBaseURL
	typesafeDefaultModel   = judge.DefaultModel
	typesafeChunk          = judge.ChunkSize
	typesafeInputLimit     = 50 << 10
	typesafeBatch          = judge.RubricBatchOne
	// typesafeDeclaredCap bounds the declared-capabilities JSON that rides
	// in the state beside the content (judge.DeclaredCapabilitiesCap).
	typesafeDeclaredCap = judge.DeclaredCapabilitiesCap
)

// typesafeQuestions are the six rubric axes as questions the model answers
// with a probability, over a state of `{path, content,
// declared_capabilities, runner_grants}`.
// The texts are pkg/judge's constants (judge.RubricQuestions), whose ids are
// the gate's category ids; the wording is part of the rubric, and changing
// it changes the hash.
var typesafeQuestions = func() map[JudgeCategory]string {
	out := map[JudgeCategory]string{}
	for _, q := range judge.RubricQuestions() {
		out[JudgeCategory(q.ID)] = q.Text
	}
	return out
}()

// NewTypeSafeJudge builds the provider. APIKey is required and Model must be
// a pinned version id (the factory refuses otherwise; Model defaults to the
// pinned id when empty); BaseURL defaults to the vendor's API.
func NewTypeSafeJudge(cfg JudgeConfig) *TypeSafeJudge {
	return newTypeSafeJudge(cfg, 0)
}

// newTypeSafeJudge is NewTypeSafeJudge with the pause before the one retry
// on 429/529 chosen: zero is the client's default, negative retries at once
// (the tests).
func newTypeSafeJudge(cfg JudgeConfig, retryWait time.Duration) *TypeSafeJudge {
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = typesafeDefaultModel
	}
	c, err := judge.New(judge.Config{BaseURL: cfg.BaseURL, APIKey: cfg.APIKey, Model: model, RetryWait: retryWait})
	return &TypeSafeJudge{client: c, model: model, err: err, batch: typesafeBatch}
}

// PinnedJudgeModel reports whether a judge model id names one version — it
// carries a dotted number — rather than a moving alias (`jev-latest`,
// `jev-preview`, a bare family name). Thresholds are calibrated per version
// and the vendor's aliases move without a changelog, so the
// factory refuses anything else.
func PinnedJudgeModel(model string) bool { return judge.PinnedModel(model) }

// hash is the rubric hash over everything that changes a verdict:
// the model, the axes and their wording, the request shape, the chunk size,
// the capability bound, the runner's grants, the thresholds, the band and
// the sample count. It is pkg/judge's (RubricScanner.Hash), which a draft's
// check records too.
func (j *TypeSafeJudge) hash() string {
	return judge.NewRubricScannerShape(modelOnly(j.model), j.batch).Hash()
}

// modelOnly is an Asker that only names a model, for the hash of a judge
// whose client could not be built.
type modelOnly string

func (m modelOnly) Model() string { return string(m) }

func (m modelOnly) Ask(context.Context, map[string]string, []judge.Question) (map[string]float64, judge.Usage, error) {
	return nil, judge.Usage{}, errors.New("judge: no client")
}

// Name implements JudgeProvider.
func (j *TypeSafeJudge) Name() string { return "typesafe" }

// ModelID implements JudgeProvider: the pinned model id.
func (j *TypeSafeJudge) ModelID() string { return j.model }

// InputLimit implements JudgeProvider: about 50 KB, what Jev's documented
// 32k-token window takes with the questions and the state around it.
// A call is still asked in typesafeChunk pieces.
func (j *TypeSafeJudge) InputLimit() int { return typesafeInputLimit }

// RequiresHumanReview implements JudgeProvider: the six axes are the rubric,
// so the verdict follows the gate's severity table like an LLM judge's.
func (j *TypeSafeJudge) RequiresHumanReview() bool { return false }

// typesafeAxisResult is one axis's best evidence over the whole version:
// the chunk that set its probability, with every sample that chunk drew.
type typesafeAxisResult struct {
	best    float64
	samples []float64
	path    string
	line    string
}

// Judge implements JudgeProvider.
func (j *TypeSafeJudge) Judge(ctx context.Context, content JudgeContent) (JudgeVerdict, error) {
	axes, usage, err := j.judgeAxes(ctx, content)
	if err != nil {
		return JudgeVerdict{}, err // fail closed
	}
	v := JudgeVerdict{
		Scores:     map[JudgeCategory]int{},
		Excerpts:   map[JudgeCategory]string{},
		Samples:    map[JudgeCategory][]float64{},
		Model:      j.model,
		PromptHash: j.hash(),
	}
	for cat, r := range axes {
		score := scoreFromProbability(r.best)
		if score == 0 {
			continue
		}
		v.Scores[cat] = score
		v.Samples[cat] = r.samples
		if len(r.samples) > 1 {
			parts := make([]string, len(r.samples))
			for i, p := range r.samples {
				parts[i] = fmt.Sprintf("%.2f", p)
			}
			v.Excerpts[cat] = fmt.Sprintf("p=%.2f (samples %s) %s: %s", r.best, strings.Join(parts, " "), r.path, excerptLine(r.line))
		} else {
			v.Excerpts[cat] = fmt.Sprintf("p=%.2f %s: %s", r.best, r.path, excerptLine(r.line))
		}
	}
	if usage.PromptTokens > 0 || usage.CompletionTokens > 0 {
		v.Usage = &usage
	}
	return v, nil
}

// judgeAxes asks about every chunk of the manifest and every file through
// pkg/judge's RubricScanner, the code a draft's check asks through too, and
// returns, per axis, the chunk that scored highest with its samples, plus
// the token use of every request. The bench reads this directly.
func (j *TypeSafeJudge) judgeAxes(ctx context.Context, content JudgeContent) (map[JudgeCategory]*typesafeAxisResult, JudgeUsage, error) {
	if j.err != nil {
		return nil, JudgeUsage{}, fmt.Errorf("scan: typesafe judge: %w", j.err)
	}
	files := make([]judge.RubricFile, len(content.Files))
	for i, f := range content.Files {
		files[i] = judge.RubricFile{Path: f.Path, Content: f.Content}
	}
	res, u, err := judge.NewRubricScannerShape(j.client, j.batch).Scan(ctx, content.ManifestJSON, shippedPacks(content.ManifestJSON), files)
	if err != nil {
		return nil, JudgeUsage{}, fmt.Errorf("scan: %w", err)
	}
	axes := make(map[JudgeCategory]*typesafeAxisResult, len(res))
	for id, r := range res {
		axes[JudgeCategory(id)] = &typesafeAxisResult{best: r.Best, samples: r.Samples, path: r.Path, line: r.Line}
	}
	return axes, JudgeUsage{PromptTokens: u.InputTokens, CompletionTokens: u.OutputTokens}, nil
}

// declaredCapabilitiesJSON is the state's declared_capabilities field for
// a manifest: its capabilities block and the packs it ships
// (judge.DeclaredCapabilities).
func declaredCapabilitiesJSON(manifestJSON []byte) string {
	return judge.DeclaredCapabilities(manifestJSON, shippedPacks(manifestJSON))
}
