package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blaktron/agentry/pkg/judge"
)

// TypeSafeJudge is the `typesafe` provider (plan judge-jev-provider.md,
// agentry#387, DEV-113): TypeSafe AI's Jev, a typed-decision model behind
// POST /v1/systemone, asked the six rubric axes as yes/no questions ("Nouls")
// that answer with a probability. It reads the manifest and every text file
// of the version, one chunk of one file per request, and takes the highest
// probability over the chunks as the version's score on each axis.
//
// It is not an LLM judge: it returns numbers, no text, so there is nothing
// in which a manipulated-judge symptom (§8.4.3) could show, and it has no
// temperature or seed, so two identical requests may answer differently.
// The record compensates (plan D4): the model id is pinned in configuration,
// checked against every response and in the rubric hash with everything
// else that changes a verdict; an answer in the borderline band is asked
// twice more and the maximum is taken, never the mean (PLAN §8.3 S5:
// disagreement escalates, never averages away), with every sample on the
// finding for an appeal to read.
//
// The question texts are constants. Nothing from the version — not the
// manifest, not a path, not a line of content — is rendered into them:
// the content and the manifest's declared capabilities travel in the
// request's `state`, the data the questions are asked about, so an
// attacker-authored manifest can no more rewrite the question than a
// SKILL.md can (§8.4.1, content is data).
type TypeSafeJudge struct {
	// client is the estate's one Jev client (pkg/judge, agentry#608): the
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
	// three (plan D3).
	batch int
}

const (
	typesafeDefaultBaseURL = judge.DefaultBaseURL
	typesafeDefaultModel   = judge.DefaultModel
	typesafeChunk          = judge.ChunkSize
	typesafeInputLimit     = 50 << 10
	typesafeBatch          = 1
	typesafeBandLow        = judge.BandLow
	typesafeBandHigh       = judge.BandHigh
	typesafeSamples        = judge.Samples
	// typesafeDeclaredCap bounds the declared-capabilities JSON that rides
	// in the state beside the content: a manifest's `mcpServers[].env` and
	// `tools` can carry tens of kilobytes of free text, and the question is
	// about the contract's shape, not its prose.
	typesafeDeclaredCap = 4 << 10
)

// typesafeQuestions are the six rubric axes as questions the model answers
// with a probability, over a state of `{path, content, declared_capabilities}`.
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
// and the vendor's aliases move without a changelog (plan D7), so the
// factory refuses anything else.
func PinnedJudgeModel(model string) bool { return judge.PinnedModel(model) }

// hash is the rubric hash (§8.4.4) over everything that changes a verdict:
// the model, the axes and their wording, the request shape, the chunk size,
// the capability bound, the thresholds, the band and the sample count.
func (j *TypeSafeJudge) hash() string {
	cats := AllJudgeCategories()
	questions := make([]string, 0, len(cats))
	for _, c := range cats {
		questions = append(questions, string(c)+"="+typesafeQuestions[c])
	}
	return RubricHash(rubricStatement, "provider=typesafe", "model="+j.model,
		"axes=C1..C6", "questions="+strings.Join(questions, "\n"),
		fmt.Sprintf("batch=%d", j.batch), fmt.Sprintf("chunk=%d", typesafeChunk),
		fmt.Sprintf("declared-cap=%d", typesafeDeclaredCap),
		"thresholds=0.5/0.7/0.9", fmt.Sprintf("band=%.2f/%.2f", typesafeBandLow, typesafeBandHigh),
		fmt.Sprintf("samples=%d", typesafeSamples))
}

// Name implements JudgeProvider.
func (j *TypeSafeJudge) Name() string { return "typesafe" }

// ModelID implements JudgeProvider: the pinned model id.
func (j *TypeSafeJudge) ModelID() string { return j.model }

// InputLimit implements JudgeProvider: about 50 KB, what Jev's documented
// 32k-token window takes with the questions and the state around it (plan
// knowledge.md §4.4). A call is still asked in typesafeChunk pieces.
func (j *TypeSafeJudge) InputLimit() int { return typesafeInputLimit }

// RequiresHumanReview implements JudgeProvider: the six axes are the rubric,
// so the verdict follows the §8.5 table like an LLM judge's (plan D3).
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
		return JudgeVerdict{}, err // fail closed (§8.4.6)
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

// judgeAxes asks about every chunk of the manifest and every file and
// returns, per axis, the chunk that scored highest with its samples, plus
// the token use of every request. The bench reads this directly.
func (j *TypeSafeJudge) judgeAxes(ctx context.Context, content JudgeContent) (map[JudgeCategory]*typesafeAxisResult, JudgeUsage, error) {
	declared := declaredCapabilitiesJSON(content.ManifestJSON)
	axes := map[JudgeCategory]*typesafeAxisResult{}
	var usage JudgeUsage
	inputs := []JudgeFile{{Path: "agent.yaml", Content: string(content.ManifestJSON)}}
	inputs = append(inputs, content.Files...)
	for _, f := range inputs {
		for _, chunk := range chunkText(f.Content, typesafeChunk) {
			if strings.TrimSpace(chunk) == "" {
				continue
			}
			probs, err := j.askChunk(ctx, f.Path, chunk, declared, &usage)
			if err != nil {
				return nil, JudgeUsage{}, err
			}
			for cat, samples := range probs {
				best := samples[0]
				for _, p := range samples[1:] {
					if p > best {
						best = p
					}
				}
				if cur := axes[cat]; cur == nil || best > cur.best {
					axes[cat] = &typesafeAxisResult{best: best, samples: samples, path: f.Path, line: firstLine(chunk)}
				}
			}
		}
	}
	return axes, usage, nil
}

// declaredCapabilitiesJSON is the manifest's `capabilities` block as compact
// JSON, bounded, for the state's declared_capabilities field. An absent or
// unreadable block reads as none declared.
func declaredCapabilitiesJSON(manifestJSON []byte) string {
	var m struct {
		Capabilities json.RawMessage `json:"capabilities"`
	}
	if json.Unmarshal(manifestJSON, &m) != nil || len(m.Capabilities) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if json.Compact(&buf, m.Capabilities) != nil || buf.Len() == 0 {
		return "{}"
	}
	s := buf.String()
	if len(s) > typesafeDeclaredCap {
		s = s[:typesafeDeclaredCap] + "…(truncated)"
	}
	return s
}

// askChunk asks every axis about one chunk in j.batch requests, then asks
// the borderline axes twice more in the same request shape (each group's
// borderline members together). It returns every sample per axis.
func (j *TypeSafeJudge) askChunk(ctx context.Context, path, chunk, declared string, usage *JudgeUsage) (map[JudgeCategory][]float64, error) {
	groups := j.groups()
	out := map[JudgeCategory][]float64{}
	for _, g := range groups {
		probs, err := j.ask(ctx, path, chunk, declared, g, usage)
		if err != nil {
			return nil, err
		}
		for cat, p := range probs {
			out[cat] = []float64{p}
		}
	}
	for i := 1; i < typesafeSamples; i++ {
		for _, g := range groups {
			var again []JudgeCategory
			for _, cat := range g {
				if p := out[cat][0]; p >= typesafeBandLow && p <= typesafeBandHigh {
					again = append(again, cat)
				}
			}
			if len(again) == 0 {
				continue
			}
			probs, err := j.ask(ctx, path, chunk, declared, again, usage)
			if err != nil {
				return nil, err
			}
			for cat, p := range probs {
				out[cat] = append(out[cat], p)
			}
		}
	}
	return out, nil
}

// groups is the request shape: which axes travel together. Only the three
// shapes the plan compares exist; anything else is the shipped shape.
func (j *TypeSafeJudge) groups() [][]JudgeCategory {
	switch j.batch {
	case 2:
		return [][]JudgeCategory{{CatInjection, CatUndeclaredCap, CatObfuscation}, {CatExfiltration, CatDeception, CatDestructive}}
	case 6:
		out := make([][]JudgeCategory, 0, 6)
		for _, c := range AllJudgeCategories() {
			out = append(out, []JudgeCategory{c})
		}
		return out
	default:
		return [][]JudgeCategory{AllJudgeCategories()}
	}
}

// ask posts one request for the given axes over one chunk and returns each
// axis's probability, through the shared client: one retry on 429/529, and
// every other failure, a missing answer, a probability outside [0,1] or a
// response naming a model other than the pinned one is an error.
func (j *TypeSafeJudge) ask(ctx context.Context, path, chunk, declared string, cats []JudgeCategory, usage *JudgeUsage) (map[JudgeCategory]float64, error) {
	if j.err != nil {
		return nil, fmt.Errorf("scan: typesafe judge: %w", j.err)
	}
	qs := make([]judge.Question, 0, len(cats))
	for _, c := range cats {
		qs = append(qs, judge.Question{ID: string(c), Text: typesafeQuestions[c]})
	}
	probs, u, err := j.client.Ask(ctx, map[string]string{"path": path, "content": chunk, "declared_capabilities": declared}, qs)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	out := make(map[JudgeCategory]float64, len(cats))
	for _, c := range cats {
		out[c] = probs[string(c)]
	}
	if usage != nil {
		usage.PromptTokens += u.InputTokens
		usage.CompletionTokens += u.OutputTokens
	}
	return out, nil
}
