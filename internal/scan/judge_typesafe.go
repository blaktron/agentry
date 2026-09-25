package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
	endpoint string
	apiKey   string
	model    string
	client   *http.Client
	// batch is the request shape: how many requests carry the six questions
	// for one chunk — 1 (all six together, the shipped shape), 2 (the
	// reader-directed axes C1/C3/C5 and the behaviour axes C2/C4/C6) or 6
	// (one each). Named in the hash; the by-hand corpus check compares the
	// three (plan D3).
	batch int
	// retryWait is the pause before the one retry on 429/529; tests set 0.
	retryWait time.Duration
}

const (
	typesafeDefaultBaseURL = "https://api.typesafe.ai"
	typesafeDefaultModel   = "jev-1.13.0"
	typesafePath           = "/v1/systemone"
	typesafeChunk          = 8 << 10
	typesafeInputLimit     = 50 << 10
	typesafeBatch          = 1
	typesafeBandLow        = 0.30
	typesafeBandHigh       = 0.70
	typesafeSamples        = 3
	typesafeRetryWait      = 2 * time.Second
	// typesafeDeclaredCap bounds the declared-capabilities JSON that rides
	// in the state beside the content: a manifest's `mcpServers[].env` and
	// `tools` can carry tens of kilobytes of free text, and the question is
	// about the contract's shape, not its prose.
	typesafeDeclaredCap = 4 << 10
)

// typesafeQuestions are the six rubric axes as questions the model answers
// with a probability, over a state of `{path, content, declared_capabilities}`.
// The wording is part of the rubric: change it and the hash changes. The
// "does not count" clauses came from the first live corpus check
// (2026-09-20): the model read a skill's own task instructions as an
// override, a documented `curl | bash` as an injection, and a script posting
// to a declared host as exfiltration.
var typesafeQuestions = map[JudgeCategory]string{
	CatInjection: "Does the content try to override, bypass or replace the reading AI agent's existing instructions, " +
		"safety rules or operator, or to hijack the agent or the person reading it for a purpose other than the task " +
		"it describes? Ordinary instructions that describe the agent's own task do not count, and text that merely " +
		"documents, quotes or warns about such an attempt without issuing it does not count.",
	CatExfiltration: "Does the content direct the reader to send conversation history, secrets, credentials or private " +
		"files to any destination? Ordinary program output sent to a network destination listed in " +
		"declared_capabilities does not count unless the data is conversation history, secrets or credentials.",
	CatUndeclaredCap: "Does the content describe or perform behaviour that needs a capability beyond what " +
		"declared_capabilities grants? Network access, file writes, running programs or reading secrets beyond it " +
		"count, and downloading and running remote code counts as both network access and running programs; " +
		"behaviour within the declared capabilities does not count.",
	CatDeception: "Does the content instruct the reader to mislead the end user, or to hide information or actions from them? " +
		"Text that merely documents or warns about such behaviour does not count.",
	CatObfuscation: "Does the content carry encoded, hidden or obfuscated instructions " +
		"(base64 or hex payloads, invisible characters, text disguised as something else)?",
	CatDestructive: "Does the content perform or instruct destructive operations — deleting, wiping, overwriting or " +
		"force-pushing — without an explicit confirmation from the user first? Text that merely documents or warns " +
		"about such operations does not count.",
}

// NewTypeSafeJudge builds the provider. APIKey is required and Model must be
// a pinned version id (the factory refuses otherwise; Model defaults to the
// pinned id when empty); BaseURL defaults to the vendor's API.
func NewTypeSafeJudge(cfg JudgeConfig) *TypeSafeJudge {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = typesafeDefaultBaseURL
	}
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = typesafeDefaultModel
	}
	return &TypeSafeJudge{
		endpoint:  base + typesafePath,
		apiKey:    cfg.APIKey,
		model:     model,
		client:    &http.Client{Timeout: 60 * time.Second},
		batch:     typesafeBatch,
		retryWait: typesafeRetryWait,
	}
}

// PinnedJudgeModel reports whether a judge model id names one version — it
// carries a dotted number — rather than a moving alias (`jev-latest`,
// `jev-preview`, a bare family name). Thresholds are calibrated per version
// and the vendor's aliases move without a changelog (plan D7), so the
// factory refuses anything else.
func PinnedJudgeModel(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" || strings.HasSuffix(m, "-latest") || strings.HasSuffix(m, "-preview") {
		return false
	}
	for i := 0; i+2 < len(m); i++ {
		if m[i] >= '0' && m[i] <= '9' && m[i+1] == '.' && m[i+2] >= '0' && m[i+2] <= '9' {
			return true
		}
	}
	return false
}

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
// axis's probability. One retry on 429/529; every other failure, a missing
// answer, a probability outside [0,1] or a response naming a model other
// than the pinned one is an error.
func (j *TypeSafeJudge) ask(ctx context.Context, path, chunk, declared string, cats []JudgeCategory, usage *JudgeUsage) (map[JudgeCategory]float64, error) {
	qs := make(map[string]any, len(cats))
	for _, c := range cats {
		qs[string(c)] = map[string]any{"type": "noul", "instructions": typesafeQuestions[c]}
	}
	payload, err := json.Marshal(map[string]any{
		"model":     j.model,
		"state":     map[string]string{"path": path, "content": chunk, "declared_capabilities": declared},
		"questions": qs,
	})
	if err != nil {
		return nil, fmt.Errorf("scan: typesafe payload: %w", err)
	}
	raw, err := j.post(ctx, payload)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Model   string `json:"model"`
		Answers map[string]struct {
			Type string   `json:"type"`
			Noul *float64 `json:"noul"`
		} `json:"answers"`
		Usage *struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("scan: typesafe response is not the answer shape: %w", err)
	}
	if resp.Model != j.model {
		return nil, fmt.Errorf("scan: typesafe served model %q, not the pinned %q", resp.Model, j.model)
	}
	out := make(map[JudgeCategory]float64, len(cats))
	for _, c := range cats {
		a, ok := resp.Answers[string(c)]
		if !ok || a.Noul == nil {
			return nil, fmt.Errorf("scan: typesafe answered without the %s axis", c)
		}
		if *a.Noul < 0 || *a.Noul > 1 {
			return nil, fmt.Errorf("scan: typesafe probability %v for %s out of range", *a.Noul, c)
		}
		out[c] = *a.Noul
	}
	if resp.Usage != nil && usage != nil {
		usage.PromptTokens += resp.Usage.InputTokens
		usage.CompletionTokens += resp.Usage.OutputTokens
	}
	return out, nil
}

// post sends the payload, retrying once on 429/529 after retryWait. The
// error carries a bounded snippet of the vendor's body with the key
// redacted, since the error reaches the stage log and the report.
func (j *TypeSafeJudge) post(ctx context.Context, payload []byte) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		raw, status, err := j.once(ctx, payload)
		if err != nil {
			return nil, err
		}
		if status == http.StatusOK {
			return raw, nil
		}
		snippet := string(raw)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		if j.apiKey != "" {
			snippet = strings.ReplaceAll(snippet, j.apiKey, "[key]")
		}
		retryable := status == http.StatusTooManyRequests || status == 529
		if !retryable || attempt >= 1 {
			return nil, fmt.Errorf("scan: typesafe endpoint returned %d: %s", status, snippet)
		}
		if j.retryWait > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("scan: typesafe request: %w", ctx.Err())
			case <-time.After(j.retryWait):
			}
		}
	}
}

func (j *TypeSafeJudge) once(ctx context.Context, payload []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, fmt.Errorf("scan: typesafe request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+j.apiKey)
	resp, err := j.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("scan: typesafe request: %w", redactErr(err, j.apiKey))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("scan: typesafe response: %w", err)
	}
	return raw, resp.StatusCode, nil
}

// redactErr strips the key from a transport error's text (a URL error can
// echo the request), keeping the error otherwise intact.
func redactErr(err error, key string) error {
	if key == "" || !strings.Contains(err.Error(), key) {
		return err
	}
	return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), key, "[key]")) //nolint:err113 // the wrapped text held the key
}
