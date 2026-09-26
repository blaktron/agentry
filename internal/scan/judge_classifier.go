package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ClassifierJudge is the PromptGuard-class provider (D-13 "classifier";
// DEV-007/DEV-054 stub, agentry#41): a text-classification endpoint that
// returns per-label probabilities for prompt-injection / jailbreak content.
// It speaks the Hugging Face text-classification wire shape, which the
// Inference API, TGI/TEI and most self-hosted servers share:
//
//	POST <baseUrl>            {"inputs": "<text>"}
//	200  [[{"label":"INJECTION","score":0.98},{"label":"BENIGN","score":0.02}]]
//
// (a flat [{label,score}] list is accepted too). A classifier scores ONE
// rubric axis — C1_injection — so this provider forces human review
// (RequiresHumanReview = true, like `none`): it adds evidence for the
// reviewer and can never auto-clear a version, because C2–C6 go unscored.
// Operators who want auto-clearing need an LLM provider; a classifier is a
// cheap, deterministic pre-screen, not a judge of the whole rubric.
type ClassifierJudge struct {
	endpoint   string
	apiKey     string
	model      string
	client     *http.Client
	promptHash string
}

// classifierMaxInput bounds one request body; longer files are chunked.
const classifierMaxInput = 8 << 10

// NewClassifierJudge builds the provider. BaseURL is the full classify URL
// (config validates it is set); APIKey is optional (Bearer); Model names the
// deployed classifier for the record and defaults to "prompt-guard".
func NewClassifierJudge(cfg JudgeConfig) *ClassifierJudge {
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = "prompt-guard"
	}
	return &ClassifierJudge{
		endpoint: strings.TrimSpace(cfg.BaseURL), apiKey: cfg.APIKey, model: model,
		client:     &http.Client{Timeout: 60 * time.Second},
		promptHash: RubricHash(rubricStatement, "provider=classifier", "model="+model, "axis=C1_injection", "thresholds=0.5/0.7/0.9"),
	}
}

// Name implements JudgeProvider.
func (j *ClassifierJudge) Name() string { return "classifier" }

// RequiresHumanReview implements JudgeProvider: one axis is not the rubric.
func (j *ClassifierJudge) RequiresHumanReview() bool { return true }

// ModelID implements JudgeProvider: the classifier's Model is a deployment
// label ("prompt-guard" by default), not a versioned model id, so the run
// keeps recording the provider's name (agentry#321).
func (j *ClassifierJudge) ModelID() string { return "" }

// InputLimit implements JudgeProvider: a call is split into requests of
// classifierMaxInput, and eight of them bound one call.
func (j *ClassifierJudge) InputLimit() int { return 8 * classifierMaxInput }

// injectionLabel reports whether a classifier label names the positive
// class. PromptGuard uses INJECTION/JAILBREAK; others use LABEL_1 with the
// positive class second, or "unsafe".
func injectionLabel(label string) bool {
	l := strings.ToUpper(strings.TrimSpace(label))
	switch {
	case strings.Contains(l, "INJECTION"), strings.Contains(l, "JAILBREAK"), l == "UNSAFE", l == "MALICIOUS", l == "LABEL_1":
		return true
	}
	return false
}

// Judge implements JudgeProvider: the C1 score is the max injection
// probability over all chunks of all prose files, mapped 0.5/0.7/0.9 → 1/2/3.
func (j *ClassifierJudge) Judge(ctx context.Context, content JudgeContent) (JudgeVerdict, error) {
	v := JudgeVerdict{
		Scores:     map[JudgeCategory]int{},
		Excerpts:   map[JudgeCategory]string{},
		Model:      j.model,
		PromptHash: j.promptHash,
	}
	var best float64
	var bestExcerpt string
	inputs := []JudgeFile{{Path: "agent.yaml", Content: string(content.ManifestJSON)}}
	inputs = append(inputs, content.Files...)
	for _, f := range inputs {
		for _, chunk := range chunkText(f.Content, classifierMaxInput) {
			if strings.TrimSpace(chunk) == "" {
				continue
			}
			p, err := j.classify(ctx, chunk)
			if err != nil {
				return JudgeVerdict{}, err // fail closed (§8.4.6)
			}
			if p > best {
				best = p
				bestExcerpt = f.Path + ": " + excerptLine(firstLine(chunk))
			}
		}
	}
	if s := scoreFromProbability(best); s > 0 {
		v.Scores[CatInjection] = s
		v.Excerpts[CatInjection] = fmt.Sprintf("p=%.2f %s", best, bestExcerpt)
	}
	return v, nil
}

// classify posts one chunk and returns the injection probability.
func (j *ClassifierJudge) classify(ctx context.Context, text string) (float64, error) {
	payload, err := json.Marshal(map[string]any{"inputs": text})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("scan: classifier request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if j.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+j.apiKey)
	}
	resp, err := j.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("scan: classifier request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("scan: classifier response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		snippet := string(raw)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return 0, fmt.Errorf("scan: classifier endpoint returned %d: %s", resp.StatusCode, snippet)
	}
	return parseClassifierScores(raw)
}

// parseClassifierScores accepts [[{label,score}]] or [{label,score}] and
// returns the highest positive-class probability.
func parseClassifierScores(raw []byte) (float64, error) {
	type ls struct {
		Label string  `json:"label"`
		Score float64 `json:"score"`
	}
	var nested [][]ls
	var flat []ls
	switch {
	case json.Unmarshal(raw, &nested) == nil && len(nested) > 0:
		flat = nested[0]
	case json.Unmarshal(raw, &flat) == nil:
	default:
		return 0, errors.New("scan: classifier output is not a label/score list")
	}
	if len(flat) == 0 {
		return 0, errors.New("scan: classifier returned no labels")
	}
	sort.SliceStable(flat, func(i, k int) bool { return flat[i].Label < flat[k].Label })
	var best float64
	var positive bool
	for _, e := range flat {
		if injectionLabel(e.Label) {
			positive = true
			if e.Score > best {
				best = e.Score
			}
		}
	}
	if !positive {
		return 0, fmt.Errorf("scan: classifier labels carry no injection class (%s)", flat[0].Label)
	}
	if best < 0 || best > 1 {
		return 0, fmt.Errorf("scan: classifier score %v out of range", best)
	}
	return best, nil
}

// chunkText splits s into pieces of at most n bytes on line boundaries
// where possible. It is the publication scan's own split, kept byte for
// byte: the rubric hash names the chunk size, and a change to where a
// chunk ends changes what Jev and the classifier read. The model-input
// scan uses judge.Chunk, which also never cuts inside a character.
func chunkText(s string, n int) []string {
	if len(s) <= n {
		return []string{s}
	}
	var out []string
	for len(s) > n {
		cut := strings.LastIndexByte(s[:n], '\n')
		if cut < n/2 {
			cut = n
		}
		out = append(out, s[:cut])
		s = s[cut:]
	}
	return append(out, s)
}
