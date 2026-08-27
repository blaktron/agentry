package scan

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// S5 judge (§8.4). The judge reviews manifest + prose/instruction files with
// a fixed rubric and returns per-category structured scores. It is itself an
// injection target, so it has no tools, temperature 0, bounded output, and a
// manipulated-judge symptom (§8.4.3) routes to review.

// JudgeCategory is one rubric axis (§8.5 S5 categories C1–C6).
type JudgeCategory string

// The six rubric categories.
const (
	CatInjection     JudgeCategory = "C1_injection"    // override of the consuming agent
	CatExfiltration  JudgeCategory = "C2_exfiltration" // data exfiltration directives
	CatUndeclaredCap JudgeCategory = "C3_undeclared_capability"
	CatDeception     JudgeCategory = "C4_user_deception"
	CatObfuscation   JudgeCategory = "C5_obfuscation"
	CatDestructive   JudgeCategory = "C6_destructive_actions"
)

// AllJudgeCategories lists the rubric.
func AllJudgeCategories() []JudgeCategory {
	return []JudgeCategory{CatInjection, CatExfiltration, CatUndeclaredCap, CatDeception, CatObfuscation, CatDestructive}
}

// JudgeVerdict is the judge's structured output. Scores are 0–3 per category
// (§8.5: 3 ⇒ high finding, 2 ⇒ medium).
type JudgeVerdict struct {
	Scores map[JudgeCategory]int `json:"scores"`
	// Cited excerpts per category (evidence, not directives).
	Excerpts map[JudgeCategory]string `json:"excerpts"`
	// Manipulated is set when the provider detected instruction-following
	// symptoms in its own output (§8.4.3) — always routes to review.
	Manipulated bool `json:"manipulated"`
	// Model and PromptHash record reproducibility (§8.4.4).
	Model      string `json:"model"`
	PromptHash string `json:"promptHash"`
}

// JudgeProvider is the D-13 provider interface.
type JudgeProvider interface {
	// Name identifies the provider (bedrock|anthropic|classifier|none|static).
	Name() string
	// Judge adjudicates the presented content (manifest + prose files).
	Judge(ctx context.Context, content JudgeContent) (JudgeVerdict, error)
	// RequiresHumanReview reports whether this provider forces review
	// regardless of scores (the `none` provider does, §8.4.6).
	RequiresHumanReview() bool
}

// JudgeContent is what the judge sees: manifest plus prose files, presented
// as DATA inside delimited blocks by the provider (§8.4.1).
type JudgeContent struct {
	ManifestJSON []byte
	Files        []JudgeFile
}

// JudgeFile is one prose/instruction file for adjudication.
type JudgeFile struct {
	Path    string
	Content string
}

// NoneProvider skips S5 and forces human review (§8.4.6): self-host without
// an LLM. The gate treats every version as if it had one medium finding.
type NoneProvider struct{}

// Name implements JudgeProvider.
func (NoneProvider) Name() string { return "none" }

// RequiresHumanReview implements JudgeProvider.
func (NoneProvider) RequiresHumanReview() bool { return true }

// Judge implements JudgeProvider: no scores, review forced by the gate.
func (NoneProvider) Judge(_ context.Context, _ JudgeContent) (JudgeVerdict, error) {
	return JudgeVerdict{Scores: map[JudgeCategory]int{}, Model: "none"}, nil
}

// StaticProvider is a deterministic heuristic judge used in dev/tests
// (DEV-007): it scores categories from strong lexical signals so the gate and
// review flow are exercisable without a live model. It is NOT a substitute
// for a real LLM in production and never auto-clears with high confidence
// beyond what the signals justify.
type StaticProvider struct{}

// Name implements JudgeProvider.
func (StaticProvider) Name() string { return "static" }

// RequiresHumanReview implements JudgeProvider.
func (StaticProvider) RequiresHumanReview() bool { return false }

var (
	reInjection    = regexp.MustCompile(`(?i)ignore (?:all |your )?(?:previous|prior|above) instructions|disregard (?:the|all) (?:system|previous)`)
	reExfiltration = regexp.MustCompile(`(?i)(?:send|post|upload|email|exfiltrate|leak)[^.\n]{0,40}(?:the )?(?:conversation|contents|data|secrets|credentials|history)`)
	// Destructive actions must name a destructive OPERATION on a target —
	// not merely a word that also has innocent senses ("format" in "output
	// format", "drop" in "drop a note"). Each alternative below is anchored
	// to an object that makes the destructive reading unambiguous.
	reDestructive = regexp.MustCompile(`(?i)` +
		`rm\s+-[a-z]*[rf][a-z]*\s|` + // rm -rf, rm -fr, rm -r
		`\bdelete\s+(?:all|every|the\s+entire)\b|` +
		`\b(?:wipe|erase)\s+(?:all|every|the\s+)?(?:disk|drive|volume|database|repo|repositor|file|data|directory|folder)|` +
		`\bformat\s+(?:the\s+)?(?:disk|drive|volume|partition|filesystem|/dev/)|` +
		`\bdrop\s+(?:table|database|schema)\b|` +
		`\b(?:destroy|obliterate)\s+(?:all|every|the\s+)?(?:data|database|backup|volume|resource)|` +
		`\bgit\s+push\s+--force\b|` +
		`\btruncate\s+table\b`)
	reDeception    = regexp.MustCompile(`(?i)(?:do not (?:tell|inform|reveal)|without (?:telling|informing)|hide (?:this )?from) the user`)
	reManipSymptom = regexp.MustCompile(`(?i)as (?:instructed|requested) (?:in|by) (?:the|this) (?:file|document|content)`)
)

// Judge implements JudgeProvider with deterministic lexical scoring.
func (StaticProvider) Judge(_ context.Context, content JudgeContent) (JudgeVerdict, error) {
	v := JudgeVerdict{
		Scores:   map[JudgeCategory]int{},
		Excerpts: map[JudgeCategory]string{},
		Model:    "static-heuristic-v1",
	}
	score := func(cat JudgeCategory, re *regexp.Regexp, text string) {
		if m := re.FindString(text); m != "" {
			if v.Scores[cat] < 3 {
				v.Scores[cat] = 3
			}
			if v.Excerpts[cat] == "" {
				v.Excerpts[cat] = strings.TrimSpace(m)
			}
		}
	}
	for _, f := range content.Files {
		score(CatInjection, reInjection, f.Content)
		score(CatExfiltration, reExfiltration, f.Content)
		score(CatDestructive, reDestructive, f.Content)
		score(CatDeception, reDeception, f.Content)
		if reManipSymptom.MatchString(f.Content) {
			v.Manipulated = true
		}
	}
	return v, nil
}

// UnconfiguredProvider stands in for bedrock/anthropic until wired (DEV-007).
type UnconfiguredProvider struct{ ProviderName string }

// Name implements JudgeProvider.
func (u UnconfiguredProvider) Name() string { return u.ProviderName }

// RequiresHumanReview implements JudgeProvider: fail toward review (§8.4.6).
func (UnconfiguredProvider) RequiresHumanReview() bool { return true }

// Judge implements JudgeProvider: returns an error so the orchestrator
// records an S5 stage error and fails closed to review.
func (u UnconfiguredProvider) Judge(_ context.Context, _ JudgeContent) (JudgeVerdict, error) {
	return JudgeVerdict{}, errors.New("scan: judge provider " + u.ProviderName + " is not configured (Q3)")
}

// NewJudgeProvider builds the configured provider.
func NewJudgeProvider(name string) JudgeProvider {
	switch name {
	case "", "none":
		return NoneProvider{}
	case "static":
		return StaticProvider{}
	case "bedrock", "anthropic", "classifier":
		return UnconfiguredProvider{ProviderName: name}
	default:
		return NoneProvider{}
	}
}

// S5Judge adapts the judge into a Stage.
type S5Judge struct{}

func (S5Judge) ID() string { return "S5" }

func (S5Judge) Run(sc stageContext, in *Input) StageResult {
	if sc.judge == nil {
		return StageResult{Scanner: "S5", Err: errors.New("scan: no judge provider")}
	}
	files := make([]JudgeFile, 0, len(in.Files))
	for _, f := range in.Files {
		if f.IsText && f.Content != nil && isProse(f.Path) {
			files = append(files, JudgeFile{Path: f.Path, Content: string(f.Content)})
		}
	}
	verdict, err := sc.judge.Judge(sc.Context(), JudgeContent{ManifestJSON: in.ManifestJSON, Files: files})
	if err != nil {
		return StageResult{Scanner: "S5", Err: err} // fail closed (§8.4.6)
	}

	var findings []Finding
	catTitle := map[JudgeCategory]string{
		CatInjection: "prompt injection / override", CatExfiltration: "data exfiltration",
		CatUndeclaredCap: "undeclared capability described", CatDeception: "end-user deception",
		CatObfuscation: "obfuscation indicators", CatDestructive: "destructive actions without confirmation",
	}
	for _, cat := range AllJudgeCategories() {
		s := verdict.Scores[cat]
		if s < 2 {
			continue
		}
		sev := SevMedium
		if s >= 3 {
			sev = SevHigh
		}
		findings = append(findings, Finding{
			Scanner: "S5/" + string(cat), Severity: sev, Confidence: ConfMedium,
			Title:    "Judge: " + catTitle[cat],
			Excerpt:  verdict.Excerpts[cat],
			Detail:   map[string]any{"category": string(cat), "score": s, "model": verdict.Model},
			Taxonomy: []string{"LLM01", "ASI06"},
		})
	}
	if verdict.Manipulated {
		findings = append(findings, Finding{
			Scanner: "S5/manipulated-judge", Severity: SevHigh, Confidence: ConfMedium,
			Title:    "Judge output shows manipulation symptoms — routing to human review",
			Detail:   map[string]any{"reason": "instruction-following symptom in judge output (§8.4.3)"},
			Taxonomy: []string{"LLM01"},
		})
	}
	return StageResult{Scanner: "S5", Findings: findings}
}

func isProse(path string) bool {
	switch strings.ToLower(pathExt(path)) {
	case ".md", ".markdown", ".txt", ".text", ".yaml", ".yml", ".json", "":
		return true
	}
	return false
}

func pathExt(p string) string {
	for i := len(p) - 1; i >= 0 && p[i] != '/'; i-- {
		if p[i] == '.' {
			return p[i:]
		}
	}
	return ""
}
