package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blaktron/agentry/pkg/judge"
	"github.com/blaktron/agentry/pkg/manifest"
)

// AI Review's persona questions. A persistent release that ships a persona
// is asked two more questions about that file alone (judge.PersonaQuestions):
// whether it has the agent pass for a human, a named real person or a real
// organisation's staff, and whether it carries instructions about tools or
// permissions. A release without a persona is asked nothing more, so its
// rubric hash and its verdict are what they were. Only a provider that asks
// them (PersonaJudge) can review a persona: with any other, S5 fails on such
// a release and the gate sends it to a person.

// The persona questions' categories, the gate's ids for them.
const (
	CatPersonaImpersonation    JudgeCategory = judge.PersonaIDImpersonation
	CatPersonaToolInstructions JudgeCategory = judge.PersonaIDToolInstructions
)

// PersonaJudge is a JudgeProvider that also asks the persona questions.
type PersonaJudge interface {
	// JudgePersona asks the persona questions about the release's persona
	// file. Any failure is an error, and S5 fails closed on it.
	JudgePersona(ctx context.Context, manifestJSON []byte, persona JudgeFile) (PersonaVerdict, error)
}

// PersonaVerdict is what the persona questions found.
type PersonaVerdict struct {
	// Scores are the categories scored above 0, 0–3.
	Scores map[JudgeCategory]int
	// Excerpts locate each scored category's strongest evidence.
	Excerpts map[JudgeCategory]string
	// Model is the model that answered.
	Model string
	// PromptHash is the persona set's hash.
	PromptHash string
	// Usage is the token use of the requests, nil when none was reported.
	Usage *JudgeUsage
}

// errNoPersonaJudge is S5's failure for a persona its provider cannot review.
var errNoPersonaJudge = errors.New("scan: the judge provider does not ask the persona questions, so the persona is not reviewed")

// JudgePersona implements PersonaJudge with pkg/judge's PersonaScanner, the
// same client the rubric asks through.
func (j *TypeSafeJudge) JudgePersona(ctx context.Context, manifestJSON []byte, persona JudgeFile) (PersonaVerdict, error) {
	if j.err != nil {
		return PersonaVerdict{}, fmt.Errorf("scan: typesafe judge: %w", j.err)
	}
	s := judge.NewPersonaScanner(j.client)
	axes, u, err := s.Scan(ctx, manifestJSON, judge.RubricFile{Path: persona.Path, Content: persona.Content})
	if err != nil {
		return PersonaVerdict{}, fmt.Errorf("scan: %w", err)
	}
	v := PersonaVerdict{Scores: map[JudgeCategory]int{}, Excerpts: map[JudgeCategory]string{}, Model: j.model, PromptHash: s.Hash()}
	for id, r := range axes {
		if score := scoreFromProbability(r.Best); score > 0 {
			cat := JudgeCategory(id)
			v.Scores[cat] = score
			v.Excerpts[cat] = fmt.Sprintf("p=%.2f %s: %s", r.Best, r.Path, excerptLine(r.Line))
		}
	}
	if u.InputTokens > 0 || u.OutputTokens > 0 {
		v.Usage = &JudgeUsage{PromptTokens: u.InputTokens, CompletionTokens: u.OutputTokens}
	}
	return v, nil
}

// personaOf is the release's persona file among the inventoried files, or
// nil for a release that ships none (or one S1 could not read as text,
// which S1 reports).
func personaOf(manifestJSON []byte, files []FileEntry) *FileEntry {
	var m manifest.Manifest
	if json.Unmarshal(manifestJSON, &m) != nil {
		return nil
	}
	return textFile(m.PersonaFile(), files)
}

// personaFindings are a persona verdict's findings: either category at a
// score of 2 or more is high (judge.PersonaSeverity), so the version reaches
// a person.
func personaFindings(v PersonaVerdict, path string) []Finding {
	titles := map[JudgeCategory]string{
		CatPersonaImpersonation:    "Judge: the persona presents the agent as a person, a real person or a real organisation's staff",
		CatPersonaToolInstructions: "Judge: the persona carries instructions about tools or permissions",
	}
	var out []Finding
	for _, cat := range []JudgeCategory{CatPersonaImpersonation, CatPersonaToolInstructions} {
		s := v.Scores[cat]
		sev := judge.PersonaSeverity(s)
		if sev == "" {
			continue
		}
		out = append(out, Finding{
			Scanner: "S5/" + string(cat), Severity: Severity(sev), Confidence: ConfMedium,
			Title: titles[cat], FilePath: path, Excerpt: v.Excerpts[cat],
			Detail:   map[string]any{"category": string(cat), "score": s, "model": v.Model},
			Taxonomy: []string{"LLM01", "ASI06"},
		})
	}
	return out
}

// isPersonaCategory reports a persona question's category.
func isPersonaCategory(cat JudgeCategory) bool {
	return cat == CatPersonaImpersonation || cat == CatPersonaToolInstructions
}
