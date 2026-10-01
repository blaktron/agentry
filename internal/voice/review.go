package voice

import (
	"context"
	"fmt"
	"slices"

	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/pkg/judge"
)

// ReportSchema names a review report's shape.
const ReportSchema = "agentry.voice-review/v1"

// Verdict is a review's answer.
type Verdict string

// A review passes a version, flags it, or did not finish: a stage failed
// or the judge could not answer, and the version stays in review.
const (
	VerdictPass       Verdict = "pass"
	VerdictFlagged    Verdict = "flagged"
	VerdictIncomplete Verdict = "incomplete"
)

// ScannerAIReview names a finding of the voice question set.
const ScannerAIReview = "S5/voice"

// Report is what a version's review read and found. It keeps no excerpt:
// it is in the clear beside a sealed text, so it says where a finding is
// (a line, or a question of AI Review), never the words there.
type Report struct {
	Schema   string           `json:"schema"`
	Verdict  Verdict          `json:"verdict"`
	Stages   []scan.PackStage `json:"stages"`
	Findings []Finding        `json:"findings"`
	AIReview AIReview         `json:"aiReview"`
}

// Finding is one thing the review found. Flags says whether it is what
// keeps the version from going live: a rule finding of medium severity or
// above, or a question of the voice set scored at the withhold line.
type Finding struct {
	Scanner  string `json:"scanner"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Line     int    `json:"line,omitempty"`
	Question string `json:"question,omitempty"`
	Score    int    `json:"score,omitempty"`
	Flags    bool   `json:"flags"`
}

// AIReview is the voice question set's record: the model, the set's hash,
// each question's score, and why it did not answer when it did not.
type AIReview struct {
	Model       string         `json:"model,omitempty"`
	QuestionSet string         `json:"questionSet,omitempty"`
	Scores      map[string]int `json:"scores,omitempty"`
	Failure     string         `json:"failure,omitempty"`
	Requests    int            `json:"requests"`
	InputTokens int            `json:"inputTokens"`
}

// ProseScanner runs the pack scan's rule stages over text files: the
// scan orchestrator's ScanProse.
type ProseScanner interface {
	ScanProse(ctx context.Context, files []scan.PackFile) scan.PackReport
}

// Judge asks the voice question set: *judge.VoiceScanner.
type Judge interface {
	Scan(ctx context.Context, voice string) judge.VoiceResult
	QuestionSet() string
}

// Reviewer reviews a version: the rule stages, then the voice set.
type Reviewer struct {
	rules ProseScanner
	judge Judge
}

// NewReviewer builds a reviewer; with no judge there is none, and the
// store is off, since no version could ever pass.
func NewReviewer(rules ProseScanner, j Judge) *Reviewer {
	if rules == nil || j == nil {
		return nil
	}
	return &Reviewer{rules: rules, judge: j}
}

// QuestionSet is the hash of the set a review asks now.
func (r *Reviewer) QuestionSet() string { return r.judge.QuestionSet() }

// flagSeverity is the least severity a rule finding flags a voice at.
var flagSeverity = []scan.Severity{scan.SevMedium, scan.SevHigh, scan.SevCritical}

// Review reads text and answers its report. It never fails: a stage that
// failed, or a judge that did not answer, is a report whose verdict is
// incomplete.
func (r *Reviewer) Review(ctx context.Context, text string) Report {
	rep := Report{Schema: ReportSchema, Findings: []Finding{}}
	prose := r.rules.ScanProse(ctx, []scan.PackFile{{Path: File, Content: []byte(text)}})
	rep.Stages = prose.Stages
	complete := prose.Complete() && len(prose.Read.NotRead) == 0
	flagged := false
	for _, f := range prose.Findings {
		flags := slices.Contains(flagSeverity, f.Severity)
		flagged = flagged || flags
		rep.Findings = append(rep.Findings, Finding{Scanner: f.Scanner, Severity: string(f.Severity), Title: f.Title, Line: f.Line, Flags: flags})
	}
	rep.Stages = append(rep.Stages, scan.PackStage{ID: "S5", Name: "AI Review"})
	res := r.judge.Scan(ctx, text)
	rep.AIReview = AIReview{Model: res.Model, QuestionSet: res.QuestionSet, Scores: res.Scores, Failure: res.Failure,
		Requests: res.Usage.Requests, InputTokens: res.Usage.InputTokens}
	// An answer is read only when it is a verdict and every question of the
	// set was scored; anything less is not a review, and fails closed.
	answered := res.Verdict == judge.VerdictPass || res.Verdict == judge.VerdictFlagged
	for _, q := range judge.VoiceQuestions() {
		if _, ok := res.Scores[q.ID]; !ok {
			answered = false
		}
	}
	if !answered {
		rep.Stages[len(rep.Stages)-1].Failed = true
		complete = false
	}
	switch res.Verdict {
	case judge.VerdictPass, judge.VerdictFlagged:
		if res.Verdict == judge.VerdictFlagged {
			flagged = true
		}
		for _, q := range judge.VoiceQuestions() {
			sc := res.Scores[q.ID]
			if sc < judge.WithholdScore {
				continue
			}
			flagged = true
			// The judge's 0–3 scale: 2 is the gate's medium, 3 its high.
			sev := scan.SevMedium
			if sc > judge.WithholdScore {
				sev = scan.SevHigh
			}
			rep.Findings = append(rep.Findings, Finding{Scanner: ScannerAIReview, Severity: string(sev),
				Title: fmt.Sprintf("AI Review: %s", q.ID), Question: q.ID, Score: sc, Flags: true})
		}
	}
	// A flag stands even when a stage did not finish: the version cannot
	// pass whatever the rest would have said.
	switch {
	case flagged:
		rep.Verdict = VerdictFlagged
	case !complete:
		rep.Verdict = VerdictIncomplete
	default:
		rep.Verdict = VerdictPass
	}
	return rep
}
