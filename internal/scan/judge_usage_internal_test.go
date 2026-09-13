package scan

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// usageJudge answers a clean verdict and reports a fixed token use.
type usageJudge struct{ usage *JudgeUsage }

func (usageJudge) Name() string              { return "usage-test" }
func (usageJudge) RequiresHumanReview() bool { return false }
func (u usageJudge) Judge(context.Context, JudgeContent) (JudgeVerdict, error) {
	return JudgeVerdict{Scores: map[JudgeCategory]int{}, Model: "m", PromptHash: "sha256:x", Usage: u.usage}, nil
}

// TestJudgeUsageReachesTheRunAndNotTheReport pins two things about where the
// judge's token use goes (plan subscription-tiers §10). S5 lifts it onto the
// run result so the scan run can record it; and the canonical S10 report —
// whose digest is the subject of the signed attestation and must be
// reproducible — never carries it, because a token count varies from one
// run of the same bytes to the next.
func TestJudgeUsageReachesTheRunAndNotTheReport(t *testing.T) {
	o := NewOrchestrator(nil, usageJudge{&JudgeUsage{PromptTokens: 5, CompletionTokens: 2}}, slog.New(slog.DiscardHandler))
	res := S5Judge{}.Run(stageContext{ctx: context.Background(), log: o.log, judge: o.judge}, &Input{ManifestJSON: []byte(`{}`)})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if res.JudgeUsage == nil || res.JudgeUsage.PromptTokens != 5 || res.JudgeUsage.CompletionTokens != 2 {
		t.Fatalf("S5 must lift the judge's usage onto its result, got %+v", res.JudgeUsage)
	}

	raw, err := json.Marshal(Report{SchemaVersion: "1", JudgeModel: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "usage") || strings.Contains(string(raw), "token") {
		t.Fatalf("the signed report must not carry token use: %s", raw)
	}
}
