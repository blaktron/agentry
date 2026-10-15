package scan

import (
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

// usageJudge answers a clean verdict and reports a fixed token use.
type usageJudge struct{ usage *JudgeUsage }

func (usageJudge) Name() string              { return "usage-test" }
func (usageJudge) RequiresHumanReview() bool { return false }
func (usageJudge) ModelID() string           { return "" }
func (usageJudge) InputLimit() int           { return 0 }
func (u usageJudge) Judge(context.Context, JudgeContent) (JudgeVerdict, error) {
	return JudgeVerdict{Scores: map[JudgeCategory]int{}, Model: "m", PromptHash: "sha256:x", Usage: u.usage}, nil
}

// TestJudgeUsageReachesTheRunAndNotTheReport pins two things about where the
// judge's token use goes. S5 lifts it onto the
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

	usageType := reflect.TypeOf(JudgeUsage{})
	rt := reflect.TypeOf(Report{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft == usageType || strings.Contains(strings.ToLower(f.Name), "usage") {
			t.Fatalf("Report.%s would put token use into the signed report", f.Name)
		}
	}
}
