package scan

import (
	"context"
	"encoding/json"
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

	// A whole run carries it, and the rubric version, onto its result and not
	// into the report that is hashed and signed.
	run := hardeningRun(t, usageJudge{&JudgeUsage{PromptTokens: 5, CompletionTokens: 2}}, RunParams{})
	if run.JudgeUsage == nil || *run.JudgeUsage != (JudgeUsage{PromptTokens: 5, CompletionTokens: 2}) || run.JudgePromptHash != "sha256:x" {
		t.Fatalf("run usage %+v, rubric %q", run.JudgeUsage, run.JudgePromptHash)
	}
	if blob, _ := json.Marshal(run.Report); strings.Contains(string(blob), "promptTokens") || strings.Contains(string(blob), `"usage"`) {
		t.Fatalf("the signed report carries the usage: %s", blob)
	}
	if none := hardeningRun(t, usageJudge{}, RunParams{}); none.JudgeUsage != nil {
		t.Fatalf("a judge that reports no use leaves none: %+v", none.JudgeUsage)
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
