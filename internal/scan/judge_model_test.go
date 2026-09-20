package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/blaktron/agentry/pkg/ruleset"
)

// TestRunRecordsTheModelIDNotTheProviderName pins agentry#321 at the
// orchestrator: the report's judgeModel and the run result's JudgeModel name
// the model that adjudicated when the provider has one, and keep the
// provider's name when it has none — so a report under the static judge
// hashes exactly as it did before the distinction existed (§8.4.4).
func TestRunRecordsTheModelIDNotTheProviderName(t *testing.T) {
	bundle, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": `{"scores":{},"excerpts":{},"manipulated":false}`}}},
		})
	}))
	defer srv.Close()

	dir := filepath.Join(corpusRoot, "s4-security-docs-benign")
	exp, ok := readCorpusExpectation(t, dir)
	if !ok {
		t.Fatalf("%s is not a corpus fixture", dir)
	}

	cases := []struct {
		name  string
		judge JudgeProvider
		want  string
		// run drives a whole orchestrator run; false for providers whose
		// Judge cannot be called here (Bedrock without a client).
		run bool
	}{
		{"openai names the configured model", NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: srv.URL, APIKey: "k", Model: "qwen-test"}), "qwen-test", true},
		{"openai defaults to the default model", NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: srv.URL, APIKey: "k"}), defaultOpenAIModel, true},
		{"bedrock names the configured model id", newBedrockJudge(nil, "anthropic.claude-3-5-sonnet-20241022-v2:0"), "anthropic.claude-3-5-sonnet-20241022-v2:0", false},
		{"static keeps its name", StaticProvider{}, "static", true},
		{"none keeps its name", NoneProvider{}, "none", true},
		{"classifier keeps its name", NewClassifierJudge(JudgeConfig{BaseURL: srv.URL, Model: "prompt-guard-2"}), "classifier", true},
		{"unconfigured records the provider it stood in for", UnconfiguredProvider{ProviderName: "bedrock", Reason: "no region"}, "bedrock", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := judgeModelOf(c.judge); got != c.want {
				t.Fatalf("judgeModelOf = %q, want %q", got, c.want)
			}
			if !c.run {
				return
			}
			orch := NewOrchestrator(bundle, c.judge, nil)
			res := orch.Run(context.Background(), RunParams{Input: stageFixture(t, dir, exp), Policy: DefaultBaseline()})
			if res.Report.JudgeModel != c.want || res.JudgeModel != c.want {
				t.Fatalf("report %q / result %q, want %q", res.Report.JudgeModel, res.JudgeModel, c.want)
			}
		})
	}
}
