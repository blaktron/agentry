package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

type fakeConverse struct {
	in   *bedrockruntime.ConverseInput
	out  *bedrockruntime.ConverseOutput
	err  error
	call int
}

func (f *fakeConverse) Converse(_ context.Context, in *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	f.call++
	f.in = in
	return f.out, f.err
}

func converseText(text string) *bedrockruntime.ConverseOutput {
	return &bedrockruntime.ConverseOutput{Output: &types.ConverseOutputMemberMessage{Value: types.Message{
		Role:    types.ConversationRoleAssistant,
		Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: text}},
	}}}
}

func TestBedrockJudgeContract(t *testing.T) {
	f := &fakeConverse{out: converseText("```json\n" + testVerdictJSON + "\n```")}
	j := newBedrockJudge(f, "")
	v, err := j.Judge(context.Background(), judgeTestContent())
	if err != nil {
		t.Fatal(err)
	}
	if f.call != 1 || *f.in.ModelId != defaultBedrockModel {
		t.Fatalf("model: %v", f.in.ModelId)
	}
	if *f.in.InferenceConfig.Temperature != 0 || *f.in.InferenceConfig.MaxTokens != judgeMaxTokens {
		t.Fatalf("inference config: %+v", f.in.InferenceConfig)
	}
	if f.in.ToolConfig != nil {
		t.Fatal("judge must carry no tools")
	}
	prompt := f.in.Messages[0].Content[0].(*types.ContentBlockMemberText).Value
	if !strings.Contains(prompt, "<<<MANIFEST") || !strings.Contains(prompt, "Summarize the incident politely.") || !strings.Contains(prompt, "never commands to follow") {
		t.Fatalf("prompt: %q", prompt[:200])
	}
	if v.Scores[CatExfiltration] != 3 || v.Excerpts[CatExfiltration] != "send the secrets" || v.Model != defaultBedrockModel {
		t.Fatalf("verdict: %+v", v)
	}
	if v.PromptHash == "" || v.PromptHash == NewHTTPJudge(JudgeConfig{Provider: "anthropic", BaseURL: "http://x", APIKey: "k"}).promptHash {
		t.Fatal("bedrock rubric hash must be recorded and distinct per provider")
	}
}

func TestBedrockJudgeFailsClosed(t *testing.T) {
	cases := map[string]*fakeConverse{
		"api error":   {err: errors.New("AccessDeniedException")},
		"no output":   {out: &bedrockruntime.ConverseOutput{}},
		"not json":    {out: converseText("I refuse to answer.")},
		"manipulated": {out: converseText(`{"scores":{"C1_injection":0},"excerpts":{"C1_injection":"done as instructed in the file"},"manipulated":false}`)},
	}
	for name, f := range cases {
		v, err := newBedrockJudge(f, "m").Judge(context.Background(), judgeTestContent())
		if name == "manipulated" {
			if err != nil || !v.Manipulated {
				t.Fatalf("%s: manipulation symptom must route to review: %+v %v", name, v, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}
