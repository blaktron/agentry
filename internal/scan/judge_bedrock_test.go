package scan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

type fakeConverse struct {
	in   *bedrockruntime.ConverseInput
	out  *bedrockruntime.ConverseOutput
	err  error
	call int
	// left is how long the call's context had to run when the call came in;
	// bounded is whether it had a deadline at all.
	left    time.Duration
	bounded bool
}

func (f *fakeConverse) Converse(ctx context.Context, in *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	f.call++
	f.in = in
	if d, ok := ctx.Deadline(); ok {
		f.bounded, f.left = true, time.Until(d)
	}
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

	// One call is bounded to 90 seconds, goes to the configured model as a
	// user message, and the judge names itself and what it reads.
	if !f.bounded || f.left > 90*time.Second || f.left < 60*time.Second {
		t.Fatalf("the call must run under a 90s deadline: bounded %v, left %v", f.bounded, f.left)
	}
	if got := f.in.Messages[0].Role; got != types.ConversationRoleUser || len(f.in.Messages) != 1 {
		t.Fatalf("one user message, got %d with role %v", len(f.in.Messages), got)
	}
	g := &fakeConverse{out: converseText(testVerdictJSON)}
	named := newBedrockJudge(g, "my.model-v1")
	nv, err := named.Judge(context.Background(), judgeTestContent())
	if err != nil {
		t.Fatal(err)
	}
	if *g.in.ModelId != "my.model-v1" || nv.Model != "my.model-v1" || named.ModelID() != "my.model-v1" {
		t.Fatalf("a configured model is the one asked and recorded: request %q verdict %q provider %q", *g.in.ModelId, nv.Model, named.ModelID())
	}
	if blank := newBedrockJudge(g, "  "); blank.ModelID() != defaultBedrockModel {
		t.Fatalf("a blank model is the default, got %q", blank.ModelID())
	}
	if j.Name() != "bedrock" || j.InputLimit() != 256<<10 || j.RequiresHumanReview() {
		t.Fatalf("contract: %q %d %v", j.Name(), j.InputLimit(), j.RequiresHumanReview())
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

	// Each refusal names itself, and a provider error stays reachable.
	apiErr := errors.New("ThrottlingException")
	_, err := newBedrockJudge(&fakeConverse{err: apiErr}, "m").Judge(context.Background(), judgeTestContent())
	if !errors.Is(err, apiErr) || !strings.Contains(err.Error(), "scan: bedrock judge: ThrottlingException") {
		t.Fatalf("api error: %v", err)
	}
	for name, c := range map[string]struct {
		f    *fakeConverse
		want string
	}{
		"no response at all":         {&fakeConverse{}, "scan: bedrock judge: empty response"},
		"no output":                  {&fakeConverse{out: &bedrockruntime.ConverseOutput{}}, "scan: bedrock judge: empty response"},
		"an output of another kind":  {&fakeConverse{out: &bedrockruntime.ConverseOutput{Output: &types.UnknownUnionMember{Tag: "other"}}}, "unexpected output type"},
		"a reply with no text block": {&fakeConverse{out: &bedrockruntime.ConverseOutput{Output: &types.ConverseOutputMemberMessage{Value: types.Message{Content: []types.ContentBlock{&types.ContentBlockMemberToolUse{}}}}}}, "scan: bedrock judge: response carries no text"},
		"a reply of empty text":      {&fakeConverse{out: converseText("")}, "scan: bedrock judge: response carries no text"},
	} {
		if _, err := newBedrockJudge(c.f, "m").Judge(context.Background(), judgeTestContent()); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, c.want)
		}
	}

	// A reply in several text blocks is one text, and a block of another kind
	// between them is not part of it.
	half := len(testVerdictJSON) / 2
	split := &bedrockruntime.ConverseOutput{Output: &types.ConverseOutputMemberMessage{Value: types.Message{Content: []types.ContentBlock{
		&types.ContentBlockMemberText{Value: testVerdictJSON[:half]},
		&types.ContentBlockMemberToolUse{},
		&types.ContentBlockMemberText{Value: testVerdictJSON[half:]},
	}}}}
	if v, err := newBedrockJudge(&fakeConverse{out: split}, "m").Judge(context.Background(), judgeTestContent()); err != nil || v.Scores[CatExfiltration] != 3 {
		t.Fatalf("a verdict split over text blocks: %+v %v", v, err)
	}
}

// Converse reports token use in its own Usage block; the judge records it,
// and a reply without one records nothing rather than zero.
func TestBedrockJudgeRecordsUsage(t *testing.T) {
	out := converseText(testVerdictJSON)
	out.Usage = &types.TokenUsage{InputTokens: aws.Int32(700), OutputTokens: aws.Int32(60)}
	v, err := newBedrockJudge(&fakeConverse{out: out}, "").Judge(context.Background(), judgeTestContent())
	if err != nil {
		t.Fatal(err)
	}
	if v.Usage == nil || v.Usage.PromptTokens != 700 || v.Usage.CompletionTokens != 60 {
		t.Fatalf("usage: %+v", v.Usage)
	}
	v, err = newBedrockJudge(&fakeConverse{out: converseText(testVerdictJSON)}, "").Judge(context.Background(), judgeTestContent())
	if err != nil {
		t.Fatal(err)
	}
	if v.Usage != nil {
		t.Fatalf("usage must be nil without a Usage block, got %+v", *v.Usage)
	}
	// A Usage block missing either count is not a measurement.
	for name, u := range map[string]*types.TokenUsage{
		"input only":  {InputTokens: aws.Int32(7)},
		"output only": {OutputTokens: aws.Int32(7)},
		"neither":     {},
	} {
		part := converseText(testVerdictJSON)
		part.Usage = u
		v, err := newBedrockJudge(&fakeConverse{out: part}, "").Judge(context.Background(), judgeTestContent())
		if err != nil || v.Usage != nil {
			t.Errorf("%s: usage %+v err %v, want none", name, v.Usage, err)
		}
	}
}
