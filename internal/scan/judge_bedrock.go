package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

// BedrockJudge adjudicates through Amazon Bedrock's Converse API (D-13's
// SaaS provider; DEV-007/DEV-054 left it as a stub, agentry#41). Same judge
// contract as HTTPJudge: no tools, temperature 0, bounded output, content
// presented as data under the shared rubric template, fail closed toward
// review on any error. Credentials come from the task role / default chain
// — there is no API key to configure — and the model id from
// AGENTRY_JUDGE_MODEL (terraform sets it; the default below only keeps the
// path runnable).
type BedrockJudge struct {
	api        bedrockConverseAPI
	model      string
	promptHash string
	timeout    time.Duration
}

// bedrockConverseAPI is the slice of the Bedrock runtime client the judge
// uses, so tests can fake the wire.
type bedrockConverseAPI interface {
	Converse(ctx context.Context, in *bedrockruntime.ConverseInput, opts ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}

const defaultBedrockModel = "anthropic.claude-3-5-sonnet-20241022-v2:0"

// NewBedrockJudge builds the provider from the default AWS credential chain.
// Region comes from cfg.Region (AGENTRY_JUDGE_REGION) when set, else the
// SDK's own resolution (AWS_REGION, profile, IMDS).
func NewBedrockJudge(ctx context.Context, cfg JudgeConfig) (*BedrockJudge, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if r := strings.TrimSpace(cfg.Region); r != "" {
		opts = append(opts, awsconfig.WithRegion(r))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("scan: bedrock judge: aws config: %w", err)
	}
	if awsCfg.Region == "" {
		return nil, errors.New("scan: bedrock judge: no AWS region (set AGENTRY_JUDGE_REGION or AWS_REGION)")
	}
	return newBedrockJudge(bedrockruntime.NewFromConfig(awsCfg), cfg.Model), nil
}

func newBedrockJudge(api bedrockConverseAPI, model string) *BedrockJudge {
	if strings.TrimSpace(model) == "" {
		model = defaultBedrockModel
	}
	return &BedrockJudge{
		api: api, model: model, timeout: 90 * time.Second,
		promptHash: RubricHash(rubricStatement, "provider=bedrock", "model="+model, judgePromptTemplate),
	}
}

// Name implements JudgeProvider.
func (j *BedrockJudge) Name() string { return "bedrock" }

// RequiresHumanReview implements JudgeProvider: a live judge scores.
func (j *BedrockJudge) RequiresHumanReview() bool { return false }

// Judge implements JudgeProvider.
func (j *BedrockJudge) Judge(ctx context.Context, content JudgeContent) (JudgeVerdict, error) {
	ctx, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()
	out, err := j.api.Converse(ctx, &bedrockruntime.ConverseInput{
		ModelId: aws.String(j.model),
		Messages: []types.Message{{
			Role:    types.ConversationRoleUser,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: judgePrompt(content)}},
		}},
		InferenceConfig: &types.InferenceConfiguration{
			Temperature: aws.Float32(0),
			MaxTokens:   aws.Int32(judgeMaxTokens),
		},
	})
	if err != nil {
		return JudgeVerdict{}, fmt.Errorf("scan: bedrock judge: %w", err)
	}
	text, err := bedrockResponseText(out)
	if err != nil {
		return JudgeVerdict{}, err
	}
	verdict, err := parseJudgeJSON(text)
	if err != nil {
		return JudgeVerdict{}, err
	}
	if reManipSymptom.MatchString(text) {
		verdict.Manipulated = true
	}
	verdict.Model = j.model
	verdict.PromptHash = j.promptHash
	return verdict, nil
}

// bedrockResponseText concatenates the text blocks of a Converse reply.
func bedrockResponseText(out *bedrockruntime.ConverseOutput) (string, error) {
	if out == nil || out.Output == nil {
		return "", errors.New("scan: bedrock judge: empty response")
	}
	msg, ok := out.Output.(*types.ConverseOutputMemberMessage)
	if !ok {
		return "", fmt.Errorf("scan: bedrock judge: unexpected output type %T", out.Output)
	}
	var sb strings.Builder
	for _, block := range msg.Value.Content {
		if t, ok := block.(*types.ContentBlockMemberText); ok {
			sb.WriteString(t.Value)
		}
	}
	if sb.Len() == 0 {
		return "", errors.New("scan: bedrock judge: response carries no text")
	}
	return sb.String(), nil
}
