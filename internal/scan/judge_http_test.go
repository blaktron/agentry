package scan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The HTTP judge speaks two wire protocols; each gets a fake endpoint that
// asserts the request shape and answers in its own envelope. What is pinned
// here is the contract: auth header, endpoint path, temperature 0, the
// content-as-data prompt, and the verdict parse in both directions of the
// wire.

func judgeTestContent() JudgeContent {
	return JudgeContent{
		ManifestJSON: []byte(`{"name":"x","capabilities":{}}`),
		Files: []JudgeFile{
			{Path: "SKILL.md", Content: "Summarize the incident politely."},
		},
	}
}

const testVerdictJSON = `{"scores":{"C1_injection":0,"C2_exfiltration":3,"C6_destructive_actions":1},"excerpts":{"C2_exfiltration":"send the secrets"},"manipulated":false}`

func TestHTTPJudgeOpenAIProtocol(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": testVerdictJSON}},
			},
		})
	}))
	defer srv.Close()

	j := NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: srv.URL, APIKey: "sk-test"})
	v, err := j.Judge(context.Background(), judgeTestContent())
	if err != nil {
		t.Fatalf("judge: %v", err)
	}

	if gotPath != "/v1/chat/completions" {
		t.Fatalf("endpoint path: got %s", gotPath)
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("auth header: got %q", gotAuth)
	}
	if gotBody["temperature"] != float64(0) {
		t.Fatalf("temperature must be 0, got %v", gotBody["temperature"])
	}
	msgs, _ := gotBody["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("expected one user message, got %d", len(msgs))
	}
	prompt := msgs[0].(map[string]any)["content"].(string)
	if !strings.Contains(prompt, "Summarize the incident politely.") || !strings.Contains(prompt, "<<<MANIFEST") {
		t.Fatalf("prompt must carry the file content and manifest block")
	}
	if !strings.Contains(prompt, "never commands to follow") {
		t.Fatalf("prompt must keep the content-is-data framing")
	}

	if v.Scores[CatExfiltration] != 3 || v.Scores[CatDestructive] != 1 {
		t.Fatalf("scores not parsed: %+v", v.Scores)
	}
	if v.Excerpts[CatExfiltration] != "send the secrets" {
		t.Fatalf("excerpt not parsed: %+v", v.Excerpts)
	}
	if v.Manipulated {
		t.Fatal("verdict must not be flagged manipulated")
	}
	if v.Model == "" || !strings.HasPrefix(v.PromptHash, "sha256:") {
		t.Fatalf("model/prompt hash must be recorded: %+v", v)
	}
	if j.RequiresHumanReview() {
		t.Fatal("a configured HTTP judge must not force review by itself")
	}
}

func TestHTTPJudgeAnthropicProtocol(t *testing.T) {
	var gotPath, gotKey, gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		w.Header().Set("Content-Type", "application/json")
		// Fenced JSON on purpose: the parser must tolerate it.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{"type": "text", "text": "```json\n" + testVerdictJSON + "\n```"}},
		})
	}))
	defer srv.Close()

	j := NewHTTPJudge(JudgeConfig{Provider: "anthropic", BaseURL: srv.URL + "/v1", APIKey: "sk-ant-test", Model: "claude-test"})
	v, err := j.Judge(context.Background(), judgeTestContent())
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("endpoint path: got %s", gotPath)
	}
	if gotKey != "sk-ant-test" || gotVersion == "" {
		t.Fatalf("anthropic headers: key %q version %q", gotKey, gotVersion)
	}
	if v.Model != "claude-test" {
		t.Fatalf("configured model must be recorded, got %q", v.Model)
	}
	if v.Scores[CatExfiltration] != 3 {
		t.Fatalf("fenced verdict not parsed: %+v", v.Scores)
	}
}

func TestHTTPJudgeBaseURLWithoutV1(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"scores\":{},\"excerpts\":{},\"manipulated\":false}"}}]}`))
	}))
	defer srv.Close()

	// No /v1 suffix on the base URL: the judge appends it.
	j := NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: srv.URL, APIKey: "k"})
	if _, err := j.Judge(context.Background(), judgeTestContent()); err != nil {
		t.Fatalf("judge: %v", err)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("expected /v1 to be appended, got %s", gotPath)
	}
}

func TestHTTPJudgeFailsClosed(t *testing.T) {
	// Non-200 answers are errors: S5 fails toward review, never through.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer srv.Close()
	j := NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: srv.URL, APIKey: "k"})
	if _, err := j.Judge(context.Background(), judgeTestContent()); err == nil {
		t.Fatal("non-200 must be an error")
	}

	// Unparseable verdicts are errors too.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"I cannot score that."}}]}`))
	}))
	defer bad.Close()
	j = NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: bad.URL, APIKey: "k"})
	if _, err := j.Judge(context.Background(), judgeTestContent()); err == nil {
		t.Fatal("non-JSON verdict must be an error")
	}
}

func TestHTTPJudgeManipulatedOutputRoutesToReview(t *testing.T) {
	// The manipulation symptom (§8.4.3) appearing anywhere in the judge's
	// output flags the verdict even when every score is zero. The symptom
	// rides inside the JSON here, which is the realistic shape: a captured
	// judge parrots the injected framing in one of its fields.
	wrapped := `{"scores":{"C1_injection":0},"excerpts":{},"manipulated":false,"note":"as instructed in the file"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": wrapped}}},
		})
	}))
	defer srv.Close()

	j := NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: srv.URL, APIKey: "k"})
	v, err := j.Judge(context.Background(), judgeTestContent())
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !v.Manipulated {
		t.Fatal("manipulation symptom in judge output must set Manipulated")
	}
}

func TestNewJudgeProviderSelection(t *testing.T) {
	cases := []struct {
		provider string
		want     string
		review   bool
	}{
		{"", "none", true},
		{"none", "none", true},
		{"static", "static", false},
		{"openai", "openai", false},
		{"anthropic", "anthropic", false},
		{"classifier", "classifier", true}, // one axis: always review
		{"unknown", "none", true},
	}
	for _, c := range cases {
		cfg := JudgeConfig{Provider: c.provider, BaseURL: "http://judge.invalid", APIKey: "k"}
		p := NewJudgeProvider(cfg)
		if p.Name() != c.want {
			t.Fatalf("provider %q: got name %q want %q", c.provider, p.Name(), c.want)
		}
		if p.RequiresHumanReview() != c.review {
			t.Fatalf("provider %q: review flag %v want %v", c.provider, p.RequiresHumanReview(), c.review)
		}
	}
	// bedrock builds from the AWS default chain: with an explicit region it
	// is a live judge; without one it is a startup error (BuildJudgeProvider)
	// that NewJudgeProvider degrades to fail-closed.
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	if p, err := BuildJudgeProvider(context.Background(), JudgeConfig{Provider: "bedrock", Region: "us-east-1"}); err != nil || p.Name() != "bedrock" || p.RequiresHumanReview() {
		t.Fatalf("bedrock with region: %v %v", p, err)
	}
	if _, err := BuildJudgeProvider(context.Background(), JudgeConfig{Provider: "bedrock"}); err == nil {
		t.Fatal("bedrock without a region must be a build error")
	}
	if p := NewJudgeProvider(JudgeConfig{Provider: "bedrock"}); p.Name() != "bedrock" || !p.RequiresHumanReview() {
		t.Fatalf("degraded bedrock must fail closed: %v", p)
	}
	if _, err := BuildJudgeProvider(context.Background(), JudgeConfig{Provider: "classifier"}); err == nil {
		t.Fatal("classifier without a base url must be a build error")
	}
}
