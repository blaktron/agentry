package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	var gotPath, gotAuth, gotCT string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
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
	// Content sits in delimited blocks, the manifest and each file apart.
	if !strings.Contains(prompt, "<<<MANIFEST\n{\"name\":\"x\",\"capabilities\":{}}\nMANIFEST>>>") ||
		!strings.Contains(prompt, "<<<FILE SKILL.md\nSummarize the incident politely.\nFILE>>>\n\n") {
		t.Fatalf("prompt blocks: %q", prompt)
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

	// The rest of the request is fixed too: the bounded output, the model
	// the verdict is recorded under, one user message, the content type, the
	// client's timeout, and what the provider reads.
	if gotBody["max_tokens"] != float64(1024) {
		t.Fatalf("max_tokens must bound the verdict at 1024, got %v", gotBody["max_tokens"])
	}
	if gotBody["model"] != "gpt-4o" || v.Model != "gpt-4o" || j.ModelID() != "gpt-4o" {
		t.Fatalf("model: request %v, verdict %q, provider %q", gotBody["model"], v.Model, j.ModelID())
	}
	if role := msgs[0].(map[string]any)["role"]; role != "user" {
		t.Fatalf("the prompt must travel as a user message, got %v", role)
	}
	if gotCT != "application/json" {
		t.Fatalf("content type: %q", gotCT)
	}
	if j.client.Timeout != 90*time.Second {
		t.Fatalf("client timeout = %v, want 90s", j.client.Timeout)
	}
	if j.Name() != "openai" || j.InputLimit() != 256<<10 {
		t.Fatalf("name %q input limit %d", j.Name(), j.InputLimit())
	}
}

func TestHTTPJudgeAnthropicProtocol(t *testing.T) {
	var gotPath, gotKey, gotVersion, gotBearer string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotBearer = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
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
	if gotVersion != "2023-06-01" {
		t.Fatalf("anthropic-version = %q, want the pinned 2023-06-01", gotVersion)
	}
	if gotBearer != "" {
		t.Fatalf("an anthropic request carries the key in x-api-key only, got Authorization %q", gotBearer)
	}
	msgs, _ := gotBody["messages"].([]any)
	if gotBody["model"] != "claude-test" || gotBody["temperature"] != float64(0) || gotBody["max_tokens"] != float64(1024) || len(msgs) != 1 || msgs[0].(map[string]any)["role"] != "user" {
		t.Fatalf("anthropic request body: %v", gotBody)
	}
	if j.Name() != "anthropic" || j.ModelID() != "claude-test" {
		t.Fatalf("name %q model %q", j.Name(), j.ModelID())
	}

	// With no model configured the provider's own default is asked and recorded.
	if d := NewHTTPJudge(JudgeConfig{Provider: "anthropic", BaseURL: srv.URL, APIKey: "k"}); d.ModelID() != "claude-3-5-sonnet-latest" || d.model != defaultAnthropicModel {
		t.Fatalf("anthropic default model = %q", d.ModelID())
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

	// A trailing slash is dropped before /v1 is added or recognised.
	for _, base := range []string{srv.URL + "/", srv.URL + "/v1/", srv.URL + "/v1"} {
		gotPath = ""
		if _, err := NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: base, APIKey: "k"}).Judge(context.Background(), judgeTestContent()); err != nil {
			t.Fatalf("%s: %v", base, err)
		}
		if gotPath != "/v1/chat/completions" {
			t.Fatalf("base %s reached %q, want /v1/chat/completions", base, gotPath)
		}
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

	t.Run("a status other than 200 is an error whatever the body says", func(t *testing.T) {
		// A well-formed verdict behind a 4xx or a redirect is still not an answer.
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNoContent, http.StatusFound} {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"scores\":{},\"excerpts\":{},\"manipulated\":false}"}}]}`))
			}))
			_, err := NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: srv.URL, APIKey: "k"}).Judge(context.Background(), judgeTestContent())
			srv.Close()
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("scan: judge endpoint returned %d", status)) {
				t.Fatalf("status %d: %v", status, err)
			}
		}
	})
	t.Run("the error carries the status and at most 200 bytes of the body", func(t *testing.T) {
		long := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(strings.Repeat("q", 300)))
		}))
		defer long.Close()
		_, err := NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: long.URL, APIKey: "k"}).Judge(context.Background(), judgeTestContent())
		if err == nil || !strings.Contains(err.Error(), "returned 502: ") || strings.Count(err.Error(), "q") != 200 {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("an answer over 1 MiB is cut and so is not a verdict", func(t *testing.T) {
		pad := strings.Repeat("a", 1<<20+1024)
		big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"scores\":{},\"excerpts\":{},\"manipulated\":false}"}}],"pad":"` + pad + `"}`))
		}))
		defer big.Close()
		if _, err := NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: big.URL, APIKey: "k"}).Judge(context.Background(), judgeTestContent()); err == nil {
			t.Fatal("a response past the read bound must be an error")
		}
	})
	t.Run("an envelope with no choices is an error that says so", func(t *testing.T) {
		none := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"choices":[]}`)) }))
		defer none.Close()
		_, err := NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: none.URL, APIKey: "k"}).Judge(context.Background(), judgeTestContent())
		if err == nil || !strings.Contains(err.Error(), "carries no choices") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("anthropic reads only the text blocks", func(t *testing.T) {
		mixed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]any{
				{"type": "thinking", "text": "scoring this now"},
				{"type": "text", "text": testVerdictJSON},
			}})
		}))
		defer mixed.Close()
		v, err := NewHTTPJudge(JudgeConfig{Provider: "anthropic", BaseURL: mixed.URL, APIKey: "k"}).Judge(context.Background(), judgeTestContent())
		if err != nil || v.Scores[CatExfiltration] != 3 {
			t.Fatalf("a non-text block must not reach the verdict: %+v %v", v.Scores, err)
		}
	})
}

// TestParseJudgeJSON pins how a model's verdict text becomes a verdict: the
// fence forms it tolerates, scores clamped to the rubric's 0-3, categories
// outside the rubric dropped, and the model's own manipulated flag kept.
func TestParseJudgeJSON(t *testing.T) {
	const body = `{"scores":{"C1_injection":2},"excerpts":{"C1_injection":"quoted"},"manipulated":false}`
	for name, text := range map[string]string{
		"bare":             body,
		"json fence":       "```json\n" + body + "\n```",
		"plain fence":      "```\n" + body + "\n```",
		"surrounding text": "  \n" + body + "\n  ",
	} {
		v, err := parseJudgeJSON(text)
		if err != nil || v.Scores[CatInjection] != 2 || v.Excerpts[CatInjection] != "quoted" {
			t.Errorf("%s: %+v %v", name, v, err)
		}
	}

	v, err := parseJudgeJSON(`{"scores":{"C1_injection":-2,"C2_exfiltration":7,"C3_undeclared_capability":3,"C4_user_deception":0,"C9_invented":3,"free text":2},` +
		`"excerpts":{"C2_exfiltration":"kept","C9_invented":"dropped"},"manipulated":true}`)
	if err != nil {
		t.Fatal(err)
	}
	if v.Scores[CatInjection] != 0 || v.Scores[CatExfiltration] != 3 || v.Scores[CatUndeclaredCap] != 3 || v.Scores[CatDeception] != 0 {
		t.Fatalf("scores must be clamped to 0-3: %v", v.Scores)
	}
	if len(v.Scores) != 4 {
		t.Fatalf("categories outside the rubric must be dropped: %v", v.Scores)
	}
	if len(v.Excerpts) != 1 || v.Excerpts[CatExfiltration] != "kept" {
		t.Fatalf("excerpts of unknown categories must be dropped: %v", v.Excerpts)
	}
	if !v.Manipulated {
		t.Fatal("the model's own manipulated flag must be kept")
	}
	for _, bad := range []string{"", "I cannot score that.", `["scores"]`, `{"scores":"high"}`} {
		if _, err := parseJudgeJSON(bad); err == nil || !strings.Contains(err.Error(), "not the required JSON") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestHTTPJudgeManipulatedOutputRoutesToReview(t *testing.T) {
	// The manipulation symptom appearing anywhere in the judge's
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
		cfg := JudgeConfig{Provider: c.provider, BaseURL: "https://judge.invalid", APIKey: "k"}
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
	if _, err := BuildJudgeProvider(context.Background(), JudgeConfig{Provider: "classifier", BaseURL: "   "}); err == nil {
		t.Fatal("a blank base url must be a build error")
	}
	// A region of blanks names no region.
	if _, err := BuildJudgeProvider(context.Background(), JudgeConfig{Provider: "bedrock", Region: "  "}); err == nil || !strings.Contains(err.Error(), "AGENTRY_JUDGE_REGION") {
		t.Fatalf("bedrock with a blank region must be a build error naming the setting: %v", err)
	}

	// What each provider reads in one call, and what it names itself.
	for _, c := range []struct {
		cfg   JudgeConfig
		limit int
	}{
		{JudgeConfig{Provider: "none"}, 0},
		{JudgeConfig{Provider: "static"}, 256 << 10},
		{JudgeConfig{Provider: "openai", BaseURL: "https://judge.invalid", APIKey: "k"}, 256 << 10},
		{JudgeConfig{Provider: "anthropic", BaseURL: "https://judge.invalid", APIKey: "k"}, 256 << 10},
		{JudgeConfig{Provider: "classifier", BaseURL: "https://judge.invalid"}, 8 * (8 << 10)},
		{JudgeConfig{Provider: "typesafe", BaseURL: "https://judge.invalid", APIKey: "k"}, 50 << 10},
		{JudgeConfig{Provider: "bedrock", Region: "us-east-1"}, 256 << 10},
	} {
		p, err := BuildJudgeProvider(context.Background(), c.cfg)
		if err != nil {
			t.Fatalf("%s: %v", c.cfg.Provider, err)
		}
		if p.InputLimit() != c.limit {
			t.Errorf("%s: input limit %d, want %d", c.cfg.Provider, p.InputLimit(), c.limit)
		}
	}
	if m := (NoneProvider{}).ModelID(); m != "" {
		t.Errorf("none names a model: %q", m)
	}

	// A provider that could not be built fails every verdict, naming it and
	// why, reads as much as a live one (so a caller makes the call and records
	// the failure) and names no model.
	u := NewJudgeProvider(JudgeConfig{Provider: "bedrock"})
	if _, err := u.Judge(context.Background(), judgeTestContent()); err == nil ||
		!strings.Contains(err.Error(), "scan: judge provider bedrock is not configured: ") || !strings.Contains(err.Error(), "no AWS region") {
		t.Fatalf("unconfigured verdict error: %v", err)
	}
	if u.InputLimit() != 256<<10 || u.ModelID() != "" {
		t.Fatalf("unconfigured: limit %d model %q", u.InputLimit(), u.ModelID())
	}
	if _, err := (UnconfiguredProvider{ProviderName: "typesafe"}).Judge(context.Background(), judgeTestContent()); err == nil || err.Error() != "scan: judge provider typesafe is not configured" {
		t.Fatalf("an unconfigured provider with no reason: %v", err)
	}
}

// The judge's token use is what a review costs:
// each wire protocol reports it in its own envelope, and a response without
// it leaves Usage nil rather than zero, so "unknown" and "free" never blur.
func TestHTTPJudgeRecordsUsage(t *testing.T) {
	cases := []struct {
		name, provider string
		body           map[string]any
		want           *JudgeUsage
	}{
		{"openai", "openai", map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": testVerdictJSON}}},
			"usage":   map[string]any{"prompt_tokens": 812, "completion_tokens": 97, "total_tokens": 909},
		}, &JudgeUsage{PromptTokens: 812, CompletionTokens: 97}},
		{"anthropic", "anthropic", map[string]any{
			"content": []map[string]any{{"type": "text", "text": testVerdictJSON}},
			"usage":   map[string]any{"input_tokens": 640, "output_tokens": 55},
		}, &JudgeUsage{PromptTokens: 640, CompletionTokens: 55}},
		{"openai without usage", "openai", map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": testVerdictJSON}}},
		}, nil},
		{"anthropic without usage", "anthropic", map[string]any{
			"content": []map[string]any{{"type": "text", "text": testVerdictJSON}},
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tc.body)
			}))
			defer srv.Close()
			j := NewHTTPJudge(JudgeConfig{Provider: tc.provider, BaseURL: srv.URL, APIKey: "k"})
			v, err := j.Judge(context.Background(), judgeTestContent())
			if err != nil {
				t.Fatalf("judge: %v", err)
			}
			switch {
			case tc.want == nil && v.Usage != nil:
				t.Fatalf("usage must be nil when the response reports none, got %+v", *v.Usage)
			case tc.want != nil && (v.Usage == nil || *v.Usage != *tc.want):
				t.Fatalf("usage: got %+v want %+v", v.Usage, tc.want)
			}
		})
	}
}
