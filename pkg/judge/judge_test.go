package judge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// call is one request the fake Jev saw, decoded.
type call struct {
	Auth      string
	Model     string            `json:"model"`
	State     map[string]string `json:"state"`
	Questions map[string]struct {
		Type         string `json:"type"`
		Instructions string `json:"instructions"`
	} `json:"questions"`
}

// fakeJev fakes POST /v1/systemone. answer decides one question's
// probability (a negative one omits the answer) or a status for the whole
// request.
func fakeJev(t *testing.T, model string, answer func(n int, id string, c call) (float64, int)) (*httptest.Server, *[]call) {
	t.Helper()
	var mu sync.Mutex
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var c call
		if r.URL.Path != Path || json.Unmarshal(raw, &c) != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusUnprocessableEntity)
			return
		}
		c.Auth = r.Header.Get("Authorization")
		mu.Lock()
		calls = append(calls, c)
		n := len(calls)
		mu.Unlock()
		answers := map[string]any{}
		for id := range c.Questions {
			p, st := answer(n, id, c)
			if st != 0 {
				w.WriteHeader(st)
				_, _ = w.Write([]byte(`{"error":"the key tok-secret-value was refused"}`))
				return
			}
			if p >= 0 {
				answers[id] = map[string]any{"type": "noul", "noul": p}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": model, "answers": answers,
			"usage": map[string]int{"input_tokens": 100, "output_tokens": 4},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func client(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: srv.URL, APIKey: "tok-secret-value", RetryWait: -1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewRefusesNoKeyAndAMovingModel(t *testing.T) {
	if _, err := New(Config{}); err != ErrNoKey {
		t.Fatalf("no key: %v", err)
	}
	for _, m := range []string{"jev-latest", "jev-preview", "jev", "jev-1.13-latest"} {
		if _, err := New(Config{APIKey: "k", Model: m}); err == nil {
			t.Fatalf("model %q must be refused", m)
		}
	}
	c, err := New(Config{APIKey: "k"})
	if err != nil || c.Model() != DefaultModel || c.Endpoint() != DefaultBaseURL+Path {
		t.Fatalf("defaults: %v %+v", err, c)
	}
}

func TestAskSendsTheQuestionsAndTheStateAndReadsEveryAnswer(t *testing.T) {
	srv, calls := fakeJev(t, DefaultModel, func(_ int, id string, _ call) (float64, int) {
		if id == ModelInputIDInjection {
			return 0.8, 0
		}
		return 0.1, 0
	})
	c := client(t, srv)
	probs, u, err := c.Ask(context.Background(), map[string]string{"source": "page", "content": "hello"}, ModelInputQuestions())
	if err != nil {
		t.Fatal(err)
	}
	if probs[ModelInputIDInjection] != 0.8 || probs[ModelInputIDObfuscation] != 0.1 || len(probs) != 4 {
		t.Fatalf("probs: %+v", probs)
	}
	if u.InputTokens != 100 || u.OutputTokens != 4 || u.Requests != 1 {
		t.Fatalf("usage: %+v", u)
	}
	got := (*calls)[0]
	if got.Auth != "Bearer tok-secret-value" || got.Model != DefaultModel || got.State["content"] != "hello" {
		t.Fatalf("request: %+v", got)
	}
	for _, q := range ModelInputQuestions() {
		if got.Questions[q.ID].Type != "noul" || got.Questions[q.ID].Instructions != q.Text {
			t.Fatalf("question %s: %+v", q.ID, got.Questions[q.ID])
		}
	}
}

func TestAskFailsOnEveryOutOfShapeAnswer(t *testing.T) {
	ctx := context.Background()
	st := map[string]string{"content": "x"}
	t.Run("another model", func(t *testing.T) {
		srv, _ := fakeJev(t, "jev-1.14.0", func(int, string, call) (float64, int) { return 0.1, 0 })
		if _, _, err := client(t, srv).Ask(ctx, st, ModelInputQuestions()); err == nil || !strings.Contains(err.Error(), "jev-1.14.0") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a missing answer", func(t *testing.T) {
		srv, _ := fakeJev(t, DefaultModel, func(_ int, id string, _ call) (float64, int) {
			if id == ModelInputIDDeception {
				return -1, 0
			}
			return 0.1, 0
		})
		if _, _, err := client(t, srv).Ask(ctx, st, ModelInputQuestions()); err == nil {
			t.Fatal("a missing answer must fail")
		}
	})
	t.Run("out of range", func(t *testing.T) {
		srv, _ := fakeJev(t, DefaultModel, func(int, string, call) (float64, int) { return 1.5, 0 })
		if _, _, err := client(t, srv).Ask(ctx, st, ModelInputQuestions()); err == nil {
			t.Fatal("a probability above 1 must fail")
		}
	})
	t.Run("no questions", func(t *testing.T) {
		srv, calls := fakeJev(t, DefaultModel, func(int, string, call) (float64, int) { return 0.1, 0 })
		if _, _, err := client(t, srv).Ask(ctx, st, nil); err == nil || len(*calls) != 0 {
			t.Fatal("no questions must fail before any request")
		}
	})
}

func TestAskRetriesOnceOn429AndRedactsTheKey(t *testing.T) {
	srv, calls := fakeJev(t, DefaultModel, func(int, string, call) (float64, int) { return 0, http.StatusTooManyRequests })
	_, _, err := client(t, srv).Ask(context.Background(), map[string]string{"content": "x"}, ModelInputQuestions())
	if err == nil || len(*calls) != 2 {
		t.Fatalf("err %v after %d calls; want an error after two", err, len(*calls))
	}
	if strings.Contains(err.Error(), "tok-secret-value") || !strings.Contains(err.Error(), "[key]") {
		t.Fatalf("the key must be redacted: %v", err)
	}
	var se *StatusError
	if !asStatus(err, &se) || se.Status != http.StatusTooManyRequests {
		t.Fatalf("want a StatusError: %v", err)
	}

	srv5, calls5 := fakeJev(t, DefaultModel, func(int, string, call) (float64, int) { return 0, http.StatusServiceUnavailable })
	if _, _, err := client(t, srv5).Ask(context.Background(), map[string]string{"content": "x"}, ModelInputQuestions()); err == nil || len(*calls5) != 1 {
		t.Fatalf("a 503 is not retried: %v after %d", err, len(*calls5))
	}
}

func asStatus(err error, se **StatusError) bool {
	e, ok := err.(*StatusError)
	if ok {
		*se = e
	}
	return ok
}

func TestChunkKeepsEveryByteAndNeverSplitsACharacter(t *testing.T) {
	text := strings.Repeat("é", 5000) + "\n" + strings.Repeat("ab\n", 3000) + strings.Repeat("日本語", 4000)
	pieces := Chunk(text, ChunkSize)
	if strings.Join(pieces, "") != text {
		t.Fatal("the pieces must join back to the text")
	}
	for i, p := range pieces {
		if len(p) > ChunkSize {
			t.Fatalf("piece %d is %d bytes", i, len(p))
		}
		if !utf8.ValidString(p) {
			t.Fatalf("piece %d ends inside a character", i)
		}
	}
	if got := Chunk("short", ChunkSize); len(got) != 1 || got[0] != "short" {
		t.Fatalf("short text: %q", got)
	}
}

func TestScoreFromProbability(t *testing.T) {
	for p, want := range map[float64]int{0: 0, 0.49: 0, 0.5: 1, 0.69: 1, 0.7: 2, 0.89: 2, 0.9: 3, 1: 3} {
		if got := ScoreFromProbability(p); got != want {
			t.Fatalf("p=%v: %d, want %d", p, got, want)
		}
	}
}

// The question sets are constants: every call answers the same texts, the
// ids are distinct, a caller that changes its slice changes nobody else's,
// and no text is a template anything could be rendered into.
func TestTheQuestionSetsAreConstants(t *testing.T) {
	for name, set := range map[string]func() []Question{"rubric": RubricQuestions, "model input": ModelInputQuestions, "draft": DraftQuestions} {
		a, b := set(), set()
		a[0].Text = "changed by a caller"
		if b[0].Text == "changed by a caller" || set()[0].Text == "changed by a caller" {
			t.Fatalf("%s: the set is shared between callers", name)
		}
		seen := map[string]bool{}
		for _, q := range set() {
			if q.ID == "" || seen[q.ID] {
				t.Fatalf("%s: id %q empty or repeated", name, q.ID)
			}
			seen[q.ID] = true
			for _, marker := range []string{"%", "{{", "${", "<<<"} {
				if strings.Contains(q.Text, marker) {
					t.Fatalf("%s: question %s holds %q, a place text could be rendered into", name, q.ID, marker)
				}
			}
		}
	}
	want := map[string]string{
		ModelInputIDInjection: ModelInputInjection, ModelInputIDExfiltration: ModelInputExfiltration,
		ModelInputIDDeception: ModelInputDeception, ModelInputIDObfuscation: ModelInputObfuscation,
	}
	got := ModelInputQuestions()
	if len(got) != len(want) {
		t.Fatalf("the model-input set has %d questions, want %d (D23)", len(got), len(want))
	}
	for _, q := range got {
		if want[q.ID] != q.Text {
			t.Fatalf("%s is not its constant", q.ID)
		}
	}
	if len(RubricQuestions()) != 6 {
		t.Fatal("the rubric has six questions")
	}
	draft := map[string]string{DraftIDOffTask: DraftOffTask}
	if got := DraftQuestions(); len(got) != len(draft) {
		t.Fatalf("the draft set has %d questions, want %d", len(got), len(draft))
	}
	for _, q := range DraftQuestions() {
		if draft[q.ID] != q.Text {
			t.Fatalf("%s is not its constant", q.ID)
		}
	}
}

// Every set's hash names every question's wording (agentry#703): change one
// question's text, or its id, and the hash changes. A hash that dropped the
// texts would make two differently worded sets read as one.
func TestEveryQuestionSetHashNamesEachQuestionsWording(t *testing.T) {
	for name, c := range map[string]struct {
		set  func() []Question
		hash func([]Question) string
	}{
		"model input": {ModelInputQuestions, func(qs []Question) string { return modelInputHashOf(DefaultModel, true, qs) }},
		"draft":       {DraftQuestions, func(qs []Question) string { return draftHashOf(DefaultModel, qs) }},
		"rubric":      {RubricQuestions, func(qs []Question) string { return rubricHashOf(DefaultModel, RubricBatchOne, qs) }},
	} {
		base := c.hash(c.set())
		for i := range c.set() {
			worded := c.set()
			worded[i].Text += " Reworded."
			if c.hash(worded) == base {
				t.Fatalf("%s: question %s's wording is not in the hash", name, worded[i].ID)
			}
			renamed := c.set()
			renamed[i].ID += "_x"
			if c.hash(renamed) == base {
				t.Fatalf("%s: question %s's id is not in the hash", name, renamed[i].ID)
			}
		}
	}
	if modelInputHash(DefaultModel, true) != modelInputHashOf(DefaultModel, true, ModelInputQuestions()) ||
		draftHash(DefaultModel) != draftHashOf(DefaultModel, DraftQuestions()) {
		t.Fatal("a scanner's hash is the hash of the set it asks")
	}
}

// Chunk ends for every size, a size smaller than one character included,
// and never returns an empty piece before the last.
func TestChunkEndsAtEverySize(t *testing.T) {
	text := "€x\n日本\nabc" + string([]byte{0xff, 0xfe}) + "é"
	for n := 1; n <= 12; n++ {
		pieces := Chunk(text, n)
		if strings.Join(pieces, "") != text {
			t.Fatalf("n=%d: the pieces must join back to the text", n)
		}
		for i, p := range pieces[:len(pieces)-1] {
			if p == "" {
				t.Fatalf("n=%d: piece %d is empty", n, i)
			}
		}
	}
}

// A key echoed across the snippet's cut is redacted whole: redaction runs
// before the cut, so no half of it survives.
func TestAKeyAcrossTheSnippetCutIsRedacted(t *testing.T) {
	key := "tok-secret-value-that-is-long"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strings.Repeat("x", 190) + key + " trailing"))
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, APIKey: key, RetryWait: -1})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.Ask(context.Background(), map[string]string{"content": "x"}, ModelInputQuestions())
	if err == nil || strings.Contains(err.Error(), "tok-secret") {
		t.Fatalf("a part of the key survived: %v", err)
	}
}

// A redirect is never followed, so the key never reaches another host.
func TestAskNeverFollowsARedirect(t *testing.T) {
	var hit bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, APIKey: "k", RetryWait: -1, HTTPClient: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.Ask(context.Background(), map[string]string{"content": "x"}, ModelInputQuestions())
	var se *StatusError
	if !asStatus(err, &se) || se.Status != http.StatusTemporaryRedirect || hit {
		t.Fatalf("err %v, followed %v", err, hit)
	}
}
