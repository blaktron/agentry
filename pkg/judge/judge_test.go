package judge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// call is one request the fake Jev saw, decoded.
type call struct {
	Auth string
	// Method, ContentType and Raw are read off the wire, never decoded
	// from the body.
	Method      string            `json:"-"`
	ContentType string            `json:"-"`
	Raw         string            `json:"-"`
	Model       string            `json:"model"`
	State       map[string]string `json:"state"`
	Questions   map[string]struct {
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
		c.Method, c.ContentType, c.Raw = r.Method, r.Header.Get("Content-Type"), string(raw)
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
	// The pinned version the thresholds are calibrated against and the
	// vendor's endpoint, spelled out.
	if DefaultModel != "jev-1.13.0" || c.Endpoint() != "https://api.typesafe.ai/v1/systemone" {
		t.Fatalf("defaults: %s at %s", DefaultModel, c.Endpoint())
	}

	// A key of white space is no key.
	for _, k := range []string{"", " ", "\t\n "} {
		if _, err := New(Config{APIKey: k}); err != ErrNoKey {
			t.Fatalf("key %q: %v, want ErrNoKey", k, err)
		}
	}
	// A moving alias is refused whatever its case, and a number is a version
	// only when digits stand on both sides of a dot.
	for _, m := range []string{"jev-1.13-preview", "JEV-1.13-LATEST", "Jev-1.13-Preview", "jev-1.x", "jev-v.1", "jev-1.", "jev-113", "jev-.5"} {
		if _, err := New(Config{APIKey: "k", Model: m}); err == nil {
			t.Fatalf("model %q must be refused", m)
		}
	}
	// A pinned id is kept as given, trimmed; a blank one is the default.
	for in, want := range map[string]string{"": DefaultModel, "  ": DefaultModel, " jev-1.13.0 \n": "jev-1.13.0", "jev-1.2": "jev-1.2", "jev-2.0.1-rc1": "jev-2.0.1-rc1"} {
		c, err := New(Config{APIKey: "k", Model: in})
		if err != nil || c.Model() != want {
			t.Fatalf("model %q: %v, %v", in, err, c)
		}
	}
	// The endpoint is the base with its trailing slashes and white space
	// cut, then the path.
	for in, want := range map[string]string{
		"https://api.example.test":          "https://api.example.test/v1/systemone",
		"https://api.example.test/":         "https://api.example.test/v1/systemone",
		"  https://api.example.test///  \n": "https://api.example.test/v1/systemone",
		"http://127.0.0.1:9/base/":          "http://127.0.0.1:9/base/v1/systemone",
	} {
		c, err := New(Config{APIKey: "k", BaseURL: in})
		if err != nil || c.Endpoint() != want {
			t.Fatalf("base %q: %v, endpoint %q, want %q", in, err, c.Endpoint(), want)
		}
	}
	// The key is stored trimmed: it is what rides in the header and what is
	// redacted.
	if c, _ := New(Config{APIKey: "  tok-secret-value \n"}); c.apiKey != "tok-secret-value" {
		t.Fatalf("the key is stored as %q", c.apiKey)
	}

	// The default client has a 60-second timeout; a caller's client keeps
	// its own timeout and transport, is copied rather than changed, and is
	// still kept from following a redirect.
	if c, _ := New(Config{APIKey: "k"}); c.http.Timeout != 60*time.Second || c.http.CheckRedirect == nil {
		t.Fatalf("default client: %+v", c.http)
	}
	mine := &http.Client{Timeout: 7 * time.Second, Transport: http.DefaultTransport}
	c, err = New(Config{APIKey: "k", HTTPClient: mine})
	if err != nil || c.http == mine || c.http.Timeout != 7*time.Second || c.http.Transport != http.DefaultTransport || c.http.CheckRedirect == nil {
		t.Fatalf("caller's client: %v %+v", err, c.http)
	}
	if mine.CheckRedirect != nil {
		t.Fatal("the caller's own client must not be changed")
	}

	// The pause before the retry: two seconds when unset, none when
	// negative, the caller's own otherwise.
	if defaultRetryWait != 2*time.Second {
		t.Fatalf("the default retry wait is %v, want 2s", defaultRetryWait)
	}
	for in, want := range map[time.Duration]time.Duration{0: 2 * time.Second, -1: 0, -time.Hour: 0, 5 * time.Millisecond: 5 * time.Millisecond} {
		if c, _ := New(Config{APIKey: "k", RetryWait: in}); c.retryWait != want {
			t.Fatalf("RetryWait %v: %v, want %v", in, c.retryWait, want)
		}
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
	// Readings add field by field.
	sum := Usage{InputTokens: 1, OutputTokens: 2, Requests: 3}
	sum.Add(Usage{InputTokens: 10, OutputTokens: 20, Requests: 30})
	if sum != (Usage{InputTokens: 11, OutputTokens: 22, Requests: 33}) {
		t.Fatalf("Usage.Add: %+v", sum)
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
	if got.Method != http.MethodPost || got.ContentType != "application/json" || c.Endpoint() != srv.URL+Path {
		t.Fatalf("wire: %s %q to %s", got.Method, got.ContentType, c.Endpoint())
	}
	// The key rides in the header and nowhere in the body.
	if strings.Contains(got.Raw, "tok-secret-value") {
		t.Fatalf("the key is in the request body: %s", got.Raw)
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
		if _, _, err := client(t, srv).Ask(ctx, st, ModelInputQuestions()); err == nil || !strings.Contains(err.Error(), "without the deception question") {
			t.Fatalf("a missing answer must fail: %v", err)
		}
	})
	// rawJev answers every request with the given status and body.
	rawJev := func(t *testing.T, status int, body string) *Client {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		return client(t, srv)
	}
	// open is a well-formed body, minus its last brace, whose four answers
	// are all p, written as the JSON number it is given.
	open := func(p string) string {
		var parts []string
		for _, q := range ModelInputQuestions() {
			parts = append(parts, `"`+q.ID+`":{"type":"noul","noul":`+p+`}`)
		}
		return `{"model":"` + DefaultModel + `","answers":{` + strings.Join(parts, ",") + `}`
	}
	answers := func(p string) string { return open(p) + "}" }
	// ask is Ask, with a panic reported as the failure it is.
	ask := func(t *testing.T, c *Client) (err error) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Ask panicked on an answer without a value: %v", r)
			}
		}()
		_, _, err = c.Ask(ctx, st, ModelInputQuestions())
		return err
	}
	t.Run("an answer without its value", func(t *testing.T) {
		body := strings.Replace(answers("0.1"), `"noul":0.1`, `"other":0.1`, 1)
		if err := ask(t, rawJev(t, http.StatusOK, body)); err == nil || !strings.Contains(err.Error(), "without the") {
			t.Fatalf("an answer with no noul value must fail: %v", err)
		}
	})
	t.Run("a null value", func(t *testing.T) {
		body := strings.Replace(answers("0.1"), `"noul":0.1`, `"noul":null`, 1)
		if err := ask(t, rawJev(t, http.StatusOK, body)); err == nil || !strings.Contains(err.Error(), "without the") {
			t.Fatalf("a null noul value must fail: %v", err)
		}
	})
	t.Run("a body cut short", func(t *testing.T) {
		// The reply declares more bytes than it sends: the whole answer is
		// there, but the read did not finish, so it is no answer.
		body := answers("0.1")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)+50))
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		if _, _, err := client(t, srv).Ask(ctx, st, ModelInputQuestions()); err == nil || !strings.Contains(err.Error(), "typesafe response") {
			t.Fatalf("a body cut short must fail as a response error: %v", err)
		}
	})
	t.Run("the probability bounds", func(t *testing.T) {
		for _, p := range []string{"-0.01", "-1e-9", "-1", "1.0000001", "1.01", "2", "100"} {
			if _, _, err := rawJev(t, http.StatusOK, answers(p)).Ask(ctx, st, ModelInputQuestions()); err == nil || !strings.Contains(err.Error(), "out of range") {
				t.Fatalf("p=%s must be out of range: %v", p, err)
			}
		}
		for _, p := range []string{"0", "1", "0.5", "1.0", "0.0"} {
			probs, _, err := rawJev(t, http.StatusOK, answers(p)).Ask(ctx, st, ModelInputQuestions())
			if err != nil || len(probs) != 4 {
				t.Fatalf("p=%s must be accepted: %v %v", p, probs, err)
			}
		}
	})
	t.Run("a body that is not the answer shape", func(t *testing.T) {
		if _, _, err := rawJev(t, http.StatusOK, "not json").Ask(ctx, st, ModelInputQuestions()); err == nil || !strings.Contains(err.Error(), "not the answer shape") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("only a 200 is an answer", func(t *testing.T) {
		for _, status := range []int{http.StatusCreated, http.StatusAccepted, http.StatusNoContent, http.StatusPartialContent} {
			_, _, err := rawJev(t, status, answers("0.1")).Ask(ctx, st, ModelInputQuestions())
			var se *StatusError
			if !asStatus(err, &se) || se.Status != status {
				t.Fatalf("status %d: %v", status, err)
			}
		}
	})
	t.Run("a response without usage", func(t *testing.T) {
		probs, u, err := rawJev(t, http.StatusOK, answers("0.1")).Ask(ctx, st, ModelInputQuestions())
		if err != nil || len(probs) != 4 || u != (Usage{Requests: 1}) {
			t.Fatalf("%v %+v %v", probs, u, err)
		}
	})
	// A response is read to 1 MiB and no further: a body of exactly that
	// size is an answer, one byte more is cut and cannot be read.
	t.Run("the response size cap", func(t *testing.T) {
		const limit = 1 << 20
		head, tail := open("0.1")+`,"pad":"`, `"}`
		pad := func(total int) string { return head + strings.Repeat("x", total-len(head)-len(tail)) + tail }
		if body := pad(limit); len(body) != limit {
			t.Fatalf("fixture is %d bytes", len(body))
		}
		if probs, _, err := rawJev(t, http.StatusOK, pad(limit)).Ask(ctx, st, ModelInputQuestions()); err != nil || len(probs) != 4 {
			t.Fatalf("a body of exactly 1 MiB: %v %v", probs, err)
		}
		for _, total := range []int{limit + 1, limit + 1000, 3 * limit} {
			if _, _, err := rawJev(t, http.StatusOK, pad(total)).Ask(ctx, st, ModelInputQuestions()); err == nil || !strings.Contains(err.Error(), "not the answer shape") {
				t.Fatalf("a body of %d bytes must be cut and refused: %v", total, err)
			}
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

	// Only a 429 and a 529 are retried, once: a refusal that comes first and
	// then an answer is an answer, and every other failure stands at once.
	ctx := context.Background()
	st := map[string]string{"content": "x"}
	for _, status := range []int{http.StatusTooManyRequests, 529} {
		srvR, callsR := fakeJev(t, DefaultModel, func(n int, _ string, _ call) (float64, int) {
			if n == 1 {
				return 0, status
			}
			return 0.1, 0
		})
		probs, u, err := client(t, srvR).Ask(ctx, st, ModelInputQuestions())
		if err != nil || len(probs) != 4 || u.Requests != 1 || len(*callsR) != 2 {
			t.Fatalf("a %d then an answer: %v %v %+v after %d", status, probs, err, u, len(*callsR))
		}
		srv2, calls2 := fakeJev(t, DefaultModel, func(int, string, call) (float64, int) { return 0, status })
		if _, _, err := client(t, srv2).Ask(ctx, st, ModelInputQuestions()); !asStatus(err, new(*StatusError)) || len(*calls2) != 2 {
			t.Fatalf("a %d twice: %v after %d requests, want a StatusError after two", status, err, len(*calls2))
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError, http.StatusBadGateway, 530} {
		srvX, callsX := fakeJev(t, DefaultModel, func(int, string, call) (float64, int) { return 0, status })
		if _, _, err := client(t, srvX).Ask(ctx, st, ModelInputQuestions()); err == nil || len(*callsX) != 1 {
			t.Fatalf("a %d is not retried: %v after %d", status, err, len(*callsX))
		}
	}
	srvM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("tok-secret-value bad"))
	}))
	defer srvM.Close()
	_, _, err = client(t, srvM).Ask(ctx, st, ModelInputQuestions())
	if !asStatus(err, &se) || se.Status != 400 || se.Snippet != "[key] bad" || err.Error() != "judge: typesafe endpoint returned 400: [key] bad" {
		t.Fatalf("status error: %v", err)
	}

	// The status snippet is at most 200 bytes, cut on a character, and says
	// nothing past the cut.
	for name, c := range map[string]struct{ body, want string }{
		"under":           {strings.Repeat("x", 199), strings.Repeat("x", 199)},
		"at the cut":      {strings.Repeat("x", 200), strings.Repeat("x", 200)},
		"one over":        {strings.Repeat("x", 201), strings.Repeat("x", 200)},
		"far over":        {strings.Repeat("x", 5000), strings.Repeat("x", 200)},
		"inside a rune":   {strings.Repeat("x", 199) + "\u00e9" + "tail", strings.Repeat("x", 199)},
		"three byte end":  {strings.Repeat("x", 198) + "\u65e5" + "tail", strings.Repeat("x", 198)},
		"rune at the cut": {strings.Repeat("x", 198) + "\u00e9" + "tail", strings.Repeat("x", 198) + "\u00e9"},
	} {
		srvC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(c.body))
		}))
		_, _, err := client(t, srvC).Ask(ctx, st, ModelInputQuestions())
		srvC.Close()
		if !asStatus(err, &se) || se.Snippet != c.want || !utf8.ValidString(se.Snippet) {
			t.Fatalf("%s: snippet is %d bytes %q, want %d bytes", name, len(se.Snippet), se.Snippet, len(c.want))
		}
	}

	// The pause before the retry is kept, and a context that ends during it
	// ends the request at once.
	slow := func(wait time.Duration) (*Client, *int) {
		var n int
		var mu sync.Mutex
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			n++
			cur := n
			mu.Unlock()
			if cur == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			var parts []string
			for _, q := range ModelInputQuestions() {
				parts = append(parts, `"`+q.ID+`":{"type":"noul","noul":0.1}`)
			}
			_, _ = io.WriteString(w, `{"model":"`+DefaultModel+`","answers":{`+strings.Join(parts, ",")+`}}`)
		}))
		t.Cleanup(srv.Close)
		c, err := New(Config{BaseURL: srv.URL, APIKey: "tok-secret-value", RetryWait: wait})
		if err != nil {
			t.Fatal(err)
		}
		return c, &n
	}
	c, n := slow(80 * time.Millisecond)
	start := time.Now()
	if _, _, err := c.Ask(ctx, st, ModelInputQuestions()); err != nil || *n != 2 || time.Since(start) < 80*time.Millisecond {
		t.Fatalf("the retry must wait RetryWait: %v after %d requests in %v", err, *n, time.Since(start))
	}
	c, n = slow(2 * time.Second)
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, _, err = c.Ask(cctx, st, ModelInputQuestions())
	if !errors.Is(err, context.DeadlineExceeded) || *n != 1 || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("a deadline during the pause must end the request: %v after %d requests in %v", err, *n, time.Since(start))
	}

	// A request is tied to the caller's context: one that ends while the
	// answer is awaited ends the request with that context's error, and the
	// key stays out of an error whose text echoes the address.
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow, but not for ever: the answer comes after 400ms unless the
		// request ends first.
		wait, stop := context.WithTimeout(r.Context(), 400*time.Millisecond)
		defer stop()
		<-wait.Done()
	}))
	defer slowSrv.Close()
	c, err = New(Config{BaseURL: slowSrv.URL, APIKey: "tok-secret-value", RetryWait: -1})
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer dcancel()
	_, _, err = c.Ask(dctx, st, ModelInputQuestions())
	if !errors.Is(err, context.DeadlineExceeded) || FailureOf(dctx, err) != FailureTimeout {
		t.Fatalf("a deadline while awaiting the answer: %v", err)
	}
	stopCtx, stop := context.WithCancel(ctx)
	stop()
	if _, _, err = c.Ask(stopCtx, st, ModelInputQuestions()); !errors.Is(err, context.Canceled) || FailureOf(stopCtx, err) != FailureJudgeError {
		t.Fatalf("a cancelled context: %v", err)
	}

	// An address that holds the key (a base URL can) does not carry it into
	// the error of a failed connection or of a request that cannot be built.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	// A base URL that cannot be built is refused by New, without the key.
	if _, err := New(Config{BaseURL: deadURL + "/tok-secret-value\x7f", APIKey: "tok-secret-value", RetryWait: -1}); err == nil || strings.Contains(err.Error(), "tok-secret-value") {
		t.Fatalf("an unbuildable base must be refused without the key: %v", err)
	}
	for name, base := range map[string]string{
		"refused connection": deadURL + "/tok-secret-value",
	} {
		bad, err := New(Config{BaseURL: base, APIKey: "tok-secret-value", RetryWait: -1})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = bad.Ask(ctx, st, ModelInputQuestions())
		if err == nil || strings.Contains(err.Error(), "tok-secret-value") || !strings.Contains(err.Error(), "[key]") {
			t.Fatalf("%s: the key must be redacted from %v", name, err)
		}
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

	// A size that cannot hold a piece is no split at all.
	for _, n := range []int{-1, 0} {
		done := make(chan any, 1)
		go func() {
			defer func() { done <- recover() }()
			if got := Chunk("abc\ndef", n); len(got) != 1 || got[0] != "abc\ndef" {
				done <- fmt.Sprintf("Chunk(text, %d) = %q", n, got)
			}
		}()
		guard, stop := context.WithTimeout(context.Background(), 5*time.Second)
		select {
		case r := <-done:
			if r != nil {
				t.Fatalf("Chunk(text, %d) must return the text whole: %v", n, r)
			}
		case <-guard.Done():
			t.Fatalf("Chunk(text, %d) does not end", n)
		}
		stop()
	}

	// A line end is the cut only when it falls in the second half of the
	// piece (at the half or after), and the last one in the piece wins;
	// otherwise the cut is at the size.
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"aaaa\nbbbbbbbbbbbbbbb", []string{"aaaa\nbbbbb", "bbbbbbbbbb"}},
		{"aaaaa\nbbbbbbbbbbbbbb", []string{"aaaaa", "\nbbbbbbbbb", "bbbbb"}},
		{"aaaaaa\nbb\ncccccccccc", []string{"aaaaaa\nbb", "\nccccccccc", "c"}},
		{"0123456789", []string{"0123456789"}},
		{"0123456789a", []string{"0123456789", "a"}},
	} {
		if got := Chunk(c.in, 10); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Fatalf("Chunk(%q, 10) = %q, want %q", c.in, got, c.want)
		}
	}
	// A four-byte character that straddles the size is moved whole into the
	// next piece.
	emoji := strings.Repeat("\U0001F600", 6)
	got := Chunk(emoji, 7)
	if len(got) != 6 || strings.Join(got, "") != emoji {
		t.Fatalf("emoji pieces: %q", got)
	}
	for i, p := range got {
		if p != "\U0001F600" {
			t.Fatalf("emoji piece %d is %q, want one whole character", i, p)
		}
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
		t.Fatalf("the model-input set has %d questions, want %d", len(got), len(want))
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

// Every set's hash names every question's wording: change one
// question's text, or its id, and the hash changes. A hash that dropped
// the texts would make two differently worded sets read as one.
func TestEveryQuestionSetHashNamesEachQuestionsWording(t *testing.T) {
	for name, c := range map[string]struct {
		set  func() []Question
		hash func([]Question) string
	}{
		"model input": {ModelInputQuestions, func(qs []Question) string { return modelInputHashOf(DefaultModel, true, qs) }},
		"draft":       {DraftQuestions, func(qs []Question) string { return draftHashOf(DefaultModel, qs) }},
		"voice":       {VoiceQuestions, func(qs []Question) string { return voiceHashOf(DefaultModel, qs) }},
		"rubric":      {RubricQuestions, func(qs []Question) string { return rubricHashOf(DefaultModel, RubricBatchOne, qs, RunnerGrants) }},
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
	if rubricHashOf(DefaultModel, RubricBatchOne, RubricQuestions(), RunnerGrants+" Reworded.") ==
		rubricHashOf(DefaultModel, RubricBatchOne, RubricQuestions(), RunnerGrants) {
		t.Fatal("rubric: the runner's grants are not in the hash")
	}
	if modelInputHash(DefaultModel, true) != modelInputHashOf(DefaultModel, true, ModelInputQuestions()) ||
		draftHash(DefaultModel) != draftHashOf(DefaultModel, DraftQuestions()) ||
		voiceHash(DefaultModel) != voiceHashOf(DefaultModel, VoiceQuestions()) {
		t.Fatal("a scanner's hash is the hash of the set it asks")
	}

	// Hash is SHA-256 over the parts, each followed by a NUL, so a part
	// boundary cannot move without changing it.
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return "sha256:" + hex.EncodeToString(h[:]) }
	of := func(parts ...string) string { return sum(strings.Join(parts, "\x00") + "\x00") }
	for _, c := range []struct {
		parts []string
		want  string
	}{
		{nil, sum("")},
		{[]string{"a"}, sum("a\x00")},
		{[]string{"a", "b"}, sum("a\x00b\x00")},
		{[]string{"ab"}, sum("ab\x00")},
		{[]string{"", ""}, sum("\x00\x00")},
	} {
		if got := Hash(c.parts...); got != c.want {
			t.Fatalf("Hash(%q) = %s, want %s", c.parts, got, c.want)
		}
	}
	if Hash("a", "b") == Hash("ab") || Hash("a", "b") == Hash("ab", "") {
		t.Fatal("parts must be separated")
	}

	// Each hash names, beside the question texts, every bound, line and
	// count that changes a verdict; spelled out here so that dropping or
	// moving one is a change of the recorded hash.
	qs := func(qs []Question) []string {
		var out []string
		for _, q := range qs {
			out = append(out, "question="+q.ID+"="+q.Text)
		}
		return out
	}
	cat := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	model := "model=" + DefaultModel
	if got, want := modelInputHash(DefaultModel, true), of(cat(
		[]string{"agentry/model-input/v1", "provider=typesafe", model, "state=source,content"}, qs(ModelInputQuestions()),
		[]string{"sources=description,search_result,page,registry,input_file", "chunk=8192", "thresholds=0.5/0.7/0.9", "withhold=2", "band=0.30/0.70", "samples=3"})...); got != want {
		t.Fatalf("model-input hash is not the one spelled out:\n got %s\nwant %s", got, want)
	}
	if got, want := modelInputHash(DefaultModel, false), of(cat(
		[]string{"agentry/model-input/v1", "provider=typesafe", model, "state=source,content"}, qs(ModelInputQuestions()),
		[]string{"sources=description,search_result,page,registry,input_file", "chunk=8192", "thresholds=0.5/0.7/0.9", "withhold=2", "samples=1"})...); got != want {
		t.Fatalf("single-sample model-input hash is not the one spelled out:\n got %s\nwant %s", got, want)
	}
	if got, want := draftHash(DefaultModel), of(cat(
		[]string{"agentry/draft-check/v1", "provider=typesafe", model, "state=description,manifest,instruction"}, qs(DraftQuestions()),
		[]string{"bounds=8192/16384/32768/49152", "thresholds=0.5/0.7/0.9", "flag=2", "band=0.30/0.70", "samples=3"})...); got != want {
		t.Fatalf("draft hash is not the one spelled out:\n got %s\nwant %s", got, want)
	}
	if got, want := voiceHash(DefaultModel), of(cat(
		[]string{"agentry/voice-check/v1", "provider=typesafe", model, "state=voice"}, qs(VoiceQuestions()),
		[]string{"bound=32768", "thresholds=0.5/0.7/0.9", "flag=2", "band=0.30/0.70", "samples=3"})...); got != want {
		t.Fatalf("voice hash is not the one spelled out:\n got %s\nwant %s", got, want)
	}
	var rubricQs []string
	for _, q := range RubricQuestions() {
		rubricQs = append(rubricQs, q.ID+"="+q.Text)
	}
	for batch, shape := range map[int]*RubricScanner{1: NewRubricScanner(nil), 2: NewRubricScannerShape(nil, 2), 6: NewRubricScannerShape(nil, 6), 3: NewRubricScannerShape(nil, 3)} {
		want := batch
		if want == 3 {
			want = 1
		}
		fixed := of("agentry/judge-rubric/v1;categories=C1..C6;scores=0-3;content-is-data;no-tools;temperature=0;structured-output",
			"provider=typesafe", "model="+DefaultModel, "axes=C1..C6", "questions="+strings.Join(rubricQs, "\n"),
			fmt.Sprintf("batch=%d", want), "chunk=8192", "declared-cap=4096", "runner-grants="+RunnerGrants, "purpose-cap=2048",
			"thresholds=0.5/0.7/0.9", "band=0.30/0.70", "samples=3")
		if got := rubricHashOf(DefaultModel, shape.batch, RubricQuestions(), RunnerGrants); got != fixed {
			t.Fatalf("rubric hash of shape %d is not the one spelled out:\n got %s\nwant %s", batch, got, fixed)
		}
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
