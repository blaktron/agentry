package judge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

// The bearer key is sent only over https. A loopback address may be plain
// http, for a test server on the same machine, and nothing else may.
func TestNewSendsTheKeyOnlyOverHTTPS(t *testing.T) {
	refused := []string{
		"http://api.typesafe.ai",
		"http://example.com/v1",
		"http://10.0.0.5:8080",
		"http://192.168.1.2",
		"http://0.0.0.0:80",
		"http://localhost.example.com",
		"http://127.0.0.1.example.com",
		"http://127.0.0.1@example.com",
		"http://user:pass@example.com",
		"HTTP://API.TYPESAFE.AI",
		"ftp://api.typesafe.ai",
		"api.typesafe.ai",
		"//api.typesafe.ai",
		"https://",
		"https:///v1",
		"http://",
		"file:///etc/passwd",
		"not a url",
		"https://exa mple.com",
	}
	for _, base := range refused {
		var requests atomic.Int32
		hc := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return nil, io.EOF
		})}
		c, err := New(Config{BaseURL: base, APIKey: "tok-secret-value", HTTPClient: hc, RetryWait: -1})
		if err == nil || c != nil {
			t.Fatalf("base %q must be refused: %v %v", base, c, err)
		}
		if strings.Contains(err.Error(), "tok-secret-value") {
			t.Fatalf("base %q: the error carries the key: %v", base, err)
		}
		if requests.Load() != 0 {
			t.Fatalf("base %q: %d requests were sent", base, requests.Load())
		}
	}
	accepted := []string{
		"https://api.typesafe.ai",
		"https://api.typesafe.ai/",
		"HTTPS://API.TYPESAFE.AI",
		"https://llm.example.internal:8443/base",
		"http://127.0.0.1:8080",
		"http://127.1.2.3",
		"http://localhost:9",
		"http://LOCALHOST",
		"http://[::1]:8080",
		"",
	}
	for _, base := range accepted {
		if _, err := New(Config{BaseURL: base, APIKey: "k"}); err != nil {
			t.Fatalf("base %q must be accepted: %v", base, err)
		}
	}
}

func TestCheckBaseURLNamesTheRule(t *testing.T) {
	if err := CheckBaseURL(""); err != nil {
		t.Fatalf("an empty base is the default: %v", err)
	}
	err := CheckBaseURL("http://api.typesafe.ai")
	if err == nil || !strings.Contains(err.Error(), "https") || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("the refusal must say what is allowed: %v", err)
	}
	if err := CheckBaseURL("https://user:secret@example.com"); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("credentials in a base URL are refused without being repeated: %v", err)
	}
}

// A key reaches a loopback http server: the one plain channel allowed.
func TestAKeyReachesALoopbackServer(t *testing.T) {
	srv, calls := fakeJev(t, DefaultModel, func(int, string, call) (float64, int) { return 0.1, 0 })
	if !strings.HasPrefix(srv.URL, "http://127.0.0.1:") {
		t.Fatalf("fixture is %s", srv.URL)
	}
	if _, _, err := client(t, srv).Ask(context.Background(), map[string]string{"content": "x"}, ModelInputQuestions()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0].Auth != "Bearer tok-secret-value" {
		t.Fatalf("calls: %+v", *calls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// An answer must say it is a noul answer; any other type is not one the
// question asked for.
func TestAskRefusesAnAnswerThatIsNotANoul(t *testing.T) {
	for _, typ := range []string{"", "text", "NOUL", "bool", "number"} {
		body := func() string {
			var parts []string
			for _, q := range ModelInputQuestions() {
				parts = append(parts, `"`+q.ID+`":{"type":"`+typ+`","noul":0.1}`)
			}
			return `{"model":"` + DefaultModel + `","answers":{` + strings.Join(parts, ",") + `}}`
		}()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		_, _, err := client(t, srv).Ask(context.Background(), map[string]string{"content": "x"}, ModelInputQuestions())
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "noul") {
			t.Fatalf("type %q: must be refused, got %v", typ, err)
		}
	}
	srv, _ := fakeJev(t, DefaultModel, func(int, string, call) (float64, int) { return 0.1, 0 })
	if _, _, err := client(t, srv).Ask(context.Background(), map[string]string{"content": "x"}, ModelInputQuestions()); err != nil {
		t.Fatalf("a noul answer: %v", err)
	}
}

// The declared-capabilities field is cut at a character, never inside one.
func TestDeclaredCapabilitiesIsNotCutInsideACharacter(t *testing.T) {
	for _, ch := range []string{"é", "€", "😀"} {
		// Vary the lead-in so the cap falls on every byte of the character.
		for lead := 0; lead < utf8.UTFMax; lead++ {
			val := strings.Repeat("p", lead) + strings.Repeat(ch, DeclaredCapabilitiesCap)
			got := DeclaredCapabilities([]byte(`{"capabilities":{"k":"`+val+`"}}`), nil)
			if !utf8.ValidString(got) {
				t.Fatalf("%q lead %d: the field is not valid UTF-8", ch, lead)
			}
			body, ok := strings.CutSuffix(got, truncatedMark)
			if !ok {
				t.Fatalf("%q lead %d: not marked as cut", ch, lead)
			}
			if len(body) > DeclaredCapabilitiesCap || len(body) <= DeclaredCapabilitiesCap-utf8.UTFMax {
				t.Fatalf("%q lead %d: kept %d bytes of a %d cap", ch, lead, len(body), DeclaredCapabilitiesCap)
			}
		}
	}
}

// A voice or a draft with nothing in it is not sent to the judge.
func TestAnEmptyVoiceOrDraftIsNotSentToTheJudge(t *testing.T) {
	for _, voice := range []string{"", " ", "\n\t \r\n", "  "} {
		f := &fakeAsker{answer: quiet}
		res := NewVoiceScanner(f).Scan(context.Background(), voice)
		if res.Verdict != VerdictNotScanned || res.Failure != FailureInvalid || res.Err == nil {
			t.Fatalf("voice %q: %+v", voice, res)
		}
		if f.n != 0 {
			t.Fatalf("voice %q: the judge was asked %d times", voice, f.n)
		}
	}
	for _, in := range []DraftInput{
		{},
		{Description: " ", ManifestJSON: []byte("\n"), Instruction: "\t"},
		{ManifestJSON: []byte("  ")},
	} {
		f := &fakeAsker{answer: quiet}
		res := NewDraftScanner(f).Scan(context.Background(), in)
		if res.Verdict != VerdictNotScanned || res.Failure != FailureInvalid || res.Err == nil {
			t.Fatalf("draft %+v: %+v", in, res)
		}
		if f.n != 0 {
			t.Fatalf("draft %+v: the judge was asked %d times", in, f.n)
		}
	}
	// One part with something in it is a draft.
	f := &fakeAsker{answer: quiet}
	if res := NewDraftScanner(f).Scan(context.Background(), DraftInput{Instruction: "Summarise the page."}); res.Verdict != VerdictPass {
		t.Fatalf("a draft with an instruction: %+v", res)
	}
	f = &fakeAsker{answer: quiet}
	if res := NewVoiceScanner(f).Scan(context.Background(), " warm and plain "); res.Verdict != VerdictPass {
		t.Fatalf("a voice with text: %+v", res)
	}
}
