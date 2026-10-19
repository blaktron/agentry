package websearch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// braveAnswer is the LLM Context shape Brave answers
// (grounding.generic, read; grounding.map and the sources map, never read),
// with the grounding.poi its reference documents added, also never read.
const braveAnswer = `{"grounding":{
	"generic":[
		{"url":"https://www.loc.gov/preservation/digital/formats/fdd/fdd000323.shtml","title":"CSV, Comma Separated Values (RFC 4180)",
		 "snippets":["RFC 4180 defines the CSV format.","Fields may be quoted."]},
		{"url":"https://example.com/b","title":"B","snippets":[]}
	],
	"map":[{"name":"a place","url":"https://maps.example/p","title":"a place","snippets":["not read"]}],
	"poi":{"name":"a shop","url":"https://poi.example/s","title":"a shop","snippets":["not read"]}},
	"sources":{"https://www.loc.gov/preservation/digital/formats/fdd/fdd000323.shtml":{"title":"t","hostname":"www.loc.gov","snippet":"not read"}}}`

func TestBraveAsksOnceWithTheKeyAndReadsOnlyTheGenericResults(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		_, _ = w.Write([]byte(braveAnswer))
	}))
	defer srv.Close()
	b, err := NewBrave(BraveConfig{BaseURL: srv.URL, APIKey: "brave-secret-key"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.Search(context.Background(), "RFC 4180 CSV", 3)
	if err != nil {
		t.Fatal(err)
	}
	q := got.URL.Query()
	if got.Method != http.MethodGet || got.URL.Path != "/res/v1/llm/context" || got.Header.Get("X-Subscription-Token") != "brave-secret-key" {
		t.Fatalf("request: %s %s", got.Method, got.URL)
	}
	if q.Get("q") != "RFC 4180 CSV" || q.Get("maximum_number_of_urls") != "3" || q.Get("maximum_number_of_tokens") != "2048" ||
		q.Get("maximum_number_of_tokens_per_url") != "512" || q.Get("enable_local") != "false" || q.Has("count") {
		t.Fatalf("query: %v", q)
	}
	if strings.Contains(got.URL.RawQuery, "brave-secret-key") {
		t.Fatal("the key rode in the URL")
	}
	if got.Header.Get("Accept") != "application/json" {
		t.Fatalf("Accept = %q", got.Header.Get("Accept"))
	}
	assertKeyOnlyIn(t, "brave-secret-key", "X-Subscription-Token", got, nil)
	if len(res) != 2 || res[0].URL != "https://www.loc.gov/preservation/digital/formats/fdd/fdd000323.shtml" ||
		res[0].Title != "CSV, Comma Separated Values (RFC 4180)" || res[0].Snippet != "RFC 4180 defines the CSV format. … Fields may be quoted." ||
		res[1].Snippet != "" {
		t.Fatalf("results: %+v", res)
	}
	for _, r := range res {
		if strings.Contains(r.URL, "maps.example") || strings.Contains(r.URL, "poi.example") {
			t.Fatalf("a local result was read: %+v", r)
		}
	}
}

// A non-200 answer, a redirect, an answer out of shape and a missing key
// are each refused, and no error carries any part of the key.
func TestBraveRefusalsCarryNoKeyAndNoRedirectIsFollowed(t *testing.T) {
	key := "brave-secret-key-long-enough"
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(strings.Repeat("x", 190) + key))
	}))
	defer echo.Close()
	b, _ := NewBrave(BraveConfig{BaseURL: echo.URL, APIKey: key})
	_, err := b.Search(context.Background(), "q", 5)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusTooManyRequests || se.Provider != BraveName || strings.Contains(err.Error(), "brave-secr") {
		t.Fatalf("err = %v", err)
	}

	var hit bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/res/v1/llm/context", http.StatusFound)
	}))
	defer srv.Close()
	b2, _ := NewBrave(BraveConfig{BaseURL: srv.URL, APIKey: "k", HTTPClient: &http.Client{}})
	if _, err := b2.Search(context.Background(), "q", 5); !errors.As(err, &se) || se.Status != http.StatusFound || hit {
		t.Fatalf("err %v, followed %v", err, hit)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`not json`)) }))
	defer bad.Close()
	b3, _ := NewBrave(BraveConfig{BaseURL: bad.URL, APIKey: "k"})
	if _, err := b3.Search(context.Background(), "q", 5); err == nil {
		t.Fatal("an out-of-shape answer is an error")
	}
	if _, err := NewBrave(BraveConfig{APIKey: "  "}); err != ErrNoKey {
		t.Fatalf("no key: %v", err)
	}

	checkClientControls(t, controls{
		name: BraveName, key: key, header: "X-Subscription-Token",
		build:    func(c ClientConfig) (Provider, error) { return NewBrave(c) },
		path:     "/res/v1/llm/context",
		endpoint: "https://api.search.brave.com/res/v1/llm/context",
		answer:   `{"grounding":{"generic":[]}}`, head: `{"grounding":{"generic":[]},"pad":"`, tail: `"}`,
	})
}

// A query the route admits (400 characters) can pass Brave's 75 words, and
// 400 characters of a wide script pass 600 bytes; either would be a 422.
// The client searches on the query's opening words within both.
func TestBraveHoldsTheQueryToItsLimits(t *testing.T) {
	var got, urls string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, urls = r.URL.Query().Get("q"), r.URL.Query().Get("maximum_number_of_urls")
		_, _ = w.Write([]byte(`{"grounding":{"generic":[]}}`))
	}))
	defer srv.Close()
	b, _ := NewBrave(BraveConfig{BaseURL: srv.URL, APIKey: "k"})

	words := strings.TrimSpace(strings.Repeat("ab ", 120))
	q, err := CleanQuery(words)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Search(context.Background(), q, 5); err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(got)); n != 75 || got != strings.TrimSpace(strings.Repeat("ab ", 75)) {
		t.Fatalf("sent %d words: %q", n, got)
	}

	wide, err := CleanQuery(strings.Repeat("検", 400))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Search(context.Background(), wide, 5); err != nil {
		t.Fatal(err)
	}
	if len(got) > 600 || !utf8.ValidString(got) || got != strings.Repeat("検", 200) {
		t.Fatalf("sent %d bytes, valid %v", len(got), utf8.ValidString(got))
	}

	if _, err := b.Search(context.Background(), "RFC 4180 CSV", 5); err != nil || got != "RFC 4180 CSV" {
		t.Fatalf("a short query must go as it is: %q %v", got, err)
	}

	// The byte limit is 600 inclusive, cut at a character, with no space
	// left at the cut; white space between words folds to one space.
	for name, tc := range map[string]struct{ in, want string }{
		"exactly 600 bytes":          {strings.Repeat("検", 200), strings.Repeat("検", 200)},
		"one character past":         {strings.Repeat("検", 201), strings.Repeat("検", 200)},
		"a cut inside a character":   {"a" + strings.Repeat("検", 300), "a" + strings.Repeat("検", 199)},
		"a space at the cut":         {strings.Repeat("a", 599) + " bbbb", strings.Repeat("a", 599)},
		"white space between words":  {"a  b\n\tc", "a b c"},
		"exactly 75 words are whole": {strings.TrimSpace(strings.Repeat("ab ", 75)), strings.TrimSpace(strings.Repeat("ab ", 75))},
	} {
		if _, err := b.Search(context.Background(), tc.in, 5); err != nil || got != tc.want {
			t.Fatalf("%s: sent %d bytes %q, %v", name, len(got), got, err)
		}
	}

	// The count asked for is held to 1..MaxCount, 0 or less meaning the default.
	for asked, want := range map[int]string{-1: "5", 0: "5", 1: "1", 10: "10", 11: "10", 50: "10"} {
		if _, err := b.Search(context.Background(), "q", asked); err != nil || urls != want {
			t.Fatalf("asked %d: sent %q, want %q (%v)", asked, urls, want, err)
		}
	}
}
