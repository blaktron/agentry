package websearch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// braveAnswer is the LLM Context shape as Brave answered on 2026-09-26:
// grounding.generic (read), grounding.map and grounding.poi (local results,
// never read) and the sources map (never read).
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
	if q.Get("q") != "RFC 4180 CSV" || q.Get("count") != "3" || q.Get("maximum_number_of_urls") != "3" || q.Get("enable_local") != "false" {
		t.Fatalf("query: %v", q)
	}
	if strings.Contains(got.URL.RawQuery, "brave-secret-key") {
		t.Fatal("the key rode in the URL")
	}
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

func TestBraveFailsWithoutTheKeyInTheErrorAndNeverFollowsARedirect(t *testing.T) {
	key := "brave-secret-key-long-enough"
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(strings.Repeat("x", 190) + key))
	}))
	defer echo.Close()
	b, _ := NewBrave(BraveConfig{BaseURL: echo.URL, APIKey: key})
	_, err := b.Search(context.Background(), "q", 5)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusTooManyRequests || se.Provider != BraveName || strings.Contains(err.Error(), "brave-secret") {
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
}
