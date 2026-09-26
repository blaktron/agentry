package websearch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanQuery(t *testing.T) {
	if q, err := CleanQuery("  github mcp server  "); err != nil || q != "github mcp server" {
		t.Fatalf("%q %v", q, err)
	}
	for _, bad := range []string{"", "   ", strings.Repeat("a", MaxQuery+1), "line\nbreak", "tab\there", "\xff\xfe"} {
		if _, err := CleanQuery(bad); err != ErrBadQuery {
			t.Fatalf("%q must be refused", bad)
		}
	}
	if _, err := CleanQuery(strings.Repeat("é", MaxQuery)); err != nil {
		t.Fatal("the bound is in characters, not bytes")
	}
}

func TestClampCount(t *testing.T) {
	for in, want := range map[int]int{-3: DefaultCount, 0: DefaultCount, 1: 1, 7: 7, 10: 10, 11: MaxCount, 1000: MaxCount} {
		if got := ClampCount(in); got != want {
			t.Fatalf("ClampCount(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestCleanBoundsEveryResult(t *testing.T) {
	in := []Result{
		{Title: "  One\n\n  result\t", URL: "https://example.com/a", Snippet: "text\x00with\x07controls"},
		{Title: "dup", URL: "https://example.com/a"},
		{Title: "no scheme", URL: "example.com/b"},
		{Title: "ftp", URL: "ftp://example.com/c"},
		{Title: "userinfo", URL: "https://user:pass@example.com/d"},
		{Title: "javascript", URL: "javascript:alert(1)"},
		{Title: strings.Repeat("t", 500), URL: "http://example.org/long", Snippet: strings.Repeat("s", 5000) + "\xff"},
		{Title: "too long", URL: "https://example.com/" + strings.Repeat("x", maxURL)},
		{Title: "four", URL: "https://example.net/4"},
	}
	out := Clean(in, 10)
	if len(out) != 3 {
		t.Fatalf("kept %d: %+v", len(out), out)
	}
	if out[0].Title != "One result" || out[0].Snippet != "textwithcontrols" {
		t.Fatalf("first: %+v", out[0])
	}
	if utf8.RuneCountInString(out[1].Title) != maxTitle || utf8.RuneCountInString(out[1].Snippet) != maxSnippet || !utf8.ValidString(out[1].Snippet) {
		t.Fatalf("bounds: %d %d", utf8.RuneCountInString(out[1].Title), utf8.RuneCountInString(out[1].Snippet))
	}
	if got := Clean(in, 1); len(got) != 1 {
		t.Fatalf("count bounds the results: %d", len(got))
	}
}

func TestYouComAsksOnceWithTheKeyAndReadsOnlyTheWebResults(t *testing.T) {
	var got struct {
		Key, Method, Path string
		Body              map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Key, got.Method, got.Path = r.Header.Get("X-API-Key"), r.Method, r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.Body)
		_, _ = w.Write([]byte(`{"results":{
			"web":[
				{"url":"https://github.com/modelcontextprotocol/servers","title":"MCP servers","description":"Reference servers.","thumbnail_url":"https://img.example/t.png"},
				{"url":"https://example.com/b","title":"B","description":"","snippets":["from snippets"]}
			],
			"news":[{"url":"https://news.example/x","title":"news","description":"not read"}]},
			"metadata":{"search_uuid":"u","query":"q","latency":0.2}}`))
	}))
	defer srv.Close()
	y, err := NewYouCom(YouComConfig{BaseURL: srv.URL, APIKey: "ydc-secret-key"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := y.Search(context.Background(), "github mcp server", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != "ydc-secret-key" || got.Method != http.MethodPost || got.Path != "/v1/search" {
		t.Fatalf("request: %+v", got)
	}
	if got.Body["query"] != "github mcp server" || got.Body["count"] != float64(3) {
		t.Fatalf("body: %+v", got.Body)
	}
	for _, never := range []string{"extraction", "knowledge"} {
		if _, ok := got.Body[never]; ok {
			t.Fatalf("the request must never ask for %s", never)
		}
	}
	if len(res) != 2 || res[0].Title != "MCP servers" || res[0].Snippet != "Reference servers." || res[1].Snippet != "from snippets" {
		t.Fatalf("results: %+v", res)
	}
}

func TestYouComFailsWithoutTheKeyInTheError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":"payment required for key ` + r.Header.Get("X-API-Key") + `"}`))
	}))
	defer srv.Close()
	y, _ := NewYouCom(YouComConfig{BaseURL: srv.URL, APIKey: "ydc-secret-key"})
	_, err := y.Search(context.Background(), "q", 5)
	if err == nil || strings.Contains(err.Error(), "ydc-secret-key") || !strings.Contains(err.Error(), "402") {
		t.Fatalf("err = %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`not json`)) }))
	defer bad.Close()
	y2, _ := NewYouCom(YouComConfig{BaseURL: bad.URL, APIKey: "k"})
	if _, err := y2.Search(context.Background(), "q", 5); err == nil {
		t.Fatal("an out-of-shape answer is an error")
	}
}

func TestNewNamesTheProviders(t *testing.T) {
	for _, off := range []string{"", "none"} {
		if p, err := New(off, "", ""); p != nil || err != nil {
			t.Fatalf("%q: %v %v", off, p, err)
		}
	}
	if _, err := New("youcom", "", ""); err != ErrNoKey {
		t.Fatalf("no key: %v", err)
	}
	if p, err := New("youcom", "", "k"); err != nil || p.Name() != YouComName {
		t.Fatalf("youcom: %v %v", p, err)
	}
	for _, unknown := range []string{"fake", "brave", "google"} {
		if _, err := New(unknown, "", "k"); err == nil {
			t.Fatalf("%q must be refused: no configuration names the fake or an unbuilt provider", unknown)
		}
	}
}
