package websearch

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// The providers a person may name for their own key (agentry#783): each is
// one POST with the key in its header and never in the URL or the body,
// asks for the plain results and none of the paid extras, and reads only
// its result list. The answers are the documented shapes (2026-09-30), with
// the fields each client must ignore.
var personalProviders = []struct {
	name   string
	build  func(ClientConfig) (Provider, error)
	header string // the header the key rides in
	prefix string // what precedes the key in it
	count  string // the body's field for the number of results
	path   string
	want   map[string]any // the request body, for a count of 3
	answer string
	result []Result
}{
	{
		name:   TavilyName,
		build:  func(c ClientConfig) (Provider, error) { return NewTavily(c) },
		header: "Authorization", prefix: "Bearer ", count: "max_results", path: "/search",
		want: map[string]any{"query": "RFC 4180 CSV", "max_results": 3.0, "search_depth": "basic", "chunks_per_source": 2.0, "topic": "general",
			"include_answer": false, "include_raw_content": false, "include_images": false, "auto_parameters": false},
		answer: `{"query":"RFC 4180 CSV","answer":"not read","images":["https://img.example/1.png"],
			"results":[{"title":"RFC 4180","url":"https://www.rfc-editor.org/rfc/rfc4180","content":"Common Format and MIME Type for CSV Files.","score":0.9,"raw_content":null},
			{"title":"B","url":"https://example.com/b","content":""}],"response_time":0.5,"request_id":"r"}`,
		result: []Result{{Title: "RFC 4180", URL: "https://www.rfc-editor.org/rfc/rfc4180", Snippet: "Common Format and MIME Type for CSV Files."}, {Title: "B", URL: "https://example.com/b"}},
	},
	{
		name:   ExaName,
		build:  func(c ClientConfig) (Provider, error) { return NewExa(c) },
		header: "x-api-key", count: "numResults", path: "/search",
		want: map[string]any{"query": "RFC 4180 CSV", "type": "auto", "numResults": 3.0,
			"contents": map[string]any{"highlights": map[string]any{"maxCharacters": 1000.0}}},
		answer: `{"requestId":"r","resolvedSearchType":"neural","costDollars":{"total":0.007},
			"results":[{"title":"RFC 4180","url":"https://www.rfc-editor.org/rfc/rfc4180","id":"x","image":"https://img.example/i.png",
			"favicon":"https://img.example/f.ico","highlights":["Common Format and MIME Type.","Fields may be quoted."],"highlightScores":[0.5,0.4]},
			{"title":"","url":"https://example.com/b"}]}`,
		result: []Result{{Title: "RFC 4180", URL: "https://www.rfc-editor.org/rfc/rfc4180", Snippet: "Common Format and MIME Type. … Fields may be quoted."}, {URL: "https://example.com/b"}},
	},
	{
		name:   PerplexityName,
		build:  func(c ClientConfig) (Provider, error) { return NewPerplexity(c) },
		header: "Authorization", prefix: "Bearer ", count: "max_results", path: "/search",
		want: map[string]any{"query": "RFC 4180 CSV", "max_results": 3.0, "search_type": "web", "max_tokens_per_page": 256.0},
		answer: `{"id":"r","server_time":null,"results":[{"title":"RFC 4180","url":"https://www.rfc-editor.org/rfc/rfc4180",
			"snippet":"Common Format and MIME Type for CSV Files.","date":"2005-10-01","last_updated":"2024-01-01"}]}`,
		result: []Result{{Title: "RFC 4180", URL: "https://www.rfc-editor.org/rfc/rfc4180", Snippet: "Common Format and MIME Type for CSV Files."}},
	},
}

func TestPersonalProvidersAskOnceWithTheKeyInTheirHeaderAndReadOnlyTheResults(t *testing.T) {
	const key = "provider-secret-key"
	for _, p := range personalProviders {
		t.Run(p.name, func(t *testing.T) {
			var got *http.Request
			var sent map[string]any
			var calls int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				got = r.Clone(context.Background())
				raw, _ := io.ReadAll(r.Body)
				if strings.Contains(string(raw), key) {
					t.Error("the key rode in the body")
				}
				if err := json.Unmarshal(raw, &sent); err != nil {
					t.Errorf("body is not JSON: %v", err)
				}
				_, _ = w.Write([]byte(p.answer))
			}))
			defer srv.Close()
			prov, err := p.build(ClientConfig{BaseURL: srv.URL, APIKey: key})
			if err != nil {
				t.Fatal(err)
			}
			if prov.Name() != p.name {
				t.Fatalf("name %q", prov.Name())
			}
			res, err := prov.Search(context.Background(), "RFC 4180 CSV", 3)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || got.Method != http.MethodPost || got.URL.Path != p.path || got.Header.Get(p.header) != p.prefix+key ||
				got.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("request: %d %s %s %q", calls, got.Method, got.URL, got.Header)
			}
			if strings.Contains(got.URL.String(), key) {
				t.Fatal("the key rode in the URL")
			}
			if !reflect.DeepEqual(sent, p.want) {
				t.Fatalf("body:\n got %v\nwant %v", sent, p.want)
			}
			if !reflect.DeepEqual(res, p.result) {
				t.Fatalf("results:\n got %+v\nwant %+v", res, p.result)
			}
			for _, r := range res {
				if strings.Contains(r.URL, "img.example") || strings.Contains(r.Snippet, "not read") {
					t.Fatalf("an ignored field was read: %+v", r)
				}
			}
		})
	}
}

// A count past MaxCount is asked as MaxCount, so no provider bills the
// results past ten some of them charge extra for.
func TestPersonalProvidersNeverAskForMoreThanTheMostResults(t *testing.T) {
	for _, p := range personalProviders {
		t.Run(p.name, func(t *testing.T) {
			var sent map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&sent)
				_, _ = w.Write([]byte(`{"results":[]}`))
			}))
			defer srv.Close()
			prov, _ := p.build(ClientConfig{BaseURL: srv.URL, APIKey: "k"})
			if _, err := prov.Search(context.Background(), "q", 50); err != nil {
				t.Fatal(err)
			}
			if n, _ := sent[p.count].(float64); n != MaxCount {
				t.Fatalf("asked for %v results", sent[p.count])
			}
		})
	}
}

// A non-200 answer, a redirect, an answer out of shape and a missing key
// are each refused, and no error carries any part of the key.
func TestPersonalProvidersRefusalsCarryNoKeyAndNoRedirectIsFollowed(t *testing.T) {
	key := "provider-secret-key-long-enough"
	for _, p := range personalProviders {
		t.Run(p.name, func(t *testing.T) {
			echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(strings.Repeat("x", 190) + key))
			}))
			defer echo.Close()
			prov, _ := p.build(ClientConfig{BaseURL: echo.URL, APIKey: key})
			_, err := prov.Search(context.Background(), "q", 5)
			var se *StatusError
			if !errors.As(err, &se) || se.Status != http.StatusUnauthorized || se.Provider != p.name || strings.Contains(err.Error(), "provider-se") {
				t.Fatalf("err = %v", err)
			}

			var hit bool
			elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
			defer elsewhere.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, elsewhere.URL+p.path, http.StatusTemporaryRedirect)
			}))
			defer srv.Close()
			prov2, _ := p.build(ClientConfig{BaseURL: srv.URL, APIKey: key, HTTPClient: &http.Client{}})
			if _, err := prov2.Search(context.Background(), "q", 5); !errors.As(err, &se) || se.Status != http.StatusTemporaryRedirect || hit ||
				strings.Contains(err.Error(), "provider-se") {
				t.Fatalf("err %v, followed %v", err, hit)
			}

			bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`not json`)) }))
			defer bad.Close()
			prov3, _ := p.build(ClientConfig{BaseURL: bad.URL, APIKey: key})
			if _, err := prov3.Search(context.Background(), "q", 5); err == nil || strings.Contains(err.Error(), "provider-se") {
				t.Fatalf("an out-of-shape answer is an error, with no key: %v", err)
			}
			if _, err := p.build(ClientConfig{APIKey: "  "}); err != ErrNoKey {
				t.Fatalf("no key: %v", err)
			}
		})
	}
}
