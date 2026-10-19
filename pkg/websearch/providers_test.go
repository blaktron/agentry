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
	"time"
)

// roundTripFunc is a transport made of a function, so a test sees the
// request a client builds without dialing anything.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// cannedResponse is a 200 answer carrying body.
func cannedResponse(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

// serve starts a test server answering with h, closed with the test.
func serve(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s.URL
}

// clientOf is the shared client inside a provider this package built.
func clientOf(t *testing.T, p Provider) *client {
	t.Helper()
	switch v := p.(type) {
	case *YouCom:
		return v.c
	case *Brave:
		return v.c
	case *Tavily:
		return v.c
	case *Exa:
		return v.c
	case *Perplexity:
		return v.c
	}
	t.Fatalf("unexpected provider %T", p)
	return nil
}

// assertKeyOnlyIn fails when the key rides anywhere in a request but the
// one header want: any other header, the URL or the body.
func assertKeyOnlyIn(t *testing.T, key, want string, r *http.Request, body []byte) {
	t.Helper()
	for name, values := range r.Header {
		if name == http.CanonicalHeaderKey(want) {
			continue
		}
		for _, v := range values {
			if strings.Contains(v, key) {
				t.Errorf("the key rode in the %s header", name)
			}
		}
	}
	if strings.Contains(r.URL.String(), key) {
		t.Error("the key rode in the URL")
	}
	if strings.Contains(string(body), key) {
		t.Error("the key rode in the body")
	}
}

// paddedJSON is head, a filler and tail, size bytes in all, so an answer
// can sit exactly at a size bound and stay valid JSON.
func paddedJSON(head, tail string, size int) []byte {
	return []byte(head + strings.Repeat("x", size-len(head)-len(tail)) + tail)
}

// controls describes one provider to checkClientControls.
type controls struct {
	name, key      string
	header, prefix string // the header the key rides in, and what precedes it
	build          func(ClientConfig) (Provider, error)
	path           string // the request path
	endpoint       string // the provider's own address: scheme, host and path
	answer         string // a valid 200 answer
	head, tail     string // a valid answer around a filler string
}

// checkClientControls holds a provider's client to what every provider
// shares: its own https address by default, a tolerant base address, a key
// trimmed and redacted wherever an error could carry it, a bounded
// answer, no redirect followed with any client, a status other than 200
// refused with a bounded body, and a search that ends with its context.
func checkClientControls(t *testing.T, c controls) {
	t.Helper()
	const timeout = 20 * time.Second

	t.Run("the default address is the provider's own https one", func(t *testing.T) {
		var seen *http.Request
		hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			seen = r
			return cannedResponse(r, c.answer), nil
		})}
		prov, err := c.build(ClientConfig{APIKey: c.key, HTTPClient: hc})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prov.Search(context.Background(), "q", 5); err != nil {
			t.Fatal(err)
		}
		if got := seen.URL.Scheme + "://" + seen.URL.Host + seen.URL.Path; got != c.endpoint {
			t.Fatalf("asked %s, want %s", got, c.endpoint)
		}
		if seen.Header.Get(c.header) != c.prefix+c.key {
			t.Fatalf("the key is not in %s", c.header)
		}
	})

	t.Run("the client's timeout, and a caller's client left alone", func(t *testing.T) {
		prov, _ := c.build(ClientConfig{APIKey: c.key})
		if own := clientOf(t, prov).http; own.Timeout != timeout || own.CheckRedirect == nil {
			t.Fatalf("default client: timeout %v, redirect policy %v", own.Timeout, own.CheckRedirect != nil)
		}
		given := &http.Client{Timeout: 7 * time.Second}
		prov, _ = c.build(ClientConfig{APIKey: c.key, HTTPClient: given})
		if own := clientOf(t, prov).http; own == given || own.Timeout != 7*time.Second || own.CheckRedirect == nil {
			t.Fatalf("given client: same %v, timeout %v, redirect policy %v", own == given, own.Timeout, own.CheckRedirect != nil)
		}
		if given.CheckRedirect != nil {
			t.Fatal("the caller's client was changed")
		}
	})

	t.Run("a base address with a trailing slash and white space", func(t *testing.T) {
		var path string
		addr := serve(t, func(w http.ResponseWriter, r *http.Request) {
			path = r.URL.Path
			_, _ = w.Write([]byte(c.answer))
		})
		prov, _ := c.build(ClientConfig{BaseURL: "  " + addr + "/ ", APIKey: c.key})
		if _, err := prov.Search(context.Background(), "q", 5); err != nil || path != c.path {
			t.Fatalf("path %q, err %v", path, err)
		}
	})

	t.Run("a key with white space around it is trimmed and still redacted", func(t *testing.T) {
		var sent string
		addr := serve(t, func(w http.ResponseWriter, r *http.Request) {
			sent = r.Header.Get(c.header)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("xx" + c.key + "xx"))
		})
		prov, _ := c.build(ClientConfig{BaseURL: addr, APIKey: "  " + c.key + "  "})
		_, err := prov.Search(context.Background(), "q", 5)
		var se *StatusError
		if !errors.As(err, &se) || strings.Contains(err.Error(), c.key) || sent != c.prefix+c.key {
			t.Fatalf("err %v, header %q", err, sent)
		}
	})

	t.Run("only a 200 is an answer", func(t *testing.T) {
		for _, status := range []int{http.StatusCreated, http.StatusAccepted, http.StatusInternalServerError} {
			addr := serve(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(c.answer))
			})
			prov, _ := c.build(ClientConfig{BaseURL: addr, APIKey: c.key})
			_, err := prov.Search(context.Background(), "q", 5)
			var se *StatusError
			if !errors.As(err, &se) || se.Status != status {
				t.Fatalf("status %d: err = %v", status, err)
			}
		}
	})

	t.Run("a refusal says the provider and status and a bounded body without the key", func(t *testing.T) {
		send := func(status int, body string) error {
			addr := serve(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			})
			prov, _ := c.build(ClientConfig{BaseURL: addr, APIKey: c.key})
			_, err := prov.Search(context.Background(), "q", 5)
			return err
		}
		err := send(http.StatusUnauthorized, strings.Repeat("x", 190)+c.key)
		if want := "websearch: " + c.name + " returned 401: " + strings.Repeat("x", 190) + "[key]"; err == nil || err.Error() != want {
			t.Fatalf("err = %v, want %q", err, want)
		}
		x200 := strings.Repeat("x", 200)
		for name, tc := range map[string]struct{ body, want string }{
			"exactly the bound":           {x200, x200},
			"one past the bound":          {x200 + "x", x200},
			"far past the bound":          {strings.Repeat("x", 3000), x200},
			"half a character at the cut": {strings.Repeat("x", 199) + "é" + "tail", strings.Repeat("x", 199)},
			"the key twice":               {"a" + c.key + "b" + c.key, "a[key]b[key]"},
			"the key across the cut":      {strings.Repeat("x", 195) + c.key, strings.Repeat("x", 195) + "[key]"},
		} {
			var se *StatusError
			if err := send(http.StatusInternalServerError, tc.body); !errors.As(err, &se) || se.Snippet != tc.want {
				t.Fatalf("%s: err = %v", name, err)
			}
		}
	})

	t.Run("an error from the transport or the request never carries the key", func(t *testing.T) {
		hc := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("proxy refused token " + c.key + " and again " + c.key)
		})}
		prov, _ := c.build(ClientConfig{APIKey: c.key, HTTPClient: hc})
		_, err := prov.Search(context.Background(), "q", 5)
		if err == nil || strings.Contains(err.Error(), c.key) || strings.Count(err.Error(), "[key]") != 2 {
			t.Fatalf("transport error: %v", err)
		}
		prov, _ = c.build(ClientConfig{BaseURL: "http://bad host/" + c.key, APIKey: c.key})
		_, err = prov.Search(context.Background(), "q", 5)
		if err == nil || strings.Contains(err.Error(), c.key) || !strings.Contains(err.Error(), "[key]") {
			t.Fatalf("request error: %v", err)
		}
	})

	t.Run("an answer is read to two MiB and no further", func(t *testing.T) {
		const limit = 2 << 20
		for _, size := range []int{limit - 1, limit} {
			body := paddedJSON(c.head, c.tail, size)
			addr := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
			prov, _ := c.build(ClientConfig{BaseURL: addr, APIKey: c.key})
			if _, err := prov.Search(context.Background(), "q", 5); err != nil {
				t.Fatalf("an answer of %d bytes is refused: %v", size, err)
			}
		}
		body := paddedJSON(c.head, c.tail, limit+1)
		addr := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
		prov, _ := c.build(ClientConfig{BaseURL: addr, APIKey: c.key})
		if _, err := prov.Search(context.Background(), "q", 5); err == nil {
			t.Fatal("an answer past two MiB must not be read whole")
		}
	})

	t.Run("an answer cut short is a read error", func(t *testing.T) {
		addr := serve(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte("{"))
		})
		prov, _ := c.build(ClientConfig{BaseURL: addr, APIKey: c.key})
		_, err := prov.Search(context.Background(), "q", 5)
		var se *StatusError
		if !errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &se) || !strings.HasPrefix(err.Error(), "websearch: "+c.name+" response:") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("no redirect is followed, whichever client carries the request", func(t *testing.T) {
		for name, hc := range map[string]*http.Client{"the default client": nil, "a given client": {}} {
			var elsewhereHit bool
			elsewhere := serve(t, func(http.ResponseWriter, *http.Request) { elsewhereHit = true })
			var calls int
			addr := serve(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 1 {
					http.Redirect(w, r, elsewhere+c.path, http.StatusTemporaryRedirect)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			})
			prov, _ := c.build(ClientConfig{BaseURL: addr, APIKey: c.key, HTTPClient: hc})
			_, err := prov.Search(context.Background(), "q", 5)
			var se *StatusError
			if !errors.As(err, &se) || se.Status != http.StatusTemporaryRedirect || elsewhereHit || calls != 1 || strings.Contains(err.Error(), c.key) {
				t.Fatalf("%s: err %v, followed elsewhere %v, calls %d", name, err, elsewhereHit, calls)
			}
			// A redirect inside the same host is not followed either.
			calls = 0
			same := serve(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				http.Redirect(w, r, "/again", http.StatusFound)
			})
			prov, _ = c.build(ClientConfig{BaseURL: same, APIKey: c.key, HTTPClient: hc})
			if _, err := prov.Search(context.Background(), "q", 5); !errors.As(err, &se) || se.Status != http.StatusFound || calls != 1 {
				t.Fatalf("%s: same-host redirect: err %v, calls %d", name, err, calls)
			}
		}
	})

	t.Run("a search ends with its context", func(t *testing.T) {
		addr := serve(t, func(_ http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body) // the server notices a closed connection once the body is read
			<-r.Context().Done()
		})
		prov, _ := c.build(ClientConfig{BaseURL: addr, APIKey: c.key, HTTPClient: &http.Client{Timeout: 3 * time.Second}})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := prov.Search(ctx, "q", 5)
		if err == nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second || strings.Contains(err.Error(), c.key) {
			t.Fatalf("err %v after %v", err, time.Since(start))
		}
	})
}

// The providers a person may name for their own key: each is
// one POST with the key in its header and never in the URL or the body,
// asks for the plain results and none of the paid extras, and reads only
// its result list. The answers are the documented shapes, with
// the fields each client must ignore.
var personalProviders = []struct {
	name     string
	build    func(ClientConfig) (Provider, error)
	header   string // the header the key rides in
	prefix   string // what precedes the key in it
	count    string // the body's field for the number of results
	path     string
	endpoint string         // the provider's own address, without a query
	want     map[string]any // the request body, for a count of 3
	answer   string
	result   []Result
}{
	{
		name:   TavilyName,
		build:  func(c ClientConfig) (Provider, error) { return NewTavily(c) },
		header: "Authorization", prefix: "Bearer ", count: "max_results", path: "/search",
		endpoint: "https://api.tavily.com/search",
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
		endpoint: "https://api.exa.ai/search",
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
		endpoint: "https://api.perplexity.ai/search",
		want:     map[string]any{"query": "RFC 4180 CSV", "max_results": 3.0, "search_type": "web", "max_tokens_per_page": 256.0},
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
			var rawBody []byte
			var calls int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				got = r.Clone(context.Background())
				raw, _ := io.ReadAll(r.Body)
				rawBody = raw
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
			if got.Header.Get("Accept") != "application/json" {
				t.Fatalf("Accept = %q", got.Header.Get("Accept"))
			}
			if strings.Contains(got.URL.String(), key) {
				t.Fatal("the key rode in the URL")
			}
			assertKeyOnlyIn(t, key, p.header, got, rawBody)
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
			for asked, want := range map[int]float64{-1: DefaultCount, 0: DefaultCount, 1: 1, 10: 10, 11: MaxCount} {
				sent = nil
				if _, err := prov.Search(context.Background(), "q", asked); err != nil {
					t.Fatal(err)
				}
				if n, _ := sent[p.count].(float64); n != want {
					t.Fatalf("asked %d: sent %v, want %v", asked, sent[p.count], want)
				}
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
			if !errors.As(err, &se) || se.Status != http.StatusUnauthorized || se.Provider != p.name || strings.Contains(err.Error(), "provider-se") ||
				strings.Contains(err.Error(), key[:10]) {
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

			checkClientControls(t, controls{
				name: p.name, key: key, header: p.header, prefix: p.prefix, build: p.build, path: p.path, endpoint: p.endpoint,
				answer: `{"results":[]}`, head: `{"results":[],"pad":"`, tail: `"}`,
			})
		})
	}
}
