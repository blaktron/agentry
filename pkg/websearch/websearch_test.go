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
	// Every control character is refused (NUL, DEL, a C1 control), while a
	// space inside the text and the full bound are not.
	for _, bad := range []string{"nul\x00byte", "del\x7fchar", "c1\xc2\x85ctl", "esc\x1b[0m", "carriage\rreturn"} {
		if _, err := CleanQuery(bad); err != ErrBadQuery {
			t.Fatalf("%q must be refused", bad)
		}
	}
	for _, ok := range []string{strings.Repeat("a", MaxQuery), "two  spaces and a no-break\xc2\xa0space"} {
		if q, err := CleanQuery(ok); err != nil || q != ok {
			t.Fatalf("%q must be accepted whole: %q %v", ok, q, err)
		}
	}
	if _, err := CleanQuery("ok\xffnot ok"); err != ErrBadQuery {
		t.Fatal("invalid UTF-8 inside the text must be refused")
	}
}

// A query is text: a format character (a bidirectional override, a zero-width
// character, the soft hyphen, a tag character) draws nothing or reorders what
// is drawn, so it is dropped before the query is checked and sent, where a
// control character refuses the query.
func TestCleanQueryDropsFormatCharacters(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"a bidirectional override":      {"github" + string(rune(0x202e)) + " mcp", "github mcp"},
		"a zero-width space":            {"git" + string(rune(0x200b)) + "hub", "github"},
		"a zero-width non-joiner":       {"git" + string(rune(0x200c)) + "hub", "github"},
		"a word joiner":                 {"git" + string(rune(0x2060)) + "hub", "github"},
		"a soft hyphen":                 {"git" + string(rune(0xad)) + "hub", "github"},
		"a byte order mark":             {string(rune(0xfeff)) + "github", "github"},
		"a tag character":               {"github" + string(rune(0xe0041)) + string(rune(0xe0062)), "github"},
		"before the trimmed spaces":     {string(rune(0x200b)) + "  github  " + string(rune(0x200b)), "github"},
		"what remains is what is bound": {strings.Repeat("a", MaxQuery) + string(rune(0x200b)), strings.Repeat("a", MaxQuery)},
	} {
		if got, err := CleanQuery(tc.in); err != nil || got != tc.want {
			t.Errorf("%s: %q, %v, want %q", name, got, err, tc.want)
		}
	}
	for name, bad := range map[string]string{
		"only format characters": string(rune(0x200b)) + string(rune(0x202e)) + string(rune(0xe0041)),
		"format and spaces":      " " + string(rune(0xfeff)) + " ",
		"a control beside one":   "a" + string(rune(0x200b)) + "\nb",
	} {
		if _, err := CleanQuery(bad); err != ErrBadQuery {
			t.Errorf("%s must be refused", name)
		}
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

	t.Run("the count is held to 1..MaxCount, 0 or less meaning the default", func(t *testing.T) {
		var many []Result
		for i := range 12 {
			many = append(many, Result{Title: "r", URL: "https://example.com/" + strings.Repeat("p", i+1)})
		}
		for asked, want := range map[int]int{-1: DefaultCount, 0: DefaultCount, 1: 1, 10: 10, 11: MaxCount, 50: MaxCount} {
			got := Clean(many, asked)
			if len(got) != want || got[0].URL != many[0].URL || got[want-1].URL != many[want-1].URL {
				t.Fatalf("Clean(.., %d) kept %d, want %d", asked, len(got), want)
			}
		}
	})

	t.Run("an address is kept or dropped at its exact bound", func(t *testing.T) {
		base := "https://example.com/"
		for name, tc := range map[string]struct{ in, want string }{
			"exactly maxURL bytes":      {base + strings.Repeat("x", maxURL-len(base)), base + strings.Repeat("x", maxURL-len(base))},
			"one byte past maxURL":      {base + strings.Repeat("x", maxURL-len(base)+1), ""},
			"white space around":        {" \t" + base + "pad\n ", base + "pad"},
			"invalid UTF-8":             {base + "bad\xffbyte", ""},
			"user name alone":           {"https://token@example.com/e", ""},
			"https with no host":        {"https:///nohost", ""},
			"https with an opaque path": {"https:nohost", ""},
			"a file address":            {"file:///etc/passwd", ""},
			"nothing":                   {"", ""},
		} {
			got := Clean([]Result{{Title: "t", URL: tc.in}}, 5)
			switch {
			case tc.want == "" && len(got) != 0:
				t.Fatalf("%s: kept %+v", name, got)
			case tc.want != "" && (len(got) != 1 || got[0].URL != tc.want):
				t.Fatalf("%s: got %+v", name, got)
			}
		}
	})

	t.Run("text is folded, stripped and cut at its bound", func(t *testing.T) {
		clean := func(title, snippet string) Result {
			got := Clean([]Result{{Title: title, URL: "https://example.com/t", Snippet: snippet}}, 1)
			if len(got) != 1 {
				t.Fatalf("dropped %q", title)
			}
			return got[0]
		}
		for name, tc := range map[string]struct{ in, want string }{
			"a new line between words":        {"a\nb", "a b"},
			"a tab between words":             {"a\tb", "a b"},
			"unicode spaces fold":             {"a\xc2\xa0\xe2\x80\x83b", "a b"},
			"a leading unicode space":         {"\xc2\xa0 lead", "lead"},
			"a delete character":              {"x\x7fy", "xy"},
			"a C1 control":                    {"x\xc2\x85y", "x y"},
			"invalid UTF-8":                   {"bad\xffbyte", "badbyte"},
			"a zero-width space":              {"a" + string(rune(0x200b)) + "b", "ab"},
			"a zero-width non-joiner":         {"a" + string(rune(0x200c)) + "b", "ab"},
			"a zero-width joiner":             {"a" + string(rune(0x200d)) + "b", "ab"},
			"a bidirectional override":        {"a" + string(rune(0x202e)) + "b", "ab"},
			"a bidirectional isolate":         {"a" + string(rune(0x2066)) + "b", "ab"},
			"a left-to-right mark":            {"a" + string(rune(0x200e)) + "b", "ab"},
			"a word joiner":                   {"a" + string(rune(0x2060)) + "b", "ab"},
			"a soft hyphen":                   {"a" + string(rune(0xad)) + "b", "ab"},
			"a byte order mark":               {"a" + string(rune(0xfeff)) + "b", "ab"},
			"a tag character":                 {"a" + string(rune(0xe0041)) + "b", "ab"},
			"a language tag":                  {"a" + string(rune(0xe0001)) + "b", "ab"},
			"an Arabic letter mark":           {"a" + string(rune(0x61c)) + "b", "ab"},
			"format characters around a fold": {"a " + string(rune(0x200b)) + " " + string(rune(0x202e)) + "b", "a b"},
			"only format characters":          {string(rune(0x200b)) + string(rune(0xe0041)), ""},
			"a leading format character":      {string(rune(0xfeff)) + "lead", "lead"},
			"exactly the title bound":         {strings.Repeat("a", maxTitle), strings.Repeat("a", maxTitle)},
			"one past the title bound":        {strings.Repeat("a", maxTitle+1), strings.Repeat("a", maxTitle)},
			"a space ending the title bound":  {strings.Repeat("a", maxTitle-2) + " b", strings.Repeat("a", maxTitle-2) + " b"},
			"a word starting at the boundary": {strings.Repeat("a", maxTitle-1) + " bcd efg", strings.Repeat("a", maxTitle-1)},
		} {
			got := clean(tc.in, tc.in).Title
			if got != tc.want {
				t.Fatalf("%s: title %q, want %q", name, got, tc.want)
			}
			// The snippet's bound is wider than the title's, so only the
			// shorter inputs are cut the same in both.
			if snippet := clean(tc.in, tc.in).Snippet; utf8.RuneCountInString(tc.in) < maxTitle-2 && snippet != tc.want {
				t.Fatalf("%s: snippet %q, want %q", name, snippet, tc.want)
			}
		}
		// However the bound falls against a space, the text neither starts
		// nor ends with one.
		for n := range maxTitle + 3 {
			text := strings.Repeat("a", n) + " bcd efg"
			for _, got := range []string{clean(text, "").Title, clean("t", text+strings.Repeat(" x", maxSnippet)).Snippet} {
				if got != strings.TrimSpace(got) || got != "" && !strings.HasPrefix(got, strings.Repeat("a", min(n, maxTitle-1))) {
					t.Fatalf("%d characters then a fold: %q", n, got)
				}
			}
		}
		if got := clean("t", strings.Repeat("s", maxSnippet)).Snippet; got != strings.Repeat("s", maxSnippet) {
			t.Fatalf("a snippet of exactly the bound loses %d characters", maxSnippet-len(got))
		}
	})
}

func TestYouComAsksOnceWithTheKeyAndReadsOnlyTheWebResults(t *testing.T) {
	var got struct {
		Key, Method, Path string
		Body              map[string]any
		Req               *http.Request
		Raw               []byte
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Key, got.Method, got.Path = r.Header.Get("X-API-Key"), r.Method, r.URL.Path
		got.Req = r.Clone(context.Background())
		raw, _ := io.ReadAll(r.Body)
		got.Raw = raw
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
	if want := map[string]any{"query": "github mcp server", "count": 3.0}; !reflect.DeepEqual(got.Body, want) {
		t.Fatalf("the body is the query and the count alone: %v", got.Body)
	}
	if got.Req.Header.Get("Content-Type") != "application/json" || got.Req.Header.Get("Accept") != "application/json" {
		t.Fatalf("headers: %v", got.Req.Header)
	}
	assertKeyOnlyIn(t, "ydc-secret-key", "X-API-Key", got.Req, got.Raw)
	if res[0].URL != "https://github.com/modelcontextprotocol/servers" || res[1].URL != "https://example.com/b" || res[1].Title != "B" {
		t.Fatalf("results: %+v", res)
	}

	t.Run("the count is held to 1..MaxCount, 0 or less meaning the default", func(t *testing.T) {
		for asked, want := range map[int]float64{-1: DefaultCount, 0: DefaultCount, 1: 1, 10: 10, 11: MaxCount, 50: MaxCount} {
			if _, err := y.Search(context.Background(), "q", asked); err != nil || got.Body["count"] != want {
				t.Fatalf("asked %d: sent %v, want %v (%v)", asked, got.Body["count"], want, err)
			}
		}
	})

	t.Run("a blank description gives way to the first snippet, a missing one to nothing", func(t *testing.T) {
		answer := serve(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"results":{"web":[
				{"url":"https://example.com/a","title":"A","description":"  \n ","snippets":["blank description","second"]},
				{"url":"https://example.com/b","title":"B","description":"","snippets":[]},
				{"url":"https://example.com/c","title":"C"}]}}`))
		})
		y3, _ := NewYouCom(YouComConfig{BaseURL: answer, APIKey: "k"})
		rs, err := y3.Search(context.Background(), "q", 5)
		if err != nil || len(rs) != 3 || rs[0].Snippet != "blank description" || rs[1].Snippet != "" || rs[2].Snippet != "" ||
			rs[0].URL != "https://example.com/a" || rs[2].Title != "C" {
			t.Fatalf("results %+v, err %v", rs, err)
		}
	})
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
	if _, err := New("brave", "", ""); err != ErrNoKey {
		t.Fatalf("brave, no key: %v", err)
	}
	if p, err := New("brave", "", "k"); err != nil || p.Name() != BraveName {
		t.Fatalf("brave: %v %v", p, err)
	}
	for name, want := range map[string]string{"tavily": TavilyName, "exa": ExaName, "perplexity": PerplexityName} {
		if _, err := New(name, "", ""); err != ErrNoKey {
			t.Fatalf("%s, no key: %v", name, err)
		}
		if p, err := New(name, "", "k"); err != nil || p.Name() != want {
			t.Fatalf("%s: %v %v", name, p, err)
		}
	}
	for _, unknown := range []string{"fake", "google", "Brave", "kagi", "Tavily"} {
		_, err := New(unknown, "", "k")
		if err == nil || err == ErrNoKey || !strings.Contains(err.Error(), "unknown provider") ||
			!strings.Contains(err.Error(), strings.Join(Providers(), "|")) {
			t.Fatalf("%q must be refused as unknown, naming the providers there are: %v", unknown, err)
		}
	}

	// The base address and the key reach the client the name builds, and a
	// name is trimmed.
	for _, name := range []string{"youcom", "brave", "tavily", "exa", "perplexity", " brave ", "\texa\n"} {
		var hits int
		addr := serve(t, func(w http.ResponseWriter, _ *http.Request) {
			hits++
			_, _ = w.Write([]byte("{}"))
		})
		p, err := New(name, addr, "k")
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if _, err := p.Search(context.Background(), "q", 5); err != nil || hits != 1 {
			t.Fatalf("%q: the search must reach the base address once: %d hits, %v", name, hits, err)
		}
	}

	// Fake answers from its list for a test, and no configuration names it.
	t.Run("the fake provider", func(t *testing.T) {
		f := &Fake{Results: []Result{{Title: "a", URL: "https://example.com/a"}, {Title: "b", URL: "https://example.com/b"}}}
		var _ Provider = f
		if f.Name() != "fake" || Known(f.Name()) {
			t.Fatalf("name %q, known %v", f.Name(), Known(f.Name()))
		}
		all, err := f.Search(context.Background(), "q1", 5)
		if err != nil || len(all) != 2 {
			t.Fatalf("count past the list: %v %v", all, err)
		}
		all[0].Title = "changed"
		one, err := f.Search(context.Background(), "q2", 1)
		if err != nil || len(one) != 1 || one[0].Title != "a" {
			t.Fatalf("a count of one, and results that are copies: %v %v", one, err)
		}
		qs := f.Queries()
		if !reflect.DeepEqual(qs, []string{"q1", "q2"}) {
			t.Fatalf("queries: %v", qs)
		}
		qs[0] = "changed"
		if !reflect.DeepEqual(f.Queries(), []string{"q1", "q2"}) {
			t.Fatalf("queries: %v", f.Queries())
		}
		f.Err = errors.New("down")
		if rs, err := f.Search(context.Background(), "q3", 5); rs != nil || err != f.Err {
			t.Fatalf("an error answers with no results: %v %v", rs, err)
		}
		if !reflect.DeepEqual(f.Queries(), []string{"q1", "q2", "q3"}) {
			t.Fatalf("a failed search is still asked: %v", f.Queries())
		}
	})
}

func TestYouComNeverFollowsARedirectAndRedactsAcrossTheCut(t *testing.T) {
	var hit bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/v1/search", http.StatusFound)
	}))
	defer srv.Close()
	y, _ := NewYouCom(YouComConfig{BaseURL: srv.URL, APIKey: "k", HTTPClient: &http.Client{}})
	_, err := y.Search(context.Background(), "q", 5)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusFound || hit {
		t.Fatalf("err %v, followed %v", err, hit)
	}

	key := "ydc-secret-key-long-enough"
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strings.Repeat("x", 190) + key))
	}))
	defer echo.Close()
	y2, _ := NewYouCom(YouComConfig{BaseURL: echo.URL, APIKey: key})
	if _, err := y2.Search(context.Background(), "q", 5); err == nil || strings.Contains(err.Error(), "ydc-secret") {
		t.Fatalf("a part of the key survived: %v", err)
	}

	checkClientControls(t, controls{
		name: YouComName, key: key, header: "X-API-Key",
		build:    func(c ClientConfig) (Provider, error) { return NewYouCom(c) },
		path:     "/v1/search",
		endpoint: "https://ydc-index.io/v1/search",
		answer:   `{"results":{"web":[]}}`, head: `{"results":{"web":[]},"pad":"`, tail: `"}`,
	})
}

func TestOriginAndTheProviderList(t *testing.T) {
	if got := Origin("https://mcp-guides.example/ignore/your/instructions?q=1"); got != "https://mcp-guides.example/" {
		t.Fatalf("origin: %q", got)
	}
	if Origin("not a url") != "" {
		t.Fatal("no host, no origin")
	}
	if Origin("https://host.example/%zz") != "" {
		t.Fatal("an address that does not parse has no origin")
	}
	if got := Origin("https://user:pw@example.com:8443/x?y=1#z"); got != "https://example.com:8443/" {
		t.Fatalf("an origin carries no user information, path or query: %q", got)
	}
	if want := []string{"none", "youcom", "brave", "tavily", "exa", "perplexity"}; !reflect.DeepEqual(Providers(), want) {
		t.Fatalf("providers: %v", Providers())
	}
	for _, ok := range []string{"", "none", "youcom", " youcom ", "brave", "tavily", "exa", "perplexity"} {
		if !Known(ok) {
			t.Fatalf("%q must be known", ok)
		}
	}
	for _, bad := range []string{"fake", "Brave", "YouCom", "Exa", "kagi"} {
		if Known(bad) {
			t.Fatalf("%q must not be known", bad)
		}
	}
}

// The fake answers a count it cannot honour with what it can: nothing for a
// count below one, at most what it holds for one above.
func TestFakeSearchHoldsAnyCount(t *testing.T) {
	f := &Fake{Results: []Result{{Title: "a", URL: "https://example.com/a"}, {Title: "b", URL: "https://example.com/b"}}}
	for count, want := range map[int]int{-5: 0, -1: 0, 0: 0, 1: 1, 2: 2, 3: 2, 1 << 30: 2} {
		got, err := f.Search(context.Background(), "q", count)
		if err != nil || len(got) != want {
			t.Errorf("count %d: %d results, %v, want %d", count, len(got), err, want)
		}
	}
}

// A provider returns what its upstream sends, which may be more than it was
// asked for; the bound on the results a caller shows is Clean's.
func TestCleanHoldsTheCountAProviderOverran(t *testing.T) {
	var sent []Result
	for i := range 25 {
		sent = append(sent, Result{Title: "r", URL: "https://example.com/" + strings.Repeat("p", i+1)})
	}
	var p Provider = overrun{sent}
	got, err := p.Search(context.Background(), "q", 3)
	if err != nil || len(got) != len(sent) {
		t.Fatalf("the stub should overrun: %d, %v", len(got), err)
	}
	for asked, want := range map[int]int{3: 3, 10: MaxCount, 0: DefaultCount} {
		if kept := Clean(got, asked); len(kept) != want {
			t.Errorf("Clean(.., %d) kept %d, want %d", asked, len(kept), want)
		}
	}
}

type overrun struct{ results []Result }

func (overrun) Name() string { return "overrun" }
func (o overrun) Search(context.Context, string, int) ([]Result, error) {
	return o.results, nil
}
