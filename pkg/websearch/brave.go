package websearch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Brave's LLM Context API (agentry#631): the provider the operator chose on
// 2026-09-26 for dev and production, in place of You.com (DEV-156's choice,
// whose account never opened). It is a search whose results are page chunks
// extracted for a model to read, in Brave's plain Search plan. Brave's
// published terms require a plan with storage rights to store results "in
// part or whole"; the route stores none, and what a draft keeps of a source
// is its address (the register entry says so).
//
// The call is GET /res/v1/llm/context with the key in X-Subscription-Token.
// Only grounding.generic is read, each result's snippets joined into its
// snippet; local results (grounding.poi, grounding.map, never asked for:
// enable_local is off) and the sources metadata map are ignored. The token
// budget is kept small: every result is scanned before a model reads it,
// and Clean cuts a snippet to a thousand characters anyway.
const (
	BraveName           = "brave"
	BraveDefaultBaseURL = "https://api.search.brave.com"
	bravePath           = "/res/v1/llm/context"
	braveMaxResponse    = 4 << 20
	braveTokenBudget    = 2048
	braveSnippetJoin    = " … "
)

// Brave is the Brave LLM Context API client. It is safe for concurrent use.
type Brave struct {
	endpoint string
	apiKey   string
	http     *http.Client
}

// BraveConfig builds a Brave client.
type BraveConfig struct {
	// BaseURL is the API root; empty is BraveDefaultBaseURL.
	BaseURL string
	// APIKey is required, never logged, and redacted from every error.
	APIKey string
	// HTTPClient carries the requests; nil is a client with a 20-second
	// timeout.
	HTTPClient *http.Client
}

// NewBrave builds the client, refusing a missing key.
func NewBrave(cfg BraveConfig) (*Brave, error) {
	key := strings.TrimSpace(cfg.APIKey)
	if key == "" {
		return nil, ErrNoKey
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = BraveDefaultBaseURL
	}
	hc := &http.Client{Timeout: 20 * time.Second}
	if cfg.HTTPClient != nil {
		copied := *cfg.HTTPClient
		hc = &copied
	}
	// A redirect is never followed: Go carries a custom header such as
	// X-Subscription-Token across a redirect to another host, so following
	// one could hand the key there. A 3xx is then a non-200 answer.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Brave{endpoint: base + bravePath, apiKey: key, http: hc}, nil
}

// Name implements Provider.
func (*Brave) Name() string { return BraveName }

// Search implements Provider.
func (b *Brave) Search(ctx context.Context, query string, count int) ([]Result, error) {
	n := strconv.Itoa(ClampCount(count))
	q := url.Values{
		"q":                        {query},
		"count":                    {n},
		"maximum_number_of_urls":   {n},
		"maximum_number_of_tokens": {strconv.Itoa(braveTokenBudget)},
		"enable_local":             {"false"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("websearch: brave request: %w", redactKey(err, b.apiKey))
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", b.apiKey)
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("websearch: brave request: %w", redactKey(err, b.apiKey))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, braveMaxResponse))
	if err != nil {
		return nil, fmt.Errorf("websearch: brave response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(BraveName, resp.StatusCode, raw, b.apiKey)
	}
	var body struct {
		Grounding struct {
			Generic []struct {
				URL      string   `json:"url"`
				Title    string   `json:"title"`
				Snippets []string `json:"snippets"`
			} `json:"generic"`
		} `json:"grounding"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("websearch: brave response is not the result shape: %w", err)
	}
	out := make([]Result, 0, len(body.Grounding.Generic))
	for _, g := range body.Grounding.Generic {
		out = append(out, Result{Title: g.Title, URL: g.URL, Snippet: strings.Join(g.Snippets, braveSnippetJoin)})
	}
	return out, nil
}
