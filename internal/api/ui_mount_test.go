package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/httpmux"
)

// The /ui/ surface is dispatched in front of the mux, not registered on it:
// registered, "/ui/" and git's "GET /{ns}/{repo}/info/refs" are a ServeMux
// conflict and the process panics at start-up (the gitsrv conformance test
// covers it). Both must route with git mounted.
func TestUIMountsBesideGitPatterns(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	srv := api.New(cfg, nil, nil)
	gitHits := 0
	// Registered behind api.Mount's back, on purpose: the recorder still sees
	// the patterns, which is what makes an undeclared mount fail the
	// completeness gate rather than only a missing declaration panic here.
	h := api.NewHandlerWithGit(srv, func(mux httpmux.Mux) {
		mux.HandleFunc("GET /{ns}/{repo}/info/refs", func(w http.ResponseWriter, _ *http.Request) { gitHits++; w.WriteHeader(http.StatusOK) })
		mux.HandleFunc("POST /{ns}/{repo}/git-upload-pack", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		mux.HandleFunc("POST /{ns}/{repo}/git-receive-pack", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	})
	ts := httptest.NewServer(h)
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	res, err := client.Get(ts.URL + "/acme/tool.git/info/refs")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || gitHits != 1 {
		t.Fatalf("git route: %d hits=%d", res.StatusCode, gitHits)
	}
	res, err = client.Get(ts.URL + "/ui/login")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(b), "Sign in") {
		t.Fatalf("ui route: %d %s", res.StatusCode, b)
	}
	res, err = client.Get(ts.URL + "/ui/x/info/refs")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if gitHits != 1 {
		t.Fatalf("/ui/x/info/refs reached git (hits=%d)", gitHits)
	}
}
