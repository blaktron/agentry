package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/version"
	"github.com/blaktron/agentry/pkg/apiclient"
)

// TestSmoke exercises the basic path: the generated Go client
// talking to the assembled handler (spec-first contract round-trip).
func TestSmoke(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	srv := httptest.NewServer(api.NewHandler(api.New(cfg, nil, nil)))
	defer srv.Close()

	client, err := apiclient.NewClientWithResponses(srv.URL + "/api/v1")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	resp, err := client.GetMetaWithResponse(context.Background())
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if resp.StatusCode() != 200 || resp.JSON200 == nil {
		t.Fatalf("GetMeta status=%d body=%s", resp.StatusCode(), string(resp.Body))
	}
	if resp.JSON200.Version == "" || resp.JSON200.ApiVersion != "v1" {
		t.Fatalf("unexpected meta: %+v", resp.JSON200)
	}
	if _, ok := resp.JSON200.Features["signing"]; !ok {
		t.Fatalf("features missing signing flag: %+v", resp.JSON200.Features)
	}
	// A bare server, with no database, key, judge or Redis, has none of the
	// optional parts.
	for _, flag := range []string{"signing", "redis", "judge", "s3", "publicPublish2FA", "knowledge", "voice"} {
		if on, ok := resp.JSON200.Features[flag]; !ok || on {
			t.Fatalf("features[%s] = %v (present %v) on a bare server, want false", flag, on, ok)
		}
	}
}

// TestHealthEndpoints covers the non-spec endpoints the LB and deploys use.
func TestHealthEndpoints(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	srv := httptest.NewServer(api.NewHandler(api.New(cfg, nil, nil)))
	defer srv.Close()

	res, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", err, res)
	}
	if body := smokeBody(t, res); body != `{"status":"ok"}` || res.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("healthz answered %q as %q", body, res.Header.Get("Content-Type"))
	}
	// Without a database the server is alive but not ready.
	res, err = srv.Client().Get(srv.URL + "/readyz")
	if err != nil || res.StatusCode != 503 {
		t.Fatalf("readyz without db should be 503: %v %v", err, res)
	}
	if body := smokeBody(t, res); body != `{"deps":[{"name":"postgres","ok":false}],"ready":false}` {
		t.Fatalf("readyz without db answered %q", body)
	}
	res, err = srv.Client().Get(srv.URL + "/.well-known/agentry/registry.json")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("well-known: %v %v", err, res)
	}
	var known struct {
		API     string `json:"api"`
		Version string `json:"version"`
		Git     bool   `json:"git"`
	}
	if err := json.Unmarshal([]byte(smokeBody(t, res)), &known); err != nil || known.API != "/api/v1" || known.Version != version.Version || !known.Git {
		t.Fatalf("well-known document = %+v (%v), want the API root, this build's version and git", known, err)
	}
}

func smokeBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}
