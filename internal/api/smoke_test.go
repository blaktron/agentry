package api_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/PLACEHOLDER_ORG/agentry/internal/api"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/pkg/apiclient"
)

// TestM0Smoke exercises the M0 acceptance path: the generated Go client
// talking to the assembled handler (spec-first contract round-trip).
func TestM0Smoke(t *testing.T) {
	cfg := config.Default()
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
}

// TestHealthEndpoints covers the non-spec endpoints the LB and deploys use.
func TestHealthEndpoints(t *testing.T) {
	cfg := config.Default()
	srv := httptest.NewServer(api.NewHandler(api.New(cfg, nil, nil)))
	defer srv.Close()

	res, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", err, res)
	}
	// Without a database the server is alive but not ready.
	res, err = srv.Client().Get(srv.URL + "/readyz")
	if err != nil || res.StatusCode != 503 {
		t.Fatalf("readyz without db should be 503: %v %v", err, res)
	}
	res, err = srv.Client().Get(srv.URL + "/.well-known/agentry/registry.json")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("well-known: %v %v", err, res)
	}
}
