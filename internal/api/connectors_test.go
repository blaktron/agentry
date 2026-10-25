package api_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

type connectorList struct {
	Connectors []struct {
		ID             string  `json:"id"`
		Vendor         string  `json:"vendor"`
		Name           string  `json:"name"`
		Strategy       string  `json:"strategy"`
		PublicClientID *string `json:"publicClientId"`
	} `json:"connectors"`
}

// /connectors lists every connector of the catalogue to anyone, with no
// public client id where the deployment configures none.
func TestConnectorsListsTheCatalogue(t *testing.T) {
	env := newTestEnvCfg(t, func(*config.Config) {})
	var got connectorList
	env.doJSON(anonymous, http.MethodGet, "/api/v1/connectors", nil, &got, http.StatusOK)
	var ids []string
	for _, c := range got.Connectors {
		ids = append(ids, c.ID+"="+c.Strategy)
		if c.PublicClientID != nil {
			t.Errorf("%s carries a public client id with none configured", c.ID)
		}
	}
	if strings.Join(ids, ",") != "github=agentry-confidential,asana=agentry-confidential,microsoft-365=agentry-public" {
		t.Fatalf("connectors: %v", ids)
	}
}

// A configured public client id is served for its connector and nowhere
// else, and the answer holds nothing but the listed fields.
func TestConnectorsServeTheConfiguredPublicClientID(t *testing.T) {
	const id = "0f6d5e1a-2b3c-4d5e-8f90-123456789abc"
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Connectors.PublicClients = map[string]string{"microsoft-365": id}
	})
	resp := env.do(anonymous, http.MethodGet, "/api/v1/connectors", nil)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if strings.Count(string(body), id) != 1 {
		t.Fatalf("the id is not served exactly once: %s", body)
	}
	for _, word := range []string{"secret", "issuer", "grant", "servers"} {
		if strings.Contains(strings.ToLower(string(body)), word) {
			t.Errorf("the answer holds %q: %s", word, body)
		}
	}
}
