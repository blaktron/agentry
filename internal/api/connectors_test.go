package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/pkg/connector"
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
	for i, c := range got.Connectors {
		ids = append(ids, c.ID+"="+c.Strategy)
		if c.PublicClientID != nil {
			t.Errorf("%s carries a public client id with none configured", c.ID)
		}
		// Each connector is the catalogue's own, vendor and name included.
		if all := connector.Builtin().All(); i >= len(all) || c.Vendor != all[i].Vendor || c.Name != all[i].Name || c.Vendor == "" || c.Name == "" {
			t.Errorf("%s: vendor %q and name %q are not the catalogue's", c.ID, c.Vendor, c.Name)
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
	// Ids configured for connectors whose apps are confidential, or for no
	// connector at all, are not served.
	const confidentialID, unknownID = "7a1b2c3d-0000-4000-8000-00000000c0de", "7a1b2c3d-0000-4000-8000-00000000f00d"
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Connectors.PublicClients = map[string]string{
			"microsoft-365": id, "github": confidentialID, "asana": confidentialID, "no-such-connector": unknownID,
		}
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
	for _, other := range []string{confidentialID, unknownID} {
		if strings.Contains(string(body), other) {
			t.Fatalf("an id configured for a connector with no public client is served: %s", body)
		}
	}
	var got connectorList
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	for _, c := range got.Connectors {
		if want := c.ID == "microsoft-365"; (c.PublicClientID != nil) != want || (want && *c.PublicClientID != id) {
			t.Errorf("%s: public client id %v", c.ID, c.PublicClientID)
		}
	}
	for _, word := range []string{"secret", "issuer", "grant", "servers"} {
		if strings.Contains(strings.ToLower(string(body)), word) {
			t.Errorf("the answer holds %q: %s", word, body)
		}
	}
}

// Every strategy the catalogue uses is one the API's answer can carry.
func TestEveryCatalogueStrategyIsInTheAPI(t *testing.T) {
	for _, c := range connector.Builtin().All() {
		if !api.ConnectorInfoStrategy(c.Strategy).Valid() {
			t.Errorf("%s: strategy %q is not in the API's enum", c.ID, c.Strategy)
		}
	}
}
