package connector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/manifest"
)

const (
	ghIssuer = "https://github.com/login/oauth"
	asIssuer = "https://app.asana.com"
)

func remote(u string) manifest.MCPServer {
	return manifest.MCPServer{URL: u, Auth: manifest.AuthOAuth}
}

func TestTheBuiltinCatalogueListsItsConnectors(t *testing.T) {
	var ids []string
	for _, c := range Builtin().All() {
		ids = append(ids, c.ID)
	}
	if strings.Join(ids, ",") != "github,asana,microsoft-365" {
		t.Fatalf("connectors: %v", ids)
	}
	gh, _ := Builtin().Lookup("github")
	if gh.Strategy != StrategyAgentryConfidential || gh.HasPublicClient() || gh.GrantURL != "https://api.github.com/applications/{client_id}/grant" {
		t.Fatalf("github: %+v", gh)
	}
	ms, ok := Builtin().Lookup("microsoft-365")
	if !ok || !ms.HasPublicClient() || len(ms.Servers) != 0 {
		t.Fatalf("microsoft-365: %+v", ms)
	}
	if _, ok := Builtin().Lookup("nobody"); ok {
		t.Fatal("an unknown id was found")
	}
}

// The catalogue carries no client id and no secret of any kind: those are
// the deployment's configuration.
func TestTheCatalogueHoldsNoCredential(t *testing.T) {
	b, err := json.Marshal(Builtin().All())
	if err != nil {
		t.Fatal(err)
	}
	for _, word := range []string{"secret", "clientId", "client_id\"", "token"} {
		if strings.Contains(string(b), word) {
			t.Errorf("the catalogue's JSON holds %q: %s", word, b)
		}
	}
}

// GitHub's and Asana's apps go to their vendor's own server and the
// addresses under it, and to nothing else: not a look-alike host or path,
// not plain http, not another vendor's issuer, not a package naming the
// vendor's issuer.
func TestGitHubAndAsanaGoOnlyToTheirOwnServers(t *testing.T) {
	c := Builtin()
	for u, want := range map[string]bool{
		"https://api.githubcopilot.com/mcp":              true,
		"https://api.githubcopilot.com/mcp/":             true,
		"https://api.githubcopilot.com/mcp/readonly":     true,
		"https://api.githubcopilot.com/mcp/x/repos":      true,
		"https://API.githubcopilot.com/mcp":              true,
		"https://api.githubcopilot.com/mcpx":             false,
		"https://api.githubcopilot.com.evil.example/mcp": false,
		"https://evil.example/mcp":                       false,
		"http://api.githubcopilot.com/mcp":               false,
		"https://user@api.githubcopilot.com/mcp":         false,
	} {
		got, ok := c.Match(remote(u), ghIssuer)
		if ok != want || (ok && got.ID != "github") {
			t.Errorf("%s at GitHub's issuer: matched %v (%q), want %v", u, ok, got.ID, want)
		}
	}
	if got, ok := c.Match(remote("https://mcp.asana.com/v2/mcp"), asIssuer+"/"); !ok || got.ID != "asana" {
		t.Error("Asana's V2 server did not match")
	}
	if _, ok := c.Match(remote("https://mcp.asana.com/sse"), asIssuer); ok {
		t.Error("Asana's V1 address matched")
	}
	if _, ok := c.Match(remote("https://api.githubcopilot.com/mcp/"), asIssuer); ok {
		t.Error("GitHub's server matched at Asana's issuer")
	}
	if _, ok := c.Match(remote("https://api.githubcopilot.com/mcp/"), ""); ok {
		t.Error("a server matched with no issuer")
	}
	pkg := manifest.MCPServer{NPM: "@modelcontextprotocol/server-github", Version: "1.0.0", OAuth: &manifest.MCPOAuth{Issuer: ghIssuer}}
	if _, ok := c.Match(pkg, ghIssuer); ok {
		t.Error("a package server naming GitHub's issuer got GitHub's app")
	}
}

const testCatalogue = `
connectors:
  - id: example-mail
    vendor: Example
    name: Example Mail
    strategy: agentry-public
    issuer: https://login.example.com
    servers:
      - package:
          ecosystem: npm
          name: "@example/mail-mcp"
          version: 1.4.2
          oauth:
            issuer: https://login.example.com/
            scopes: [mail.read, offline_access]
            env:
              MAIL_TOKEN: "{{access_token}}"
`

func vettedPackage() manifest.MCPServer {
	return manifest.MCPServer{NPM: "@example/mail-mcp", Version: "1.4.2", OAuth: &manifest.MCPOAuth{
		Issuer: "https://login.example.com", Scopes: []string{"mail.read", "offline_access"},
		Env: map[string]string{"MAIL_TOKEN": "{{access_token}}"},
	}}
}

// A listed package matches only as listed: the same ecosystem, name, exact
// version and oauth block. A release that names the same issuer with
// another package, another version or any change to the block gets no
// Agentry app.
func TestAPackageMatchesOnlyAsListed(t *testing.T) {
	c, err := Parse([]byte(testCatalogue))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := c.Match(vettedPackage(), "https://login.example.com"); !ok || got.ID != "example-mail" {
		t.Fatalf("the listed package did not match: %v %+v", ok, got)
	}
	for name, change := range map[string]func(*manifest.MCPServer){
		"another package":       func(s *manifest.MCPServer) { s.NPM = "@example/mail-mcp-fork" },
		"another version":       func(s *manifest.MCPServer) { s.Version = "1.4.3" },
		"pypi of the same name": func(s *manifest.MCPServer) { s.PyPI, s.NPM = s.NPM, "" },
		"another issuer":        func(s *manifest.MCPServer) { s.OAuth.Issuer = "https://login.example.org" },
		"a scope added":         func(s *manifest.MCPServer) { s.OAuth.Scopes = append(s.OAuth.Scopes, "mail.send") },
		"a scope dropped":       func(s *manifest.MCPServer) { s.OAuth.Scopes = s.OAuth.Scopes[:1] },
		"the token elsewhere":   func(s *manifest.MCPServer) { s.OAuth.Env = map[string]string{"OTHER": "{{access_token}}"} },
		"a token file added": func(s *manifest.MCPServer) {
			s.OAuth.Files = []manifest.MCPOAuthFile{{Path: "t", Template: "{{access_token}}"}}
		},
		"no oauth block":  func(s *manifest.MCPServer) { s.OAuth = nil },
		"made remote too": func(s *manifest.MCPServer) { s.URL = "https://login.example.com/mcp" },
	} {
		s := vettedPackage()
		change(&s)
		issuer := "https://login.example.com"
		if s.OAuth != nil {
			issuer = s.OAuth.Issuer
		}
		if _, ok := c.Match(s, issuer); ok {
			t.Errorf("%s: matched", name)
		}
	}
}

// What a caller gets back is a copy: changing it changes nothing in the
// catalogue.
func TestTheCatalogueCannotBeChangedThroughWhatItReturns(t *testing.T) {
	c, err := Parse([]byte(testCatalogue))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := c.Lookup("example-mail")
	got.Servers[0].Package.Version = "9.9.9"
	got.Servers[0].Package.OAuth.Scopes[0] = "everything"
	if _, ok := c.Match(vettedPackage(), "https://login.example.com"); !ok {
		t.Fatal("a change to a returned connector reached the catalogue")
	}
}

func TestParseRefusesAMalformedCatalogue(t *testing.T) {
	head := "connectors:\n  - id: x\n    vendor: V\n    name: N\n    strategy: agentry-public\n"
	for name, doc := range map[string]string{
		"an unknown field":               head + "    secret: s\n",
		"a bad id":                       strings.Replace(head, "id: x", "id: Bad_Id", 1),
		"an unknown strategy":            strings.Replace(head, "agentry-public", "magic", 1),
		"servers, no issuer":             head + "    servers:\n      - remote: https://x.example/mcp\n",
		"a plain http address":           head + "    issuer: https://x.example\n    servers:\n      - remote: http://x.example/mcp\n",
		"an address with a query":        head + "    issuer: https://x.example\n    servers:\n      - remote: https://x.example/mcp?a=b\n",
		"remote and package":             head + "    issuer: https://x.example\n    servers:\n      - remote: https://x.example/mcp\n        package: {ecosystem: npm, name: p, version: 1.0.0, oauth: {issuer: https://x.example}}\n",
		"no version":                     head + "    issuer: https://x.example\n    servers:\n      - package: {ecosystem: npm, name: p, oauth: {issuer: https://x.example}}\n",
		"another ecosystem":              head + "    issuer: https://x.example\n    servers:\n      - package: {ecosystem: cargo, name: p, version: 1.0.0, oauth: {issuer: https://x.example}}\n",
		"another issuer in the block":    head + "    issuer: https://x.example\n    servers:\n      - package: {ecosystem: npm, name: p, version: 1.0.0, oauth: {issuer: https://y.example}}\n",
		"a grant address without the id": head + "    grantURL: https://x.example/grant\n",
		"listed twice":                   head + strings.TrimPrefix(head, "connectors:\n"),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
