package connector

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

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
	if !ok || !ms.HasPublicClient() || len(ms.Servers) != 2 || ms.Issuer != "https://login.microsoftonline.com/common/v2.0" ||
		ms.AdminStep == nil || ms.AdminStep.Kind != AdminStepEntraConsent {
		t.Fatalf("microsoft-365: %+v", ms)
	}
	if _, ok := Builtin().Lookup("nobody"); ok {
		t.Fatal("an unknown id was found")
	}
}

// The catalogue carries no client id and no secret of any kind: those are
// the deployment's configuration.
func TestTheCatalogueHoldsNoCredential(t *testing.T) {
	all := Builtin().All()
	// A package's oauth environment names where the access token goes and
	// holds nothing but placeholders; it is checked as such, then left out
	// of the word search below.
	for _, c := range all {
		for _, srv := range c.Servers {
			if srv.Package == nil {
				continue
			}
			for name, v := range srv.Package.OAuth.Env {
				if got, err := manifest.ExpandOAuthEnvValue(v, map[string]string{"access_token": "", "dir": ""}); err != nil || got != "" {
					t.Errorf("%s: %s's value %q is not placeholders alone", c.ID, name, v)
				}
			}
			srv.Package.OAuth.Env = nil
		}
	}
	b, err := json.Marshal(all)
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
		"https://api.githubcopilot.com/mcp/../admin":     false,
		"https://api.githubcopilot.com/mcp/%2e%2e/admin": false,
		"https://api.githubcopilot.com/mcp/./readonly":   false,
		"https://api.githubcopilot.com/mcp/%2E/readonly": false,
		"https://api.githubc\u043epilot.com/mcp":         false,
		"https://api.githubcopilot.com:443/mcp":          false,
	} {
		got, ok := c.Match(remote(u), ghIssuer)
		if ok != want || (ok && got.ID != "github") {
			t.Errorf("%s at GitHub's issuer: matched %v (%q), want %v", u, ok, got.ID, want)
		}
	}
	if got, ok := c.Match(remote("https://mcp.asana.com/v2/mcp"), asIssuer+"/"); !ok || got.ID != "asana" {
		t.Error("Asana's V2 server did not match")
	}
	for _, v1 := range []string{"https://mcp.asana.com/sse", "https://mcp.asana.com/v2/../sse", "https://mcp.asana.com/v2/%2e%2e/sse", "https://mcp.a\u017fana.com/v2"} {
		if _, ok := c.Match(remote(v1), asIssuer); ok {
			t.Errorf("%s matched Asana's V2 entry", v1)
		}
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
	looked, _ := c.Lookup("example-mail")
	matched, _ := c.Match(vettedPackage(), "https://login.example.com")
	listed := c.All()[0]
	for _, got := range []Connector{looked, matched, listed} {
		got.Servers[0].Package.Version = "9.9.9"
		got.Servers[0].Package.OAuth.Scopes[0] = "everything"
		got.Servers[0].Package.OAuth.Env["MAIL_TOKEN"] = "elsewhere"
		got.Servers = nil
	}
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
		"an unknown admin step":          head + "    issuer: https://login.microsoftonline.com/common/v2.0\n    adminStep: {kind: email-the-admin, refusals: [AADSTS90094]}\n",
		"an admin step with no refusal":  head + "    issuer: https://login.microsoftonline.com/common/v2.0\n    adminStep: {kind: entra-admin-consent, refusals: []}\n",
		"a refusal that is not a code":   head + "    issuer: https://login.microsoftonline.com/common/v2.0\n    adminStep: {kind: entra-admin-consent, refusals: [\"AADSTS 1\"]}\n",
		"Entra's step elsewhere":         head + "    issuer: https://x.example\n    adminStep: {kind: entra-admin-consent, refusals: [AADSTS90094]}\n",
		"Entra's step, no public client": strings.Replace(head, "agentry-public", "agentry-confidential", 1) + "    issuer: https://login.microsoftonline.com/common/v2.0\n    adminStep: {kind: entra-admin-consent, refusals: [AADSTS90094]}\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Microsoft 365's two tiers vet Softeria's server at the listed version
// with the very block listed, at Entra's common authority, and nothing
// that differs from it by a version, a scope, the environment or the
// issuer.
func TestMicrosoft365VetsSofteriasServerAsListed(t *testing.T) {
	c := Builtin()
	ms, _ := c.Lookup("microsoft-365")
	const issuer = "https://login.microsoftonline.com/common/v2.0"
	for i, srv := range ms.Servers {
		p := srv.Package
		if p == nil || p.Ecosystem != EcosystemNPM || p.Name != "@softeria/ms-365-mcp-server" || p.Version != "0.184.0" {
			t.Fatalf("server %d: %+v", i, srv)
		}
		declared := func(mut func(*manifest.MCPServer)) manifest.MCPServer {
			o := p.OAuth
			o.Scopes = append([]string(nil), o.Scopes...)
			o.Env = map[string]string{}
			for k, v := range p.OAuth.Env {
				o.Env[k] = v
			}
			s := manifest.MCPServer{NPM: p.Name, Version: p.Version, OAuth: &o}
			if mut != nil {
				mut(&s)
			}
			return s
		}
		if got, ok := c.Match(declared(nil), issuer); !ok || got.ID != "microsoft-365" {
			t.Fatalf("tier %d as listed is not vetted", i)
		}
		for name, mut := range map[string]func(*manifest.MCPServer){
			"another version": func(s *manifest.MCPServer) { s.Version = "0.184.1" },
			"another scope": func(s *manifest.MCPServer) {
				s.OAuth.Scopes = append(s.OAuth.Scopes, "https://graph.microsoft.com/Mail.Send.Shared")
			},
			"a scope dropped":   func(s *manifest.MCPServer) { s.OAuth.Scopes = s.OAuth.Scopes[1:] },
			"another env entry": func(s *manifest.MCPServer) { s.OAuth.Env["MS365_MCP_EXTRA"] = "{access_token}" },
			"a token file": func(s *manifest.MCPServer) {
				s.OAuth.Files = []manifest.MCPOAuthFile{{Path: "t", Template: "{access_token}"}}
			},
			"another package":    func(s *manifest.MCPServer) { s.NPM = "@softeria/ms-365-mcp-server-fork" },
			"the same on pypi":   func(s *manifest.MCPServer) { s.PyPI, s.NPM = s.NPM, "" },
			"a tenant authority": func(s *manifest.MCPServer) { s.OAuth.Issuer = "https://login.microsoftonline.com/organizations/v2.0" },
		} {
			srv := declared(mut)
			if _, ok := c.Match(srv, srv.OAuth.Issuer); ok {
				t.Errorf("tier %d, %s: vetted", i, name)
			}
		}
	}
}

// A release can declare each vetted block as it is listed: the manifest's
// own rules accept it on Softeria's server.
func TestMicrosoft365BlocksAreValidInARelease(t *testing.T) {
	ms, _ := Builtin().Lookup("microsoft-365")
	for i, srv := range ms.Servers {
		block, err := yaml.Marshal(srv.Package.OAuth)
		if err != nil {
			t.Fatal(err)
		}
		doc := "schemaVersion: \"2\"\nname: mail-triage\nnamespace: acme\nmodes: [autonomous]\nversion: 1.0.0\nsummary: \"Triages a Microsoft 365 inbox\"\nlicense: MIT\n" +
			"capabilities:\n  mcpServers:\n    - npm: \"" + srv.Package.Name + "\"\n      version: " + srv.Package.Version + "\n      egress: [graph.microsoft.com]\n      args: [--read-only]\n      oauth:\n" +
			indent(string(block), "        ") + "publish:\n  include: [agent.yaml, AGENT.md]\n"
		m, err := manifest.Parse([]byte(doc))
		if err != nil {
			t.Fatalf("tier %d: %v\n%s", i, err, doc)
		}
		if errs := manifest.Validate(m); len(errs) > 0 {
			t.Fatalf("tier %d: %v\n%s", i, errs, doc)
		}
	}
}

func indent(s, pad string) string {
	var b strings.Builder
	for _, l := range strings.SplitAfter(s, "\n") {
		if l != "" {
			b.WriteString(pad + l)
		}
	}
	return b.String()
}

// The admin step answers a refusal by its code, or by an Entra code its
// description carries as a whole word, and nothing else; a connector
// without one answers none.
func TestTheAdminStepAnswersItsRefusalsAlone(t *testing.T) {
	ms, _ := Builtin().Lookup("microsoft-365")
	for _, tc := range []struct {
		code, desc string
		want       bool
	}{
		{"invalid_request", "AADSTS90094: The grant requires admin permission.", true},
		{"access_denied", "AADSTS65001: The user or administrator has not consented to use the application.", true},
		{"consent_required", "", true},
		{"access_denied", "The user declined.", false},
		{"access_denied", "AADSTS900941: something else", false},
		{"access_denied", "XAADSTS90094 joined", false},
		{"invalid_request", "AADSTS9009", false},
		{"server_error", "consent_required_later", false},
	} {
		if got := ms.NeedsAdmin(tc.code, tc.desc); got != tc.want {
			t.Errorf("NeedsAdmin(%q, %q) = %v", tc.code, tc.desc, got)
		}
	}
	gh, _ := Builtin().Lookup("github")
	if gh.NeedsAdmin("consent_required", "AADSTS90094") {
		t.Error("a connector without an admin step answered a refusal")
	}
}

// The admin-consent link is on Entra's host, at the organizations
// authority, for the public client and the Graph permissions alone, and
// refuses a client id or a scope it cannot vouch for.
func TestEntraAdminConsentURL(t *testing.T) {
	const id = "0f6d5e1a-2b3c-4d5e-8f90-123456789abc"
	ms, _ := Builtin().Lookup("microsoft-365")
	got, err := EntraAdminConsentURL(id, ms.Servers[0].Package.OAuth.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil || u.Scheme != "https" || u.Host != "login.microsoftonline.com" || u.Path != "/organizations/v2.0/adminconsent" {
		t.Fatalf("the link: %s", got)
	}
	q := u.Query()
	if q.Get("client_id") != id || len(q) != 3 || q.Get("redirect_uri") != "http://localhost/callback" ||
		q.Get("scope") != "https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Calendars.Read https://graph.microsoft.com/Contacts.Read https://graph.microsoft.com/Files.Read https://graph.microsoft.com/MailboxSettings.Read" {
		t.Fatalf("the query: %v", q)
	}
	if got, err := EntraAdminConsentURL(id, []string{"Mail.Read", "openid"}); err != nil || !strings.Contains(got, "scope=https%3A%2F%2Fgraph.microsoft.com%2FMail.Read") || strings.Contains(got, "openid") {
		t.Fatalf("a bare permission: %s %v", got, err)
	}
	for name, tc := range map[string]struct {
		id     string
		scopes []string
	}{
		"a client id that is not an Entra id": {"not-an-id&redirect_uri=https://evil.example", []string{"Mail.Read"}},
		"another API's scope":                 {id, []string{"https://evil.example/Mail.Read"}},
		"a scope with a query":                {id, []string{"Mail.Read&prompt=none"}},
		"no Graph permission":                 {id, []string{"offline_access", "openid"}},
	} {
		if got, err := EntraAdminConsentURL(tc.id, tc.scopes); err == nil {
			t.Errorf("%s: %s", name, got)
		}
	}
}
