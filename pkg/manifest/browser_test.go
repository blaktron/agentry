package manifest

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// The browser (V15): capabilities.browser names url questions as the
// sites the person gives at run time, fixed hosts, a scope and the
// declared secrets the browser may type. These tests pin V15, that the
// line is part of the contract (canonical JSON, the capability diff),
// that a browser that types secrets cannot take public scope, and the
// schema.

// browserManifest is v2YAML with a url question and a browser line.
func browserManifest(t *testing.T) *Manifest {
	t.Helper()
	y := strings.Replace(v2YAML, "\ninteractive:", `  - id: site
    prompt: "Which site should I test?"
    type: url
    required: true

interactive:`, 1)
	y = strings.Replace(y, "  secrets: [PAGERDUTY_TOKEN]\n", `  secrets: [PAGERDUTY_TOKEN, SITE_PASSWORD]
  browser:
    sites: [site]
    hosts: [fonts.googleapis.com, "*.stripe.com"]
    secrets: [SITE_PASSWORD]
`, 1)
	return mustParse(t, y)
}

// browserIssues are Validate's blocking issues.
func browserIssues(errs []error) []*Issue {
	var out []*Issue
	for _, err := range errs {
		if is, ok := AsIssue(err); ok && is.Severity == SeverityError {
			out = append(out, is)
		}
	}
	return out
}

func TestABrowserParsesAndValidates(t *testing.T) {
	m := browserManifest(t)
	b := m.Capabilities.Browser
	if b == nil || !slices.Equal(b.Sites, []string{"site"}) || !slices.Equal(b.Hosts, []string{"fonts.googleapis.com", "*.stripe.com"}) ||
		!slices.Equal(b.Secrets, []string{"SITE_PASSWORD"}) {
		t.Fatalf("browser = %+v", b)
	}
	if b.IsPublic() || b.Scope != "" {
		t.Fatalf("an unset scope reads %q, public %v; want site", b.Scope, b.IsPublic())
	}
	if is := browserIssues(Validate(m)); len(is) != 0 {
		t.Fatalf("a declared browser is refused: %v", is)
	}
	if is := publishIssues(t, m); len(is) != 0 {
		t.Fatalf("a declared browser is refused at publish: %v", is)
	}

	m.Capabilities.Browser = &Browser{Scope: BrowserScopePublic}
	if is := browserIssues(Validate(m)); len(is) != 0 {
		t.Fatalf("a public-web browser with no site is refused: %v", is)
	}
	if !m.Capabilities.Browser.IsPublic() {
		t.Fatal("scope: public is not public")
	}
}

// TestV15RefusesWhatTheLineCannotMean: each case is one way the line goes
// wrong, and V15 (or V5's name grammar) says where.
func TestV15RefusesWhatTheLineCannotMean(t *testing.T) {
	urlQ := func(id string) IntakeQuestion { return IntakeQuestion{ID: id, Prompt: "The site", Type: IntakeURL} }
	site := []IntakeQuestion{urlQ("site")}
	for _, c := range []struct {
		name    string
		intake  []IntakeQuestion
		browser Browser
		secrets []string
		rule    string
		path    string
		says    string
	}{
		{"an empty line", site, Browser{}, nil,
			"V15", "capabilities.browser", "goes nowhere"},
		{"a site with no question", nil, Browser{Sites: []string{"site"}}, nil,
			"V15", "capabilities.browser.sites[0]", "names no intake question of type url"},
		{"a site naming a text question", []IntakeQuestion{{ID: "site", Prompt: "p"}}, Browser{Sites: []string{"site"}}, nil,
			"V15", "capabilities.browser.sites[0]", "names no intake question of type url"},
		{"a site naming a repository question", []IntakeQuestion{{ID: "site", Prompt: "p", Type: IntakeRepository}}, Browser{Sites: []string{"site"}}, nil,
			"V15", "capabilities.browser.sites[0]", "names no intake question of type url"},
		{"a duplicate site", site, Browser{Sites: []string{"site", "site"}}, nil,
			"V15", "capabilities.browser.sites[1]", "duplicate site"},
		{"five sites", []IntakeQuestion{urlQ("a"), urlQ("b"), urlQ("c"), urlQ("d"), urlQ("e")}, Browser{Sites: []string{"a", "b", "c", "d", "e"}}, nil,
			"V15", "capabilities.browser.sites", "the maximum is 4"},
		{"a wildcard host", site, Browser{Sites: []string{"site"}, Hosts: []string{"*"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "set scope: public"},
		{"an address", site, Browser{Hosts: []string{"192.168.1.10"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "not a DNS host name"},
		{"a port", site, Browser{Hosts: []string{"example.com:8443"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "not a DNS host name"},
		{"a URL", site, Browser{Hosts: []string{"https://example.com"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "not a DNS host name"},
		{"a top-level suffix", site, Browser{Hosts: []string{"*.com"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "not a DNS host name"},
		{"a mid-name star", site, Browser{Hosts: []string{"cdn.*.example.com"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "not a DNS host name"},
		{"a hex address", site, Browser{Hosts: []string{"0x7f.0.0.1"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "not a DNS host name"},
		{"a number for a last label", site, Browser{Hosts: []string{"cdn.example.123"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "not a DNS host name"},
		{"a single-label name", site, Browser{Hosts: []string{"localhost"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "not a DNS host name"},
		{"a public suffix", site, Browser{Hosts: []string{"*.co.uk"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "covers a public suffix"},
		{"a hosting provider's suffix", site, Browser{Hosts: []string{"*.GitHub.io"}}, nil,
			"V15", "capabilities.browser.hosts[0]", "covers a public suffix"},
		{"a scope in another case", site, Browser{Sites: []string{"site"}, Scope: "Public"}, nil,
			"V15", "capabilities.browser.scope", "is not site or public"},
		{"a duplicate host in another case", site, Browser{Hosts: []string{"cdn.example.com", "CDN.example.com"}}, nil,
			"V15", "capabilities.browser.hosts[1]", "duplicate host"},
		{"an unknown scope", site, Browser{Sites: []string{"site"}, Scope: "anywhere"}, nil,
			"V15", "capabilities.browser.scope", "is not site or public"},
		{"an undeclared secret", site, Browser{Sites: []string{"site"}, Secrets: []string{"SITE_PASSWORD"}}, nil,
			"V15", "capabilities.browser.secrets[0]", "is not declared"},
		{"a duplicate secret", site, Browser{Sites: []string{"site"}, Secrets: []string{"SITE_PASSWORD", "SITE_PASSWORD"}}, []string{"SITE_PASSWORD"},
			"V15", "capabilities.browser.secrets[1]", "duplicate browser secret"},
		{"a secret that is not a name", site, Browser{Sites: []string{"site"}, Secrets: []string{"SITE PASSWORD"}}, nil,
			"V5", "capabilities.browser.secrets[0]", ""},
		{"secrets with public scope", site, Browser{Sites: []string{"site"}, Scope: BrowserScopePublic, Secrets: []string{"SITE_PASSWORD"}}, []string{"SITE_PASSWORD"},
			"V15", "capabilities.browser.secrets", "cannot have scope: public"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := validV2Manifest(t)
			m.Intake = c.intake
			b := c.browser
			m.Capabilities.Browser = &b
			m.Capabilities.Secrets = append(m.Capabilities.Secrets, c.secrets...)
			errs := Validate(m)
			wantIssue(t, errs, c.rule, SeverityError, c.path)
			for _, err := range errs {
				if is, _ := AsIssue(err); is.Rule == c.rule && is.Path == c.path && strings.Contains(is.Message, c.says) {
					return
				}
			}
			t.Fatalf("no %s issue at %s saying %q:%s", c.rule, c.path, c.says, issueStrings(errs))
		})
	}
}

// TestV15TakesWhatTheLineMeans: the shapes the browser line allows,
// each valid.
func TestV15TakesWhatTheLineMeans(t *testing.T) {
	urlQ := func(id string) IntakeQuestion { return IntakeQuestion{ID: id, Prompt: "The site", Type: IntakeURL} }
	for _, c := range []struct {
		name     string
		intake   []IntakeQuestion
		browser  Browser
		secrets  []string
		optional []string
	}{
		{"one site", []IntakeQuestion{urlQ("site")}, Browser{Sites: []string{"site"}}, nil, nil},
		{"four sites", []IntakeQuestion{urlQ("a"), urlQ("b"), urlQ("c"), urlQ("d")}, Browser{Sites: []string{"a", "b", "c", "d"}}, nil, nil},
		{"hosts alone", nil, Browser{Hosts: []string{"status.example.com", "*.example.net"}}, nil, nil},
		{"a suffix under a public suffix", nil, Browser{Hosts: []string{"*.example.co.uk", "*.myproject.github.io", "github.io"}}, nil, nil},
		{"site scope written out", []IntakeQuestion{urlQ("site")}, Browser{Sites: []string{"site"}, Scope: BrowserScopeSite}, nil, nil},
		{"public with a site", []IntakeQuestion{urlQ("site")}, Browser{Sites: []string{"site"}, Scope: BrowserScopePublic}, nil, nil},
		{"an optional secret", []IntakeQuestion{urlQ("site")}, Browser{Sites: []string{"site"}, Secrets: []string{"SITE_USER"}}, []string{"SITE_USER"}, []string{"SITE_USER"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := validV2Manifest(t)
			m.Intake = c.intake
			b := c.browser
			m.Capabilities.Browser = &b
			m.Capabilities.Secrets = append(m.Capabilities.Secrets, c.secrets...)
			m.Capabilities.OptionalSecrets = c.optional
			if is := browserIssues(Validate(m)); len(is) != 0 {
				t.Fatalf("refused: %v", is)
			}
		})
	}
}

func TestBrowserIsAV2Field(t *testing.T) {
	m := validV2Manifest(t)
	m.SchemaVersion = "1"
	m.Capabilities.Browser = &Browser{Scope: BrowserScopePublic}
	wantIssue(t, Validate(m), "V1", SeverityError, "capabilities.browser")
}

// TestBrowserIsInTheContract: the canonical JSON the registry stores
// carries the line, so consent, search (capability=browser) and the
// judge's declared capabilities all read it.
func TestBrowserIsInTheContract(t *testing.T) {
	m := browserManifest(t)
	if got := m.Contract().Browser; got == nil || !slices.Equal(got.Sites, []string{"site"}) {
		t.Fatalf("Contract().Browser = %+v", got)
	}
	raw, err := CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Capabilities struct {
			Browser map[string]json.RawMessage `json:"browser"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"sites", "hosts", "secrets"} {
		if _, ok := doc.Capabilities.Browser[k]; !ok {
			t.Fatalf("canonical capabilities.browser has no %s in %s", k, raw)
		}
	}
	if _, ok := doc.Capabilities.Browser["scope"]; ok {
		t.Fatalf("an unset scope is written: %s", raw)
	}
	var back Manifest
	if err := json.Unmarshal(raw, &back); err != nil || back.Capabilities.Browser == nil ||
		!slices.Equal(back.Capabilities.Browser.Hosts, []string{"fonts.googleapis.com", "*.stripe.com"}) {
		t.Fatalf("the canonical form does not read back: %v %+v", err, back.Capabilities.Browser)
	}
}

// TestDiffCapabilitiesBrowser pins that a new line, a new site, a new
// host, a new secret the browser may type, or site to public widens;
// the reverse narrows; the same line is no change.
func TestDiffCapabilitiesBrowser(t *testing.T) {
	site := &Browser{Sites: []string{"site"}, Hosts: []string{"cdn.example.com"}}
	for _, c := range []struct {
		name              string
		old, next         *Browser
		widened, narrowed []string
	}{
		{"a new line", nil, site,
			[]string{"adds a web browser (the site you name for site; cdn.example.com)"}, nil},
		{"a new public line", nil, &Browser{Scope: BrowserScopePublic},
			[]string{"adds a web browser (any public site)"}, nil},
		{"a new line with a secret", nil, &Browser{Sites: []string{"site"}, Secrets: []string{"SITE_PASSWORD"}},
			[]string{"adds a web browser (the site you name for site)", "lets the browser type the secret SITE_PASSWORD into the site"}, nil},
		{"the line dropped", site, nil, nil, []string{"drops the web browser"}},
		{"the same line", site, &Browser{Sites: []string{"site"}, Hosts: []string{"CDN.example.com"}, Scope: BrowserScopeSite}, nil, nil},
		{"a second site", site, &Browser{Sites: []string{"site", "staging"}, Hosts: []string{"cdn.example.com"}},
			[]string{"asks for a site for the browser when it runs: staging"}, nil},
		{"a host swapped", site, &Browser{Sites: []string{"site"}, Hosts: []string{"*.example.com"}},
			[]string{"lets the browser reach *.example.com"}, []string{"no longer lets the browser reach cdn.example.com"}},
		{"a secret added", site, &Browser{Sites: []string{"site"}, Hosts: []string{"cdn.example.com"}, Secrets: []string{"SITE_USER"}},
			[]string{"lets the browser type the secret SITE_USER into the site"}, nil},
		{"a secret dropped", &Browser{Sites: []string{"site"}, Secrets: []string{"SITE_USER"}}, &Browser{Sites: []string{"site"}},
			nil, []string{"no longer lets the browser type the secret SITE_USER"}},
		{"site to public", site, &Browser{Sites: []string{"site"}, Hosts: []string{"cdn.example.com"}, Scope: BrowserScopePublic},
			[]string{"lets the browser reach ANY public site (was: the named sites and hosts)"}, nil},
		{"public to site with a new host", &Browser{Scope: BrowserScopePublic}, &Browser{Hosts: []string{"cdn.example.com"}},
			nil, []string{"keeps the browser to the named sites and hosts (was: any public site)"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := DiffCapabilities(Capabilities{Browser: c.old}, Capabilities{Browser: c.next})
			if !slices.Equal(d.Widened, c.widened) || !slices.Equal(d.Narrowed, c.narrowed) {
				t.Fatalf("widened %q narrowed %q; want %q and %q", d.Widened, d.Narrowed, c.widened, c.narrowed)
			}
			if d.HasWidened() != (len(c.widened) > 0) {
				t.Fatalf("HasWidened = %v", d.HasWidened())
			}
		})
	}
}

// TestV2SchemaBrowserShape pins the JSON schema beside the Go rule.
func TestV2SchemaBrowserShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	type list struct {
		Type        string `json:"type"`
		UniqueItems bool   `json:"uniqueItems"`
		MaxItems    int    `json:"maxItems"`
		Items       struct {
			Pattern string `json:"pattern"`
		} `json:"items"`
	}
	var schema struct {
		Properties struct {
			Capabilities struct {
				Properties struct {
					Browser struct {
						AdditionalProperties *bool `json:"additionalProperties"`
						Properties           struct {
							Sites   list `json:"sites"`
							Hosts   list `json:"hosts"`
							Secrets list `json:"secrets"`
							Scope   struct {
								Enum []string `json:"enum"`
							} `json:"scope"`
						} `json:"properties"`
					} `json:"browser"`
				} `json:"properties"`
			} `json:"capabilities"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	b := schema.Properties.Capabilities.Properties.Browser
	if b.AdditionalProperties == nil || *b.AdditionalProperties {
		t.Fatal("capabilities.browser is not closed")
	}
	p := b.Properties
	if p.Sites.MaxItems != MaxBrowserSites || p.Sites.Items.Pattern != intakeIDRE.String() || !p.Sites.UniqueItems {
		t.Fatalf("sites = %+v", p.Sites)
	}
	if p.Hosts.MaxItems != MaxBrowserHosts || !p.Hosts.UniqueItems || p.Hosts.Items.Pattern == "" {
		t.Fatalf("hosts = %+v", p.Hosts)
	}
	if !slices.Equal(p.Scope.Enum, []string{string(BrowserScopeSite), string(BrowserScopePublic)}) {
		t.Fatalf("scope = %v", p.Scope.Enum)
	}
	if p.Secrets.Items.Pattern != envNameRE.String() {
		t.Fatalf("secrets = %+v; want the env-name grammar %s", p.Secrets, envNameRE)
	}
}
