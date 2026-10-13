package manifest

import (
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// The browser (plan browser-testing.md §5, D1, D6, D9, D12, D13;
// agentry#1134). A release that tests websites declares
// capabilities.browser, and its runs get a headless Chromium driven through
// the runner's browser tools, whose only route out is a per-run browse
// proxy that holds the line's scope. The line names where the browser may
// go, never an address the person owns: the site is the answer to a url
// intake question, given when the run starts, and the release may add
// fixed hosts its pages pull from (a CDN, a font host, a sign-in
// provider), each an exact name or a "*." suffix. scope: public lets the
// browser reach any public site instead, which the publication policy
// treats as it treats "*" egress (D1, D12).
//
// A test can sign in (D9): secrets names declared secrets the browser may
// type into the site's forms, by name, the server substituting the value.
// Such a release cannot take public scope, so the only pages that can
// receive a secret are the run-time site, its subdomains and the declared
// hosts (invariant 9).
//
// The line is inside the contract, as a target host is: consent shows it,
// an upgrade that widens it asks again, AI Review sees it among the
// declared capabilities (RunnerGrants says nothing of it: benched, DEV-247),
// and search can filter on it. It is not
// network egress: the tools container's fetch still follows
// network.egress, and a script the release ships that reaches a host
// itself is still the release's own network (S6).

// Browser is capabilities.browser (v2, V15).
type Browser struct {
	// Sites names url intake questions: the person's answer to each is a
	// site the browser may open, with its subdomains.
	Sites []string `yaml:"sites,omitempty" json:"sites,omitempty"`
	// Hosts are fixed hosts the browser may also reach, each an exact DNS
	// name or a "*." suffix (D13); no address, no port.
	Hosts []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	// Scope is BrowserScopeSite (the default when empty) or
	// BrowserScopePublic.
	Scope BrowserScope `yaml:"scope,omitempty" json:"scope,omitempty"`
	// Secrets names declared secrets the browser may type into the site's
	// forms (D9); each is also in capabilities.secrets or optionalSecrets.
	Secrets []string `yaml:"secrets,omitempty" json:"secrets,omitempty"`
}

// BrowserScope says how far the browser may go.
type BrowserScope string

// Browser scopes (D1).
const (
	// BrowserScopeSite admits the run-time sites, their subdomains and the
	// declared hosts. It is the default.
	BrowserScopeSite BrowserScope = "site"
	// BrowserScopePublic admits any public site, on ports 80 and 443; a
	// runner allows it only under its operator's policy, and publication
	// treats it as "*" egress.
	BrowserScopePublic BrowserScope = "public"
)

// MaxBrowserSites bounds the run-time sites one release may name (plan §5).
const MaxBrowserSites = 4

// MaxBrowserHosts bounds the fixed hosts one browser line may add. The
// plan names no bound; 32 is room for a site's CDNs, font hosts and sign-in
// providers, and keeps the consent list readable.
const MaxBrowserHosts = 32

// IsPublic reports whether the browser may reach any public site.
func (b *Browser) IsPublic() bool {
	return b != nil && b.Scope == BrowserScopePublic
}

// validBrowserHost reports whether h is a browser host: a DNS name of two
// labels or more, or "*." followed by one. No address (a name whose last
// label is a number, which a browser reads as IPv4, such as 0x7f.1), no
// single-label name (localhost), no port.
func validBrowserHost(h string) bool {
	name, _ := strings.CutPrefix(h, "*.")
	return validDNSHost(name) && strings.Contains(name, ".") && !endsInNumber(name)
}

// endsInNumber is the URL standard's test for a host the browser parses
// as IPv4: its last label is decimal digits, or 0x and hex digits.
func endsInNumber(name string) bool {
	labels := strings.Split(strings.ToLower(name), ".")
	last := labels[len(labels)-1]
	if hex, ok := strings.CutPrefix(last, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return strings.Trim(last, "0123456789") == ""
}

// isPublicSuffixWildcard reports a "*." host whose name is itself a public
// suffix (*.co.uk, *.github.io): it would admit every site registered under
// it, as wide as public scope while the gate sees only site scope.
func isPublicSuffixWildcard(h string) bool {
	name, ok := strings.CutPrefix(strings.ToLower(h), "*.")
	if !ok {
		return false
	}
	ps, _ := publicsuffix.PublicSuffix(name)
	return ps == name
}

// validateBrowser is V15: the browser line names url questions, at most
// MaxBrowserSites, each once; its hosts are DNS names or "*." suffixes; its
// scope is site or public; it says where the browser may go; and each
// secret it may type is declared, never with public scope (D9).
func validateBrowser(s *issues, m *Manifest) {
	b := m.Capabilities.Browser
	if b == nil {
		return
	}
	if m.Major() != 2 {
		s.errf("V1", "capabilities.browser", "browser is a v2 field; set schemaVersion: 2")
		return
	}
	switch b.Scope {
	case "", BrowserScopeSite, BrowserScopePublic:
	default:
		s.errf("V15", "capabilities.browser.scope", "scope %q is not site or public", b.Scope)
	}
	if len(b.Sites) == 0 && len(b.Hosts) == 0 && !b.IsPublic() {
		s.errf("V15", "capabilities.browser", "the browser goes nowhere: name a url question in sites, a host in hosts, or set scope: public")
	}

	if len(b.Sites) > MaxBrowserSites {
		s.errf("V15", "capabilities.browser.sites", "%d sites; the maximum is %d", len(b.Sites), MaxBrowserSites)
	}
	urlQ := map[string]bool{}
	for _, q := range m.Intake {
		if q.Type == IntakeURL {
			urlQ[q.ID] = true
		}
	}
	seen := map[string]bool{}
	for i, id := range b.Sites {
		p := fmt.Sprintf("capabilities.browser.sites[%d]", i)
		switch {
		case seen[id]:
			s.errf("V15", p, "duplicate site %q", id)
		case !urlQ[id]:
			s.errf("V15", p, "%q names no intake question of type url: a site is the person's answer to one", id)
		}
		seen[id] = true
	}

	if len(b.Hosts) > MaxBrowserHosts {
		s.errf("V15", "capabilities.browser.hosts", "%d hosts; the maximum is %d", len(b.Hosts), MaxBrowserHosts)
	}
	seen = map[string]bool{}
	for i, h := range b.Hosts {
		p := fmt.Sprintf("capabilities.browser.hosts[%d]", i)
		key := strings.ToLower(h)
		switch {
		case h == "*":
			s.errf("V15", p, "\"*\" is not a host: set scope: public for any public site")
		case !validBrowserHost(h):
			s.errf("V15", p, "%q is not a DNS host name or a \"*.\" suffix of one (no address, no single-label name, no port)", h)
		case isPublicSuffixWildcard(h):
			s.errf("V15", p, "%q covers a public suffix, every site registered under it: name the site's own domain, or set scope: public", h)
		case seen[key]:
			s.errf("V15", p, "duplicate host %q", h)
		}
		seen[key] = true
	}

	if len(b.Secrets) == 0 {
		return
	}
	if b.IsPublic() {
		s.errf("V15", "capabilities.browser.secrets", "a browser that types secrets cannot have scope: public: a secret is typed only on the person's site and the declared hosts")
	}
	c := m.Capabilities
	seen = map[string]bool{}
	for i, name := range b.Secrets {
		p := fmt.Sprintf("capabilities.browser.secrets[%d]", i)
		if !checkEnvName(s, p, name) {
			continue
		}
		switch {
		case seen[name]:
			s.errf("V15", p, "duplicate browser secret %q", name)
		case !slices.Contains(c.Secrets, name) && !slices.Contains(c.OptionalSecrets, name):
			s.errf("V15", p, "%q is not declared in capabilities.secrets or optionalSecrets: the browser types only a secret the release asks for", name)
		}
		seen[name] = true
	}
}
