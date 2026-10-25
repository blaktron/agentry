// Package connector is Agentry's catalogue of connectors: the vendors'
// MCP servers Agentry has vetted, each bound to the app Agentry registered
// with that vendor. A token minted under one of Agentry's apps must reach
// only a server Agentry has vetted, because the app is the deployment's
// identity at the vendor: a release whose server merely names the vendor's
// authorization server would otherwise receive a grant made in Agentry's
// name.
//
// Matching is implicit. A release names no connector: a declared server
// that is one of a connector's servers, signed in to at the connector's
// issuer, gets the connector's app, and every other server gets the
// person's own client, a client document or dynamic registration, never
// Agentry's app. A remote server matches a listed address when it has the
// same host over https, no user information, and the same path or a path
// under it. A package server matches a listed package only with the same
// ecosystem, name and exact version and the very same oauth block (issuer,
// scopes, files and environment), so a release that changes any of them
// is not vetted.
//
// The catalogue is embedded data (catalogue.yaml), released with the core.
// It holds no client id and no secret: the deployment configures those,
// and a connector's public client id is the only one the registry hands
// to a client.
package connector

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/pkg/manifest"
)

// Strategy is how a connector's app signs a person in.
type Strategy string

const (
	// StrategyAgentryConfidential is Agentry's web client, whose secret
	// stays with the deployment.
	StrategyAgentryConfidential Strategy = "agentry-confidential"
	// StrategyAgentryPublic is a public client id with no secret, which
	// the registry serves to clients from the deployment's configuration,
	// with Agentry's web client for hosted sign-ins.
	StrategyAgentryPublic Strategy = "agentry-public"
)

// Connector is one vendor product Agentry has vetted servers of.
type Connector struct {
	// ID names it in configuration and to clients: lowercase letters,
	// digits and hyphens.
	ID string `yaml:"id" json:"id"`
	// Vendor and Name are the company and the product, as people know
	// them.
	Vendor string `yaml:"vendor" json:"vendor"`
	Name   string `yaml:"name" json:"name"`
	// Strategy is how its app signs a person in.
	Strategy Strategy `yaml:"strategy" json:"strategy"`
	// Issuer is the vendor's authorization server, as its metadata names
	// itself; empty only for an entry that lists no servers yet.
	Issuer string `yaml:"issuer,omitempty" json:"issuer,omitempty"`
	// GrantURL, where set, is how the vendor revokes a grant when its
	// metadata offers no revocation endpoint, {client_id} replaced.
	GrantURL string `yaml:"grantURL,omitempty" json:"grantURL,omitempty"`
	// Servers are what it vets; none vets nothing.
	Servers []Server `yaml:"servers,omitempty" json:"servers,omitempty"`
}

// Server is one vetted server: a remote address, or a package.
type Server struct {
	// Remote is a vendor's https address: it and the addresses under it
	// match.
	Remote string `yaml:"remote,omitempty" json:"remote,omitempty"`
	// Package is one package at one version with one oauth block.
	Package *Package `yaml:"package,omitempty" json:"package,omitempty"`
}

// Ecosystem is the package registry a package server is installed from.
type Ecosystem string

const (
	EcosystemNPM  Ecosystem = "npm"
	EcosystemPyPI Ecosystem = "pypi"
)

// Package is a vetted package server.
type Package struct {
	Ecosystem Ecosystem `yaml:"ecosystem" json:"ecosystem"`
	Name      string    `yaml:"name" json:"name"`
	// Version is exact: a newer version is not vetted until it is listed.
	Version string `yaml:"version" json:"version"`
	// OAuth is the whole oauth block a release must declare.
	OAuth manifest.MCPOAuth `yaml:"oauth" json:"oauth"`
}

// HasPublicClient reports whether a deployment may configure a public
// client id for the connector, which the registry then serves.
func (c Connector) HasPublicClient() bool { return c.Strategy == StrategyAgentryPublic }

// Vets reports whether server is one of the connector's servers.
func (c Connector) Vets(server manifest.MCPServer) bool {
	for _, s := range c.Servers {
		switch {
		case s.Remote != "" && server.IsRemote() && underAddress(server.URL, s.Remote):
			return true
		case s.Package != nil && !server.IsRemote() && s.Package.is(server):
			return true
		}
	}
	return false
}

// underAddress reports whether addr is base or an address under it: https,
// the same host (ASCII letters compared without case, any other character
// refused), no user information, no "." or ".." path segment (encoded or
// not, since a server that resolves them would serve an address outside
// base), and the same path or one below it.
func underAddress(addr, base string) bool {
	u, err := url.Parse(addr)
	b, berr := url.Parse(base)
	if err != nil || berr != nil || u.Scheme != "https" || !sameASCIIHost(u.Host, b.Host) || u.User != nil || hasDotSegment(u.Path) {
		return false
	}
	p, want := strings.TrimRight(u.Path, "/"), strings.TrimRight(b.Path, "/")
	return p == want || strings.HasPrefix(p, want+"/")
}

// sameASCIIHost compares two hosts letter by letter, ignoring the case of
// ASCII letters alone, so no Unicode case folding can make another name
// equal to a listed one.
func sameASCIIHost(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 0x80 || y >= 0x80 {
			return false
		}
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// hasDotSegment reports whether a decoded path holds a "." or ".." segment.
func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// is reports whether server is this package, at this version, with this
// oauth block.
func (p Package) is(server manifest.MCPServer) bool {
	if server.URL != "" || server.Version != p.Version || server.OAuth == nil {
		return false
	}
	switch p.Ecosystem {
	case EcosystemNPM:
		if server.NPM != p.Name || server.PyPI != "" {
			return false
		}
	case EcosystemPyPI:
		if server.PyPI != p.Name || server.NPM != "" {
			return false
		}
	default:
		return false
	}
	return sameOAuth(*server.OAuth, p.OAuth)
}

// sameOAuth compares two oauth blocks field by field; an absent list or
// map equals an empty one.
func sameOAuth(a, b manifest.MCPOAuth) bool {
	return trimIssuer(a.Issuer) == trimIssuer(b.Issuer) &&
		slices.Equal(a.Scopes, b.Scopes) &&
		slices.Equal(a.Files, b.Files) &&
		maps.Equal(a.Env, b.Env)
}

func trimIssuer(s string) string { return strings.TrimRight(s, "/") }

// Catalogue is a validated list of connectors.
type Catalogue struct{ entries []Connector }

//go:embed catalogue.yaml
var builtinData []byte

var builtin = func() Catalogue {
	c, err := Parse(builtinData)
	if err != nil {
		panic("connector: the embedded catalogue: " + err.Error())
	}
	return c
}()

// Builtin is the catalogue released with this build.
func Builtin() Catalogue { return builtin }

// All is every connector, in the catalogue's order.
func (c Catalogue) All() []Connector {
	out := make([]Connector, len(c.entries))
	for i, e := range c.entries {
		out[i] = e.clone()
	}
	return out
}

// Lookup is the connector with this id.
func (c Catalogue) Lookup(id string) (Connector, bool) {
	for _, e := range c.entries {
		if e.ID == id {
			return e.clone(), true
		}
	}
	return Connector{}, false
}

// Match is the connector whose app a sign-in to server at issuer uses: one
// whose issuer it is and whose servers include server. ok is false for
// every other server, which then gets no Agentry app.
func (c Catalogue) Match(server manifest.MCPServer, issuer string) (Connector, bool) {
	issuer = trimIssuer(issuer)
	if issuer == "" {
		return Connector{}, false
	}
	for _, e := range c.entries {
		if e.Issuer == issuer && e.Vets(server) {
			return e.clone(), true
		}
	}
	return Connector{}, false
}

func (c Connector) clone() Connector {
	c.Servers = slices.Clone(c.Servers)
	for i, s := range c.Servers {
		if s.Package != nil {
			p := *s.Package
			p.OAuth.Scopes = slices.Clone(p.OAuth.Scopes)
			p.OAuth.Files = slices.Clone(p.OAuth.Files)
			p.OAuth.Env = maps.Clone(p.OAuth.Env)
			c.Servers[i].Package = &p
		}
	}
	return c
}

var idRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Parse reads and validates a catalogue: unknown fields, a repeated or
// malformed id, an unknown strategy, a server that is neither or both a
// remote address and a package, an address that is not plain https, a
// package without an exact version or whose oauth block names another
// issuer, and servers without an issuer are refused.
func Parse(data []byte) (Catalogue, error) {
	var doc struct {
		Connectors []Connector `yaml:"connectors"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return Catalogue{}, fmt.Errorf("connector catalogue: %w", err)
	}
	seen := map[string]bool{}
	for i := range doc.Connectors {
		e := &doc.Connectors[i]
		e.Issuer = trimIssuer(e.Issuer)
		if err := e.validate(); err != nil {
			return Catalogue{}, fmt.Errorf("connector catalogue: %q: %w", e.ID, err)
		}
		if seen[e.ID] {
			return Catalogue{}, fmt.Errorf("connector catalogue: %q is listed twice", e.ID)
		}
		seen[e.ID] = true
	}
	return Catalogue{entries: doc.Connectors}, nil
}

func (c Connector) validate() error {
	switch {
	case !idRE.MatchString(c.ID):
		return errors.New("an id is lowercase letters, digits and single hyphens")
	case c.Vendor == "" || c.Name == "":
		return errors.New("a vendor and a name are required")
	case c.Strategy != StrategyAgentryConfidential && c.Strategy != StrategyAgentryPublic:
		return fmt.Errorf("unknown strategy %q", c.Strategy)
	case len(c.Servers) > 0 && c.Issuer == "":
		return errors.New("an entry with servers needs its issuer")
	case c.Issuer != "" && !plainHTTPS(c.Issuer):
		return errors.New("the issuer is not a plain https address")
	case c.GrantURL != "" && (!strings.Contains(c.GrantURL, "{client_id}") || !plainHTTPS(strings.ReplaceAll(c.GrantURL, "{client_id}", "x"))):
		return errors.New("a grant address is https and holds {client_id}")
	}
	for _, s := range c.Servers {
		switch {
		case (s.Remote == "") == (s.Package == nil):
			return errors.New("a server is either a remote address or a package")
		case s.Remote != "" && !plainHTTPS(s.Remote):
			return fmt.Errorf("the address %q is not a plain https address", s.Remote)
		case s.Package != nil && s.Package.Ecosystem != EcosystemNPM && s.Package.Ecosystem != EcosystemPyPI:
			return fmt.Errorf("unknown ecosystem %q", s.Package.Ecosystem)
		case s.Package != nil && (s.Package.Name == "" || s.Package.Version == ""):
			return errors.New("a package needs its name and exact version")
		case s.Package != nil && trimIssuer(s.Package.OAuth.Issuer) != c.Issuer:
			return fmt.Errorf("the package %s's oauth block names another issuer", s.Package.Name)
		}
	}
	return nil
}

// plainHTTPS reports whether s is an https address with a host and no user
// information, query or fragment.
func plainHTTPS(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
