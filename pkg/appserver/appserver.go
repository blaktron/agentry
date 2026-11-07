// Package appserver is Agentry's catalogue of application servers: for
// each application a QuickAgent may use on the person's own computer, the
// MCP server Agentry has vetted for it, pinned to one exact release, with
// every tool a run may call given a class.
//
// A release names an entry by its id in capabilities.desktop.servers and
// never names a command: Agentry Desktop launches the entry's pinned server
// as the person (or connects to the loopback address the application
// serves), and the run reaches it through the desktop link, one runner-owned
// server of the run's gateway catalog per entry. Each call is answered by
// the tool's class: read and act run and are logged, exec (code or commands
// the application interprets) asks the person first. The classes are the
// catalogue's, never the server's own tool annotations, which an untrusted
// server sets as it likes.
//
// An installed server runs on the person's computer with that computer's
// network and files, which no run can hold. So an entry lists the hosts the
// server is known to reach and which tools reach them; the consent names
// them, the scanner counts them as it counts a declared server's egress, and
// the receipt says they were outside the run.
//
// The catalogue is embedded data (catalogue.yaml), released with the core
// and compiled into every client that imports this package.
package appserver

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
)

// Class is how a tool is answered.
type Class string

// The classes, a closed set.
const (
	// ClassRead reads the application's state.
	ClassRead Class = "read"
	// ClassAct changes the application's state or works inside it.
	ClassAct Class = "act"
	// ClassExec runs code or commands the application interprets: each
	// call asks the person first.
	ClassExec Class = "exec"
)

// Classes returns every class, in a fixed order.
func Classes() []Class { return []Class{ClassRead, ClassAct, ClassExec} }

// Ecosystem is the package registry an installed server is published in.
type Ecosystem string

// The ecosystems an entry may pin.
const (
	EcosystemPyPI Ecosystem = "pypi"
	EcosystemNPM  Ecosystem = "npm"
	// EcosystemApplication is a server the application ships itself, as a
	// plugin released with it: its name is the plugin's and its version the
	// application's release that brought it. No package registry holds it,
	// so there is nothing to launch and no advisory database to look it up
	// in; only a loopback-http entry may name it.
	EcosystemApplication Ecosystem = "application"
)

// Attachment is how Agentry Desktop reaches an installed server.
type Attachment string

// The attachments.
const (
	// AttachmentStdio is a server Agentry Desktop launches, speaking MCP
	// over its standard input and output.
	AttachmentStdio Attachment = "stdio"
	// AttachmentLoopbackHTTP is a server the application runs inside
	// itself on a loopback address, which Agentry Desktop connects to.
	AttachmentLoopbackHTTP Attachment = "loopback-http"
)

// Platforms an entry may be offered on, as Go names them.
var platforms = []string{"linux", "darwin", "windows"}

// Server is one catalogue entry: an application and its vetted installed
// server.
type Server struct {
	// ID names it in capabilities.desktop.servers: lowercase letters,
	// digits and single hyphens.
	ID string `yaml:"id" json:"id"`
	// Application is the application's name, as people know it.
	Application string `yaml:"application" json:"application"`
	// Platforms are the operating systems it is offered on.
	Platforms []string `yaml:"platforms" json:"platforms"`
	// Package is the installed server, pinned to one exact release.
	Package Package `yaml:"server" json:"server"`
	// Attachment is how Agentry Desktop reaches the server.
	Attachment Attachment `yaml:"attachment" json:"attachment"`
	// Launch is the command line of a stdio server.
	Launch *Launch `yaml:"launch,omitempty" json:"launch,omitempty"`
	// Endpoint is a loopback-http server's address.
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	// Listener is the loopback port the application listens on, checked
	// before a run starts.
	Listener Listener `yaml:"listener" json:"listener"`
	// Tools are every tool a run may call, in the catalogue's order.
	Tools []Tool `yaml:"tools" json:"tools"`
	// Withheld are tools the server offers that no run is given.
	Withheld []string `yaml:"withheld,omitempty" json:"withheld,omitempty"`
	// Egress are the hosts the server or the application's add-on is
	// known to reach from the person's computer.
	Egress []string `yaml:"egress,omitempty" json:"egress,omitempty"`
	// Steps are what the person does once before the first run.
	Steps []string `yaml:"steps" json:"steps"`
}

// Package is an installed server's pin.
type Package struct {
	Ecosystem Ecosystem `yaml:"ecosystem" json:"ecosystem"`
	Name      string    `yaml:"name" json:"name"`
	// Version is exact: a newer release is not vetted until it is listed.
	Version string `yaml:"version" json:"version"`
	// Source is the server's source repository, https.
	Source string `yaml:"source" json:"source"`
}

// Ref is the pin as ecosystem:name@version.
func (p Package) Ref() string { return string(p.Ecosystem) + ":" + p.Name + "@" + p.Version }

// Launch is a stdio server's command line and environment.
type Launch struct {
	// Command is the program and its arguments; one of them holds the
	// pinned version.
	Command []string `yaml:"command" json:"command"`
	// Env is set for the server's process.
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
}

// Listener is where the application listens for its server.
type Listener struct {
	Port int `yaml:"port" json:"port"`
}

// Tool is one tool a run may call.
type Tool struct {
	Name  string `yaml:"name" json:"name"`
	Class Class  `yaml:"class" json:"class"`
	// Egress marks a tool that reaches the entry's hosts.
	Egress bool `yaml:"egress,omitempty" json:"egress,omitempty"`
}

// Tool returns the entry's tool of this name.
func (s Server) Tool(name string) (Tool, bool) {
	for _, t := range s.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// ToolNames are the entry's tools, in the catalogue's order.
func (s Server) ToolNames() []string {
	out := make([]string, len(s.Tools))
	for i, t := range s.Tools {
		out[i] = t.Name
	}
	return out
}

// Offers reports whether the server offers a tool of this name, given to a
// run or withheld.
func (s Server) Offers(name string) bool {
	_, ok := s.Tool(name)
	return ok || slices.Contains(s.Withheld, name)
}

// Catalogue is a validated catalogue.
type Catalogue struct {
	version int
	entries []Server
}

//go:embed catalogue.yaml
var builtinData []byte

var builtin = func() Catalogue {
	c, err := Parse(builtinData)
	if err != nil {
		panic("appserver: the embedded catalogue: " + err.Error())
	}
	return c
}()

// Builtin is the catalogue released with this build.
func Builtin() Catalogue { return builtin }

// Version is the catalogue's version, raised on every change to it.
func (c Catalogue) Version() int { return c.version }

// All is every entry, in the catalogue's order.
func (c Catalogue) All() []Server {
	out := make([]Server, len(c.entries))
	for i, e := range c.entries {
		out[i] = e.clone()
	}
	return out
}

// Lookup is the entry with this id.
func (c Catalogue) Lookup(id string) (Server, bool) {
	for _, e := range c.entries {
		if e.ID == id {
			return e.clone(), true
		}
	}
	return Server{}, false
}

func (s Server) clone() Server {
	s.Platforms = slices.Clone(s.Platforms)
	s.Tools = slices.Clone(s.Tools)
	s.Withheld = slices.Clone(s.Withheld)
	s.Egress = slices.Clone(s.Egress)
	s.Steps = slices.Clone(s.Steps)
	if s.Launch != nil {
		l := *s.Launch
		l.Command = slices.Clone(l.Command)
		l.Env = maps.Clone(l.Env)
		s.Launch = &l
	}
	return s
}

var (
	idRE      = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	toolRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	versionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*([.+-][0-9A-Za-z.+-]+)?$`)
	hostRE    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	envRE     = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// Parse reads and validates a catalogue. It refuses unknown fields, a
// catalogue without a version, a repeated or malformed id, an entry
// without an application, a platform or a step, a server without an exact
// version, a source that is not https, a launch that does not hold the
// pin, an attachment other than stdio or loopback-http, a stdio server of
// the application's own, a loopback address that is not loopback or not on
// the listener's port, a port out of range, a tool of no class or one
// outside the closed set, a tool listed twice or both given and withheld,
// and an egress host that is not a DNS name.
func Parse(data []byte) (Catalogue, error) {
	var doc struct {
		Version int      `yaml:"version"`
		Servers []Server `yaml:"servers"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return Catalogue{}, fmt.Errorf("application server catalogue: %w", err)
	}
	if doc.Version < 1 {
		return Catalogue{}, errors.New("application server catalogue: version is a positive number")
	}
	seen := map[string]bool{}
	for _, e := range doc.Servers {
		if err := e.validate(); err != nil {
			return Catalogue{}, fmt.Errorf("application server catalogue: %q: %w", e.ID, err)
		}
		if seen[e.ID] {
			return Catalogue{}, fmt.Errorf("application server catalogue: %q is listed twice", e.ID)
		}
		seen[e.ID] = true
	}
	return Catalogue{version: doc.Version, entries: doc.Servers}, nil
}

func (s Server) validate() error {
	switch {
	case !idRE.MatchString(s.ID):
		return errors.New("an id is lowercase letters, digits and single hyphens")
	case s.Application == "":
		return errors.New("an application name is required")
	case len(s.Platforms) == 0:
		return errors.New("an entry names the platforms it is offered on")
	case len(s.Steps) == 0:
		return errors.New("an entry says what the person does before the first run")
	case len(s.Tools) == 0:
		return errors.New("an entry gives a run at least one tool")
	}
	for _, p := range s.Platforms {
		if !slices.Contains(platforms, p) {
			return fmt.Errorf("unknown platform %q (one of %s)", p, strings.Join(platforms, ", "))
		}
	}
	if err := s.Package.validate(); err != nil {
		return err
	}
	if err := s.validateAttachment(); err != nil {
		return err
	}
	if s.Listener.Port < 1 || s.Listener.Port > 65535 {
		return fmt.Errorf("listener port %d is not a port", s.Listener.Port)
	}
	given := map[string]bool{}
	for _, t := range s.Tools {
		switch {
		case !toolRE.MatchString(t.Name):
			return fmt.Errorf("tool name %q is not a tool name", t.Name)
		case given[t.Name]:
			return fmt.Errorf("tool %s is listed twice", t.Name)
		case !slices.Contains(Classes(), t.Class):
			return fmt.Errorf("tool %s has class %q: a class is read, act or exec", t.Name, t.Class)
		}
		given[t.Name] = true
	}
	withheld := map[string]bool{}
	for _, n := range s.Withheld {
		switch {
		case !toolRE.MatchString(n):
			return fmt.Errorf("withheld tool %q is not a tool name", n)
		case given[n]:
			return fmt.Errorf("tool %s is both given and withheld", n)
		case withheld[n]:
			return fmt.Errorf("withheld tool %s is listed twice", n)
		}
		withheld[n] = true
	}
	hosts := map[string]bool{}
	for _, h := range s.Egress {
		switch {
		case !hostRE.MatchString(h):
			return fmt.Errorf("egress host %q is not a lowercase DNS name", h)
		case hosts[h]:
			return fmt.Errorf("egress host %s is listed twice", h)
		}
		hosts[h] = true
	}
	return nil
}

func (p Package) validate() error {
	switch {
	case p.Ecosystem != EcosystemPyPI && p.Ecosystem != EcosystemNPM && p.Ecosystem != EcosystemApplication:
		return fmt.Errorf("unknown ecosystem %q", p.Ecosystem)
	case p.Name == "":
		return errors.New("the server needs its package name")
	case !versionRE.MatchString(p.Version):
		return fmt.Errorf("the server's version %q is not one exact release", p.Version)
	case !plainHTTPS(p.Source):
		return errors.New("the server's source is a plain https address")
	}
	return nil
}

// pinnedArg is the launch argument that names the pinned release, as the
// ecosystem's runner spells it: uvx name==version, npx name@version.
func (p Package) pinnedArg() string {
	if p.Ecosystem == EcosystemNPM {
		return p.Name + "@" + p.Version
	}
	return p.Name + "==" + p.Version
}

func (s Server) validateAttachment() error {
	switch s.Attachment {
	case AttachmentStdio:
		switch {
		case s.Package.Ecosystem == EcosystemApplication:
			return errors.New("a stdio server is launched from a package: the application's own plugin is reached on loopback")
		case s.Launch == nil || len(s.Launch.Command) == 0:
			return errors.New("a stdio server needs its launch command")
		case s.Endpoint != "":
			return errors.New("a stdio server has no endpoint")
		case !slices.Contains(s.Launch.Command, s.Package.pinnedArg()):
			return fmt.Errorf("the launch command does not hold the pin %s", s.Package.pinnedArg())
		}
		for k := range s.Launch.Env {
			if !envRE.MatchString(k) {
				return fmt.Errorf("launch environment name %q is not an environment variable name", k)
			}
		}
	case AttachmentLoopbackHTTP:
		if s.Launch != nil {
			return errors.New("a loopback-http server is not launched")
		}
		u, err := url.Parse(s.Endpoint)
		if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("endpoint %q is not an http://127.0.0.1 address", s.Endpoint)
		}
		if u.Port() != fmt.Sprint(s.Listener.Port) {
			return fmt.Errorf("endpoint %q is not on the listener's port %d", s.Endpoint, s.Listener.Port)
		}
	default:
		return fmt.Errorf("unknown attachment %q (stdio or loopback-http)", s.Attachment)
	}
	return nil
}

// plainHTTPS reports whether s is an https address with a host and no user
// information, query or fragment.
func plainHTTPS(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
