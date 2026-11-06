package manifest

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blaktron/agentry/pkg/appserver"
)

// The person's own computer. A release that works an application on the
// computer the run starts from declares capabilities.desktop: the
// application servers it uses, by their id in the catalogue of application
// servers (pkg/appserver), and whether it does computer use, the screen,
// pointer and keyboard of those applications' windows (app) or of the
// whole display (screen). The run stays in the sandbox; its calls reach
// Agentry Desktop through the desktop link, and Agentry Desktop launches
// the catalogue's pinned server as the person and answers each call.
//
// The line names the kind, never the instance: a catalogue id, never a
// command, a path, a port or an address. Each server may narrow the
// catalogue's tools, never widen them. The line is inside the contract:
// consent shows it, an upgrade that widens it asks again, the scanner
// counts the catalogue's egress and looks its pin up, a policy can block
// its two tokens (desktop and computerUse), and search can filter on it.
// No hosted run has it: the person's computer is reached only from a run
// on it or on the person's own runhost.

// Desktop is capabilities.desktop (v2, V19).
type Desktop struct {
	// Servers are the application servers the run uses on the person's
	// computer, by catalogue id.
	Servers []DesktopServer `yaml:"servers,omitempty" json:"servers,omitempty"`
	// ComputerUse is ComputerUseApp or ComputerUseScreen; empty declares
	// no computer use.
	ComputerUse ComputerUse `yaml:"computerUse,omitempty" json:"computerUse,omitempty"`
}

// DesktopServer is one application server a release uses.
type DesktopServer struct {
	// ID is the server's id in the catalogue of application servers.
	ID string `yaml:"id" json:"id"`
	// Tools narrows the run to these of the catalogue's tools; absent,
	// the run has every tool the catalogue gives.
	Tools []string `yaml:"tools,omitempty" json:"tools,omitempty"`
}

// ComputerUse says how much of the person's screen the agent sees and acts
// on.
type ComputerUse string

// Computer-use scopes.
const (
	// ComputerUseApp holds the agent to the windows of the applications
	// the run uses.
	ComputerUseApp ComputerUse = "app"
	// ComputerUseScreen gives the agent the whole display, which the
	// consent names in its own words.
	ComputerUseScreen ComputerUse = "screen"
)

// MaxDesktopServers bounds the application servers one release may use.
const MaxDesktopServers = 4

// Allowed is the tools a run of this server has: the catalogue entry's,
// narrowed to Tools where Tools is set, in the catalogue's order.
func (d DesktopServer) Allowed(e appserver.Server) []appserver.Tool {
	var out []appserver.Tool
	for _, t := range e.Tools {
		if len(d.Tools) == 0 || slices.Contains(d.Tools, t.Name) {
			out = append(out, t)
		}
	}
	return out
}

// HasComputerUse reports whether the line declares computer use.
func (d *Desktop) HasComputerUse() bool { return d != nil && d.ComputerUse != "" }

// Server returns the line's server of this catalogue id.
func (d *Desktop) Server(id string) (DesktopServer, bool) {
	if d == nil {
		return DesktopServer{}, false
	}
	for _, s := range d.Servers {
		if s.ID == id {
			return s, true
		}
	}
	return DesktopServer{}, false
}

// validateDesktop is V19: the line is v2; it uses a server or computer
// use; at most MaxDesktopServers servers, each a catalogue id named once;
// a narrowing names tools of the entry, each once, and at least one; and
// the computer-use scope is app or screen.
func validateDesktop(s *issues, m *Manifest) {
	d := m.Capabilities.Desktop
	if d == nil {
		return
	}
	if m.Major() != 2 {
		s.errf("V1", "capabilities.desktop", "desktop is a v2 field; set schemaVersion: 2")
		return
	}
	switch d.ComputerUse {
	case "", ComputerUseApp, ComputerUseScreen:
	default:
		s.errf("V19", "capabilities.desktop.computerUse", "computerUse %q is not app or screen", d.ComputerUse)
	}
	if len(d.Servers) == 0 && d.ComputerUse == "" {
		s.errf("V19", "capabilities.desktop", "the line uses nothing on the person's computer: name a server or set computerUse")
	}
	if len(d.Servers) > MaxDesktopServers {
		s.errf("V19", "capabilities.desktop.servers", "%d servers; the maximum is %d", len(d.Servers), MaxDesktopServers)
	}
	catalogue := appserver.Builtin()
	seen := map[string]bool{}
	for i, srv := range d.Servers {
		p := fmt.Sprintf("capabilities.desktop.servers[%d]", i)
		dup := seen[srv.ID]
		seen[srv.ID] = true
		e, known := catalogue.Lookup(srv.ID)
		switch {
		case dup:
			s.errf("V19", p+".id", "duplicate server %q", srv.ID)
			continue
		case !known:
			s.errf("V19", p+".id", "%q is not in the catalogue of application servers", srv.ID)
			continue
		}
		if srv.Tools != nil && len(srv.Tools) == 0 {
			s.errf("V19", p+".tools", "the narrowing names no tool: leave tools out for every tool of %s", e.Application)
		}
		tools := map[string]bool{}
		for j, name := range srv.Tools {
			tp := fmt.Sprintf("%s.tools[%d]", p, j)
			switch {
			case tools[name]:
				s.errf("V19", tp, "duplicate tool %q", name)
			case slices.Contains(e.Withheld, name):
				s.errf("V19", tp, "%q is a tool of %s's server that no run is given", name, e.Application)
			default:
				if _, ok := e.Tool(name); !ok {
					s.errf("V19", tp, "%q is not a tool of %s's server in the catalogue", name, e.Application)
				}
			}
			tools[name] = true
		}
	}
}

// desktopApplication is the application a catalogue id names, or the id
// itself where this build's catalogue does not list it.
func desktopApplication(id string) string {
	if e, ok := appserver.Builtin().Lookup(id); ok {
		return e.Application
	}
	return id
}

// DescribeDesktopServer says what one application server gives a run, in
// the consent's words: "Blender on your computer through its MCP server
// (7 tools, 1 runs code inside Blender; it reaches 12 hosts from your
// computer)".
func DescribeDesktopServer(srv DesktopServer) string {
	e, ok := appserver.Builtin().Lookup(srv.ID)
	if !ok {
		return srv.ID + " on your computer through its MCP server"
	}
	tools := srv.Allowed(e)
	exec, egress := 0, false
	for _, t := range tools {
		if t.Class == appserver.ClassExec {
			exec++
		}
		egress = egress || t.Egress
	}
	detail := countOf(len(tools), "tool")
	if exec > 0 {
		runs := "runs"
		if exec > 1 {
			runs = "run"
		}
		detail += fmt.Sprintf(", %d %s code inside %s", exec, runs, e.Application)
	}
	if egress && len(e.Egress) > 0 {
		detail += "; it reaches " + countOf(len(e.Egress), "host") + " from your computer"
	}
	return e.Application + " on your computer through its MCP server (" + detail + ")"
}

// DescribeComputerUse says what a line's computer use lets the agent do,
// in the consent's words.
func DescribeComputerUse(d *Desktop) string {
	switch {
	case !d.HasComputerUse():
		return ""
	case d.ComputerUse == ComputerUseScreen:
		return "can see and use your whole screen"
	case len(d.Servers) == 0:
		return "can see and use the window of an application you pick on your computer"
	}
	apps := make([]string, 0, len(d.Servers))
	for _, s := range d.Servers {
		apps = append(apps, desktopApplication(s.ID))
	}
	if len(apps) == 1 {
		return "can see and use " + apps[0] + "'s windows on your computer"
	}
	return "can see and use the windows of " + strings.Join(apps[:len(apps)-1], ", ") + " and " + apps[len(apps)-1] + " on your computer"
}

// countOf is "1 tool", "7 tools".
func countOf(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
