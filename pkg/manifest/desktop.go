package manifest

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/blaktron/agentry/pkg/appserver"
)

// The person's own computer. A release that works an application on the
// computer the run starts from declares capabilities.desktop: the
// applications it uses, each by a short id, and whether it does computer
// use, the screen, pointer and keyboard of those applications' windows
// (app) or of the whole display (screen). The run stays in the sandbox; its
// calls reach Agentry Desktop through the desktop link, and Agentry Desktop
// answers them with the application the person approved on that computer.
//
// The line names the kind, never the instance: an application id, never a
// command, a path, a port or an address. The id is resolved on the
// person's computer, against the applications they approved there, so the
// registry holds no list of them: any id of the grammar is accepted, and a
// tool narrowing names tools the person's server is asked for when the run
// starts. An entry may instead ask for an application the person chooses
// when the run starts. The line is inside the contract: consent shows it,
// an upgrade that widens it asks again, a policy can block its two tokens
// (desktop and computerUse), and search can filter on it. No hosted run has
// it: the person's computer is reached only from a run on it or on the
// person's own runhost.

// Desktop is capabilities.desktop (v2, V19).
type Desktop struct {
	// Servers are the applications the run uses on the person's computer:
	// each by its id, or one the person chooses.
	Servers []DesktopServer `yaml:"servers,omitempty" json:"servers,omitempty"`
	// ComputerUse is ComputerUseApp or ComputerUseScreen; empty declares
	// no computer use.
	ComputerUse ComputerUse `yaml:"computerUse,omitempty" json:"computerUse,omitempty"`
}

// DesktopServer is one application a release uses on the person's
// computer.
type DesktopServer struct {
	// ID is the application's id, resolved on the person's computer to an
	// application they approved there. Empty on a Choose entry.
	ID string `yaml:"id,omitempty" json:"id,omitempty"`
	// Choose asks for an application the person chooses when the run
	// starts, from those they approved for what Use names. At most one
	// entry of a line chooses, and it names no id and no tools.
	Choose bool `yaml:"choose,omitempty" json:"choose,omitempty"`
	// Use is what of the application the run uses: its MCP server, its
	// windows (computer use), or both. Empty is its server, and its windows
	// too where the line declares computer use.
	Use DesktopUse `yaml:"use,omitempty" json:"use,omitempty"`
	// Tools narrows the run to these tools of the application's server;
	// absent, the run has every tool the server lists.
	Tools []string `yaml:"tools,omitempty" json:"tools,omitempty"`
}

// DesktopUse is what of an application a run uses.
type DesktopUse string

// What a run may use of an application.
const (
	// DesktopUseMCP is the application's MCP server alone.
	DesktopUseMCP DesktopUse = "mcp"
	// DesktopUseComputer is the application's windows alone, through
	// computer use.
	DesktopUseComputer DesktopUse = "computer"
	// DesktopUseBoth is its MCP server and its windows.
	DesktopUseBoth DesktopUse = "both"
)

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

// MaxDesktopServers bounds the applications one release may use.
const MaxDesktopServers = 4

// MaxDesktopIDLength bounds an application id.
const MaxDesktopIDLength = 40

// The desktop link's own entry names, agentry-desktop-<name>, which no
// application id may take: the computer-use entry, and the entry of an
// application the person chooses when the run starts.
const (
	DesktopComputerName = "computer"
	DesktopChosenName   = "chosen"
)

// ReservedDesktopIDs are the ids V19 refuses, since they name the desktop
// link's own entries.
var ReservedDesktopIDs = []string{DesktopComputerName, DesktopChosenName}

var (
	desktopIDPattern   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	desktopToolPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Allowed is the tools a run of this server has among a catalogue entry's:
// the entry's, narrowed to Tools where Tools is set, in the entry's order.
// Validation, consent and the capability diff do not use it: they read no
// catalogue.
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

// Server returns the line's entry of this application id. A Choose entry
// has no id and is not found by one.
func (d *Desktop) Server(id string) (DesktopServer, bool) {
	if d == nil || id == "" {
		return DesktopServer{}, false
	}
	for _, s := range d.Servers {
		if !s.Choose && s.ID == id {
			return s, true
		}
	}
	return DesktopServer{}, false
}

// UsesServer reports whether the run uses this entry's MCP server: an
// entry that says nothing of use does.
func (s DesktopServer) UsesServer() bool {
	return s.Use == "" || s.Use == DesktopUseMCP || s.Use == DesktopUseBoth
}

// UsesWindows reports whether the run's computer use reaches this entry's
// windows: an entry that says so, and an entry that says nothing of use on
// a line that declares computer use.
func (d *Desktop) UsesWindows(s DesktopServer) bool {
	switch s.Use {
	case DesktopUseComputer, DesktopUseBoth:
		return true
	case "":
		return d.HasComputerUse()
	}
	return false
}

// ChoosesWindows reports whether app-scope computer use reaches the windows
// of an application the person chooses when the run starts: a Choose entry
// that uses windows, or a line with computer use whose entries name no
// application's windows.
func (d *Desktop) ChoosesWindows() bool {
	if d == nil || d.ComputerUse != ComputerUseApp {
		return false
	}
	named := false
	for _, s := range d.Servers {
		if !d.UsesWindows(s) {
			continue
		}
		if s.Choose {
			return true
		}
		named = true
	}
	return !named
}

// ChoosesServer reports whether the line asks for the MCP server of an
// application the person chooses when the run starts.
func (d *Desktop) ChoosesServer() bool {
	return d != nil && slices.ContainsFunc(d.Servers, func(s DesktopServer) bool { return s.Choose && s.UsesServer() })
}

// WindowApps names whose windows app-scope computer use reaches: each
// named application that uses its windows, then "an application you
// choose" where ChoosesWindows.
func (d *Desktop) WindowApps() []string {
	var out []string
	for _, s := range d.Servers {
		if !s.Choose && d.UsesWindows(s) {
			out = append(out, s.ID)
		}
	}
	if d.ChoosesWindows() {
		out = append(out, "an application you choose")
	}
	return out
}

// UsesAnyServer reports whether the line uses any application's MCP
// server, whose reach from the person's computer the registry cannot know.
func (d *Desktop) UsesAnyServer() bool {
	return d != nil && slices.ContainsFunc(d.Servers, DesktopServer.UsesServer)
}

// chooserKey is the chooser's key in a diff: no application id can spell
// it, so an application named "choose" never stands for the chooser.
const chooserKey = "(choose)"

// desktopKey is an entry's key in a diff: its id, or chooserKey.
func desktopKey(s DesktopServer) string {
	if s.Choose {
		return chooserKey
	}
	return s.ID
}

// validateDesktop is V19: the line is v2; it uses an application or
// computer use; at most MaxDesktopServers entries, each an application id
// of the grammar named once, or the one entry that chooses; use is mcp,
// computer or both, and an entry that uses windows needs computer use; a
// narrowing is of an entry that uses the server, names tools of the
// grammar, each once, and at least one; and the computer-use scope is app
// or screen.
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
		s.errf("V19", "capabilities.desktop", "the line uses nothing on the person's computer: name an application or set computerUse")
	}
	if len(d.Servers) > MaxDesktopServers {
		s.errf("V19", "capabilities.desktop.servers", "%d applications; the maximum is %d", len(d.Servers), MaxDesktopServers)
	}
	seen := map[string]bool{}
	choosers := 0
	for i, srv := range d.Servers {
		p := fmt.Sprintf("capabilities.desktop.servers[%d]", i)
		switch srv.Use {
		case "", DesktopUseMCP, DesktopUseComputer, DesktopUseBoth:
		default:
			s.errf("V19", p+".use", "use %q is not mcp, computer or both", srv.Use)
		}
		if (srv.Use == DesktopUseComputer || srv.Use == DesktopUseBoth) && d.ComputerUse == "" {
			s.errf("V19", p+".use", "use %q is the application's windows, which needs computerUse", srv.Use)
		}
		if srv.Choose {
			choosers++
			switch {
			case choosers > 1:
				s.errf("V19", p+".choose", "a second entry asks the person to choose an application; one may")
			case srv.ID != "":
				s.errf("V19", p+".id", "an entry that asks the person to choose names no id")
			case srv.Tools != nil:
				s.errf("V19", p+".tools", "an entry that asks the person to choose names no tools: the run has every tool of the server they choose")
			}
			continue
		}
		switch {
		case srv.ID == "":
			s.errf("V19", p+".id", "an application needs an id, or choose: true")
			continue
		case len(srv.ID) > MaxDesktopIDLength || !desktopIDPattern.MatchString(srv.ID):
			s.errf("V19", p+".id", "%q is not an application id: lowercase letters and digits in words joined by single hyphens, at most %d characters", srv.ID, MaxDesktopIDLength)
			continue
		case slices.Contains(ReservedDesktopIDs, srv.ID):
			s.errf("V19", p+".id", "%q is the name of the desktop link's own entry (agentry-desktop-%s), which no application may take", srv.ID, srv.ID)
			continue
		case seen[srv.ID]:
			s.errf("V19", p+".id", "duplicate application %q", srv.ID)
			continue
		}
		seen[srv.ID] = true
		if srv.Tools == nil {
			continue
		}
		if !srv.UsesServer() {
			s.errf("V19", p+".tools", "%s is used through its windows only, so it has no tools to narrow", srv.ID)
			continue
		}
		if len(srv.Tools) == 0 {
			s.errf("V19", p+".tools", "the narrowing names no tool: leave tools out for every tool of %s's server", srv.ID)
		}
		tools := map[string]bool{}
		for j, name := range srv.Tools {
			tp := fmt.Sprintf("%s.tools[%d]", p, j)
			switch {
			case !desktopToolPattern.MatchString(name):
				s.errf("V19", tp, "%q is not a tool name: letters, digits, hyphens and underscores, at most 64", name)
			case tools[name]:
				s.errf("V19", tp, "duplicate tool %q", name)
			}
			tools[name] = true
		}
	}
}

// desktopApplication is how the consent names an entry's application.
func desktopApplication(s DesktopServer) string {
	if s.Choose {
		return "an application you choose"
	}
	return "the application " + s.ID
}

// DescribeDesktopServer says what one entry gives a run, in the consent's
// words: "the application blender on your computer, through its MCP server
// (every tool it lists)". The registry knows an application by its id
// alone; Agentry Desktop, which resolves the id, says the rest.
func DescribeDesktopServer(srv DesktopServer) string {
	app := desktopApplication(srv)
	if srv.Use == DesktopUseComputer {
		return app + " on your computer, through its windows only"
	}
	tools := "every tool it lists"
	if len(srv.Tools) > 0 {
		tools = "tools " + strings.Join(srv.Tools, ", ")
	}
	return app + " on your computer, through its MCP server (" + tools + ")"
}

// DescribeComputerUse says what a line's computer use lets the agent do,
// in the consent's words.
func DescribeComputerUse(d *Desktop) string {
	switch {
	case !d.HasComputerUse():
		return ""
	case d.ComputerUse == ComputerUseScreen:
		return "can see and use your whole screen"
	}
	return "can see and use the windows of " + joinAnd(d.WindowApps()) + " on your computer"
}

// joinAnd is "a", "a and b", "a, b and c".
func joinAnd(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
