package manifest

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/appserver"
)

// The person's computer (V19): capabilities.desktop names application
// servers by catalogue id, each optionally narrowing the catalogue's tools,
// and a computer-use scope. These tests pin V19, that the line is part of
// the contract (canonical JSON, the capability diff), and the schema.

func desktopManifest(t *testing.T) *Manifest {
	t.Helper()
	return mustParse(t, strings.Replace(v2YAML, "  secrets: [PAGERDUTY_TOKEN]\n", `  secrets: [PAGERDUTY_TOKEN]
  desktop:
    servers:
      - id: blender
        tools: [get_scene_info, execute_blender_code]
    computerUse: app
`, 1))
}

func TestADesktopLineParsesAndValidates(t *testing.T) {
	m := desktopManifest(t)
	d := m.Capabilities.Desktop
	if d == nil || len(d.Servers) != 1 || d.Servers[0].ID != "blender" ||
		!slices.Equal(d.Servers[0].Tools, []string{"get_scene_info", "execute_blender_code"}) || d.ComputerUse != ComputerUseApp {
		t.Fatalf("desktop = %+v", d)
	}
	if is := browserIssues(Validate(m)); len(is) != 0 {
		t.Fatalf("a declared desktop line is refused: %v", is)
	}
}

func TestV19RefusesWhatTheLineCannotMean(t *testing.T) {
	five := Desktop{Servers: []DesktopServer{{ID: "blender"}, {ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}}
	for _, c := range []struct {
		name    string
		desktop Desktop
		path    string
		says    string
	}{
		{"an empty line", Desktop{}, "capabilities.desktop", "uses nothing"},
		{"an unknown catalogue id", Desktop{Servers: []DesktopServer{{ID: "photoshop"}}},
			"capabilities.desktop.servers[0].id", "is not in the catalogue"},
		{"a command for an id", Desktop{Servers: []DesktopServer{{ID: "uvx mcp-for-blender"}}},
			"capabilities.desktop.servers[0].id", "is not in the catalogue"},
		{"a duplicate id", Desktop{Servers: []DesktopServer{{ID: "blender"}, {ID: "blender"}}},
			"capabilities.desktop.servers[1].id", "duplicate server"},
		{"more than four servers", five, "capabilities.desktop.servers", "the maximum is 4"},
		{"a tool not in the entry", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"delete_everything"}}}},
			"capabilities.desktop.servers[0].tools[0]", "is not a tool of Blender's server"},
		{"a withheld tool", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"disable_telemetry"}}}},
			"capabilities.desktop.servers[0].tools[0]", "no run is given"},
		{"a tool in another case", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"Look"}}}},
			"capabilities.desktop.servers[0].tools[0]", "is not a tool"},
		{"a duplicate tool", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"look", "look"}}}},
			"capabilities.desktop.servers[0].tools[1]", "duplicate tool"},
		{"an empty narrowing", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{}}}},
			"capabilities.desktop.servers[0].tools", "names no tool"},
		{"an unknown scope", Desktop{ComputerUse: "everything"}, "capabilities.desktop.computerUse", "is not app or screen"},
		{"a scope in another case", Desktop{ComputerUse: "App"}, "capabilities.desktop.computerUse", "is not app or screen"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := validV2Manifest(t)
			d := c.desktop
			m.Capabilities.Desktop = &d
			errs := Validate(m)
			wantIssue(t, errs, "V19", SeverityError, c.path)
			for _, err := range errs {
				if is, _ := AsIssue(err); is.Rule == "V19" && is.Path == c.path && strings.Contains(is.Message, c.says) {
					return
				}
			}
			t.Fatalf("no V19 issue at %s saying %q:%s", c.path, c.says, issueStrings(errs))
		})
	}
}

func TestV19TakesWhatTheLineMeans(t *testing.T) {
	for _, c := range []struct {
		name    string
		desktop Desktop
	}{
		{"a server with every tool", Desktop{Servers: []DesktopServer{{ID: "blender"}}}},
		{"a narrowed server", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"look"}}}}},
		{"computer use alone", Desktop{ComputerUse: ComputerUseApp}},
		{"the whole screen", Desktop{ComputerUse: ComputerUseScreen}},
		{"a server and computer use", Desktop{Servers: []DesktopServer{{ID: "blender"}}, ComputerUse: ComputerUseApp}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := validV2Manifest(t)
			d := c.desktop
			m.Capabilities.Desktop = &d
			if is := browserIssues(Validate(m)); len(is) != 0 {
				t.Fatalf("refused: %v", is)
			}
		})
	}
}

func TestDesktopIsAV2Field(t *testing.T) {
	m := validV2Manifest(t)
	m.SchemaVersion = "1"
	m.Capabilities.Desktop = &Desktop{Servers: []DesktopServer{{ID: "blender"}}}
	wantIssue(t, Validate(m), "V1", SeverityError, "capabilities.desktop")
}

// TestDesktopIsInTheContract: the canonical JSON the registry stores
// carries the line, so consent, search (capability=desktop) and the
// judge's declared capabilities read it.
func TestDesktopIsInTheContract(t *testing.T) {
	m := desktopManifest(t)
	if got := m.Contract().Desktop; got == nil || got.Servers[0].ID != "blender" {
		t.Fatalf("Contract().Desktop = %+v", got)
	}
	raw, err := CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Capabilities struct {
			Desktop map[string]json.RawMessage `json:"desktop"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc.Capabilities.Desktop["computerUse"]) != `"app"` || len(doc.Capabilities.Desktop["servers"]) == 0 {
		t.Fatalf("canonical capabilities.desktop = %s", raw)
	}
	var back Manifest
	if err := json.Unmarshal(raw, &back); err != nil || back.Capabilities.Desktop == nil ||
		!slices.Equal(back.Capabilities.Desktop.Servers[0].Tools, []string{"get_scene_info", "execute_blender_code"}) {
		t.Fatalf("the canonical form does not read back: %v %+v", err, back.Capabilities.Desktop)
	}
}

// TestAllowedIsTheCatalogueNarrowed: a narrowing keeps the catalogue's
// order and classes, and no narrowing is every tool the entry gives.
func TestAllowedIsTheCatalogueNarrowed(t *testing.T) {
	e, _ := appserver.Builtin().Lookup("blender")
	all := DesktopServer{ID: "blender"}.Allowed(e)
	if len(all) != len(e.Tools) {
		t.Fatalf("no narrowing gives %d tools; the entry gives %d", len(all), len(e.Tools))
	}
	got := DesktopServer{ID: "blender", Tools: []string{"look", "execute_blender_code"}}.Allowed(e)
	if len(got) != 2 || got[0].Name != "execute_blender_code" || got[0].Class != appserver.ClassExec || got[1].Name != "look" {
		t.Fatalf("narrowed = %+v", got)
	}
}

// TestDiffCapabilitiesDesktop pins that a new line, a new server, a lifted
// narrowing, a tool added to a narrowing, computer use declared and app to
// screen widen; a removed server, a narrower tool list and a smaller scope
// narrow; the same line is no change.
func TestDiffCapabilitiesDesktop(t *testing.T) {
	blender := DesktopServer{ID: "blender"}
	narrow := DesktopServer{ID: "blender", Tools: []string{"look", "get_scene_info"}}
	uses := "uses Blender on your computer through its MCP server (7 tools, 1 runs code inside Blender; it reaches 12 hosts from your computer)"
	for _, c := range []struct {
		name              string
		old, next         *Desktop
		widened, narrowed []string
	}{
		{"a new line", nil, &Desktop{Servers: []DesktopServer{blender}}, []string{uses}, nil},
		{"a new narrowed line", nil, &Desktop{Servers: []DesktopServer{narrow}},
			[]string{"uses Blender on your computer through its MCP server (2 tools)"}, nil},
		{"a new line with computer use", nil, &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp},
			[]string{uses, "can see and use Blender's windows on your computer"}, nil},
		{"computer use alone", nil, &Desktop{ComputerUse: ComputerUseApp},
			[]string{"can see and use the window of an application you pick on your computer"}, nil},
		{"the whole screen", nil, &Desktop{ComputerUse: ComputerUseScreen},
			[]string{"can see and use your whole screen"}, nil},
		{"the line dropped", &Desktop{Servers: []DesktopServer{blender}}, nil, nil, []string{"no longer uses your computer"}},
		{"the same line", &Desktop{Servers: []DesktopServer{narrow}, ComputerUse: ComputerUseApp},
			&Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"get_scene_info", "look"}}}, ComputerUse: ComputerUseApp}, nil, nil},
		{"a server added to computer use", &Desktop{ComputerUse: ComputerUseApp}, &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp},
			[]string{uses}, nil},
		{"a server removed", &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp}, &Desktop{ComputerUse: ComputerUseApp},
			nil, []string{"no longer uses Blender on your computer"}},
		{"a narrowing lifted", &Desktop{Servers: []DesktopServer{narrow}}, &Desktop{Servers: []DesktopServer{blender}},
			[]string{"lifts the tool narrowing of Blender on your computer (every tool the catalogue gives)"}, nil},
		{"a narrowing set", &Desktop{Servers: []DesktopServer{blender}}, &Desktop{Servers: []DesktopServer{narrow}},
			nil, []string{"narrows Blender on your computer to tools look, get_scene_info"}},
		{"a code tool added to a narrowing", &Desktop{Servers: []DesktopServer{narrow}},
			&Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"look", "get_scene_info", "execute_blender_code"}}}},
			[]string{"adds tool execute_blender_code of Blender on your computer (runs code inside Blender)"}, nil},
		{"a tool dropped from a narrowing", &Desktop{Servers: []DesktopServer{narrow}},
			&Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"look"}}}},
			nil, []string{"drops tool get_scene_info of Blender on your computer"}},
		{"computer use added", &Desktop{Servers: []DesktopServer{blender}}, &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp},
			[]string{"can see and use Blender's windows on your computer"}, nil},
		{"app to screen", &Desktop{ComputerUse: ComputerUseApp}, &Desktop{ComputerUse: ComputerUseScreen},
			[]string{"lets computer use reach your whole screen (was: the applications' windows)"}, nil},
		{"screen to app", &Desktop{ComputerUse: ComputerUseScreen}, &Desktop{ComputerUse: ComputerUseApp},
			nil, []string{"keeps computer use to the applications' windows (was: your whole screen)"}},
		{"computer use dropped", &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp}, &Desktop{Servers: []DesktopServer{blender}},
			nil, []string{"drops computer use on your computer"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := DiffCapabilities(Capabilities{Desktop: c.old}, Capabilities{Desktop: c.next})
			if !slices.Equal(d.Widened, c.widened) || !slices.Equal(d.Narrowed, c.narrowed) {
				t.Fatalf("widened %q narrowed %q; want %q and %q", d.Widened, d.Narrowed, c.widened, c.narrowed)
			}
			if d.HasWidened() != (len(c.widened) > 0) {
				t.Fatalf("HasWidened = %v", d.HasWidened())
			}
		})
	}
}

// TestV2SchemaDesktopShape pins the JSON schema beside the Go rule: a
// closed line, at most MaxDesktopServers servers by catalogue-id grammar,
// closed server entries, and the two scopes.
func TestV2SchemaDesktopShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Capabilities struct {
				Properties struct {
					Desktop struct {
						AdditionalProperties *bool `json:"additionalProperties"`
						MinProperties        int   `json:"minProperties"`
						Properties           struct {
							Servers struct {
								MaxItems    int  `json:"maxItems"`
								UniqueItems bool `json:"uniqueItems"`
								Items       struct {
									AdditionalProperties *bool    `json:"additionalProperties"`
									Required             []string `json:"required"`
									Properties           struct {
										ID struct {
											Pattern string `json:"pattern"`
										} `json:"id"`
										Tools struct {
											MinItems    int  `json:"minItems"`
											UniqueItems bool `json:"uniqueItems"`
										} `json:"tools"`
									} `json:"properties"`
								} `json:"items"`
							} `json:"servers"`
							ComputerUse struct {
								Enum []string `json:"enum"`
							} `json:"computerUse"`
						} `json:"properties"`
					} `json:"desktop"`
				} `json:"properties"`
			} `json:"capabilities"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	d := schema.Properties.Capabilities.Properties.Desktop
	if d.AdditionalProperties == nil || *d.AdditionalProperties || d.MinProperties != 1 {
		t.Fatal("capabilities.desktop is not a closed, non-empty object")
	}
	s := d.Properties.Servers
	if s.MaxItems != MaxDesktopServers || !s.UniqueItems || s.Items.AdditionalProperties == nil || *s.Items.AdditionalProperties ||
		!slices.Equal(s.Items.Required, []string{"id"}) || s.Items.Properties.Tools.MinItems != 1 || !s.Items.Properties.Tools.UniqueItems {
		t.Fatalf("servers = %+v", s)
	}
	idRE := regexp.MustCompile(s.Items.Properties.ID.Pattern)
	for _, e := range appserver.Builtin().All() {
		if !idRE.MatchString(e.ID) {
			t.Errorf("catalogue id %q does not match the schema's id pattern", e.ID)
		}
	}
	if !slices.Equal(d.Properties.ComputerUse.Enum, []string{string(ComputerUseApp), string(ComputerUseScreen)}) {
		t.Fatalf("computerUse = %v", d.Properties.ComputerUse.Enum)
	}
}
