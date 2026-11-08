package manifest

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/appserver"
)

// The person's computer (V19): capabilities.desktop names applications by
// id, resolved on the person's computer, or asks for one the person
// chooses; each says what of the application it uses and may narrow its
// server's tools; and a computer-use scope. These tests pin V19, that the
// line is part of the contract (canonical JSON, the capability diff), and
// the schema.

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
	choose := DesktopServer{Choose: true}
	for _, c := range []struct {
		name    string
		desktop Desktop
		path    string
		says    string
	}{
		{"an empty line", Desktop{}, "capabilities.desktop", "uses nothing"},
		{"a command for an id", Desktop{Servers: []DesktopServer{{ID: "uvx mcp-for-blender"}}},
			"capabilities.desktop.servers[0].id", "is not an application id"},
		{"a path for an id", Desktop{Servers: []DesktopServer{{ID: "/usr/bin/blender"}}},
			"capabilities.desktop.servers[0].id", "is not an application id"},
		{"an id in another case", Desktop{Servers: []DesktopServer{{ID: "Blender"}}},
			"capabilities.desktop.servers[0].id", "is not an application id"},
		{"an id too long", Desktop{Servers: []DesktopServer{{ID: strings.Repeat("a", MaxDesktopIDLength+1)}}},
			"capabilities.desktop.servers[0].id", "at most 40"},
		{"no id and no choose", Desktop{Servers: []DesktopServer{{Tools: []string{"look"}}}},
			"capabilities.desktop.servers[0].id", "needs an id"},
		{"a duplicate id", Desktop{Servers: []DesktopServer{{ID: "blender"}, {ID: "blender"}}},
			"capabilities.desktop.servers[1].id", "duplicate application"},
		{"more than four applications", five, "capabilities.desktop.servers", "the maximum is 4"},
		{"a tool name that is not one", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"rm -rf"}}}},
			"capabilities.desktop.servers[0].tools[0]", "is not a tool name"},
		{"a duplicate tool", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"look", "look"}}}},
			"capabilities.desktop.servers[0].tools[1]", "duplicate tool"},
		{"an empty narrowing", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{}}}},
			"capabilities.desktop.servers[0].tools", "names no tool"},
		{"an unknown use", Desktop{Servers: []DesktopServer{{ID: "blender", Use: "everything"}}},
			"capabilities.desktop.servers[0].use", "is not mcp, computer or both"},
		{"windows without computer use", Desktop{Servers: []DesktopServer{{ID: "kdenlive", Use: DesktopUseComputer}}},
			"capabilities.desktop.servers[0].use", "needs computerUse"},
		{"both without computer use", Desktop{Servers: []DesktopServer{{ID: "kdenlive", Use: DesktopUseBoth}}},
			"capabilities.desktop.servers[0].use", "needs computerUse"},
		{"a narrowing of windows alone", Desktop{Servers: []DesktopServer{{ID: "kdenlive", Use: DesktopUseComputer, Tools: []string{"look"}}}, ComputerUse: ComputerUseApp},
			"capabilities.desktop.servers[0].tools", "windows only"},
		{"the computer-use entry's name", Desktop{Servers: []DesktopServer{{ID: "computer"}}},
			"capabilities.desktop.servers[0].id", "the desktop link's own entry"},
		{"the chosen application's entry name", Desktop{Servers: []DesktopServer{{ID: "chosen"}}},
			"capabilities.desktop.servers[0].id", "the desktop link's own entry"},
		{"two entries that choose", Desktop{Servers: []DesktopServer{choose, choose}},
			"capabilities.desktop.servers[1].choose", "one may"},
		{"a chooser with an id", Desktop{Servers: []DesktopServer{{Choose: true, ID: "blender"}}},
			"capabilities.desktop.servers[0].id", "names no id"},
		{"a chooser with tools", Desktop{Servers: []DesktopServer{{Choose: true, Tools: []string{"look"}}}},
			"capabilities.desktop.servers[0].tools", "names no tools"},
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

// Any application id is the contract's: the registry holds no list of
// the applications a person may approve, so an id it has never seen, and
// tools it cannot check, are taken as they are written.
func TestV19TakesWhatTheLineMeans(t *testing.T) {
	for _, c := range []struct {
		name    string
		desktop Desktop
	}{
		{"a server with every tool", Desktop{Servers: []DesktopServer{{ID: "blender"}}}},
		{"a narrowed server", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"look"}}}}},
		{"an application no list names", Desktop{Servers: []DesktopServer{{ID: "my-cad-2"}}}},
		{"a tool no list names", Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"delete_everything", "Look"}}}}},
		{"computer use alone", Desktop{ComputerUse: ComputerUseApp}},
		{"the whole screen", Desktop{ComputerUse: ComputerUseScreen}},
		{"a server and computer use", Desktop{Servers: []DesktopServer{{ID: "blender"}}, ComputerUse: ComputerUseApp}},
		{"windows alone", Desktop{Servers: []DesktopServer{{ID: "kdenlive", Use: DesktopUseComputer}}, ComputerUse: ComputerUseApp}},
		{"its server alone beside computer use", Desktop{Servers: []DesktopServer{{ID: "blender", Use: DesktopUseMCP}, {ID: "kdenlive", Use: DesktopUseComputer}}, ComputerUse: ComputerUseApp}},
		{"both, narrowed", Desktop{Servers: []DesktopServer{{ID: "blender", Use: DesktopUseBoth, Tools: []string{"look"}}}, ComputerUse: ComputerUseApp}},
		{"a server the person chooses", Desktop{Servers: []DesktopServer{{Choose: true}}}},
		{"windows the person chooses", Desktop{Servers: []DesktopServer{{Choose: true, Use: DesktopUseComputer}}, ComputerUse: ComputerUseApp}},
		{"one named and one chosen", Desktop{Servers: []DesktopServer{{ID: "blender"}, {Choose: true, Use: DesktopUseBoth}}, ComputerUse: ComputerUseApp}},
		{"four applications", Desktop{Servers: []DesktopServer{{ID: "a"}, {ID: "b"}, {ID: "c"}, {Choose: true}}}},
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

// What of each application a run uses: an entry that says nothing is its
// server, and its windows too where the line declares computer use, as
// every line written before use read; app scope with no application's
// windows named is an application the person chooses.
func TestWhatOfAnApplicationTheRunUses(t *testing.T) {
	plain, mcp := DesktopServer{ID: "blender"}, DesktopServer{ID: "blender", Use: DesktopUseMCP}
	windows, both := DesktopServer{ID: "kdenlive", Use: DesktopUseComputer}, DesktopServer{ID: "kdenlive", Use: DesktopUseBoth}
	noUse, withUse := &Desktop{Servers: []DesktopServer{plain}}, &Desktop{Servers: []DesktopServer{plain}, ComputerUse: ComputerUseApp}
	for _, c := range []struct {
		name            string
		d               *Desktop
		s               DesktopServer
		server, windows bool
	}{
		{"a plain entry, no computer use", noUse, plain, true, false},
		{"a plain entry, computer use", withUse, plain, true, true},
		{"its server only", withUse, mcp, true, false},
		{"its windows only", withUse, windows, false, true},
		{"both", withUse, both, true, true},
	} {
		if got := c.s.UsesServer(); got != c.server {
			t.Errorf("%s: UsesServer = %v", c.name, got)
		}
		if got := c.d.UsesWindows(c.s); got != c.windows {
			t.Errorf("%s: UsesWindows = %v", c.name, got)
		}
	}
	for _, c := range []struct {
		name string
		d    *Desktop
		want bool
	}{
		{"computer use alone", &Desktop{ComputerUse: ComputerUseApp}, true},
		{"a named application's windows", withUse, false},
		{"servers only, beside computer use", &Desktop{Servers: []DesktopServer{mcp}, ComputerUse: ComputerUseApp}, true},
		{"a chooser for windows", &Desktop{Servers: []DesktopServer{plain, {Choose: true, Use: DesktopUseComputer}}, ComputerUse: ComputerUseApp}, true},
		{"the whole screen", &Desktop{ComputerUse: ComputerUseScreen}, false},
		{"no computer use", noUse, false},
	} {
		if got := c.d.ChoosesWindows(); got != c.want {
			t.Errorf("%s: ChoosesWindows = %v", c.name, got)
		}
	}
	if (&Desktop{Servers: []DesktopServer{windows}, ComputerUse: ComputerUseApp}).UsesAnyServer() || !withUse.UsesAnyServer() {
		t.Error("UsesAnyServer does not follow what each entry uses")
	}
	if _, found := (&Desktop{Servers: []DesktopServer{{Choose: true}}}).Server(""); found {
		t.Error("Server finds a chooser by the empty id")
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

// TestDiffCapabilitiesDesktop pins that a new line, a new application, an
// application's server or windows newly used, a lifted narrowing, a tool
// added to a narrowing, computer use declared and app to screen widen; a
// removed application, a narrower use, a narrower tool list and a smaller
// scope narrow; the same line is no change.
func TestDiffCapabilitiesDesktop(t *testing.T) {
	blender := DesktopServer{ID: "blender"}
	narrow := DesktopServer{ID: "blender", Tools: []string{"look", "get_scene_info"}}
	uses := "uses the application blender on your computer, through its MCP server (every tool it lists)"
	windows := DesktopServer{ID: "kdenlive", Use: DesktopUseComputer}
	for _, c := range []struct {
		name              string
		old, next         *Desktop
		widened, narrowed []string
	}{
		{"a new line", nil, &Desktop{Servers: []DesktopServer{blender}}, []string{uses}, nil},
		{"a new narrowed line", nil, &Desktop{Servers: []DesktopServer{narrow}},
			[]string{"uses the application blender on your computer, through its MCP server (tools look, get_scene_info)"}, nil},
		{"a new line with computer use", nil, &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp},
			[]string{uses, "can see and use the windows of blender on your computer"}, nil},
		{"computer use alone", nil, &Desktop{ComputerUse: ComputerUseApp},
			[]string{"can see and use the windows of an application you choose on your computer"}, nil},
		{"a server the person chooses", nil, &Desktop{Servers: []DesktopServer{{Choose: true}}},
			[]string{"uses an application you choose on your computer, through its MCP server (every tool it lists)"}, nil},
		{"windows alone", nil, &Desktop{Servers: []DesktopServer{windows}, ComputerUse: ComputerUseApp},
			[]string{"can see and use the windows of kdenlive on your computer"}, nil},
		{"the whole screen", nil, &Desktop{ComputerUse: ComputerUseScreen},
			[]string{"can see and use your whole screen"}, nil},
		{"the line dropped", &Desktop{Servers: []DesktopServer{blender}}, nil, nil, []string{"no longer uses your computer"}},
		{"the same line", &Desktop{Servers: []DesktopServer{narrow}, ComputerUse: ComputerUseApp},
			&Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"get_scene_info", "look"}}}, ComputerUse: ComputerUseApp}, nil, nil},
		{"use written out as it read", &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp},
			&Desktop{Servers: []DesktopServer{{ID: "blender", Use: DesktopUseBoth}}, ComputerUse: ComputerUseApp}, nil, nil},
		{"an application called choose, then a chooser", &Desktop{Servers: []DesktopServer{{ID: "choose"}}}, &Desktop{Servers: []DesktopServer{{Choose: true}}},
			[]string{"uses an application you choose on your computer, through its MCP server (every tool it lists)"},
			[]string{"no longer uses the application choose on your computer"}},
		{"an application named instead of chosen", &Desktop{ComputerUse: ComputerUseApp}, &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp},
			[]string{uses, "can see and use the windows of blender on your computer"},
			[]string{"no longer sees or uses the windows of an application you choose on your computer"}},
		{"an application removed", &Desktop{Servers: []DesktopServer{blender}}, &Desktop{ComputerUse: ComputerUseApp},
			[]string{"can see and use the windows of an application you choose on your computer"},
			[]string{"no longer uses the application blender on your computer"}},
		{"windows to both", &Desktop{Servers: []DesktopServer{windows}, ComputerUse: ComputerUseApp},
			&Desktop{Servers: []DesktopServer{{ID: "kdenlive", Use: DesktopUseBoth}}, ComputerUse: ComputerUseApp},
			[]string{"uses the application kdenlive on your computer, through its MCP server (every tool it lists)"}, nil},
		{"both to its server only", &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp},
			&Desktop{Servers: []DesktopServer{{ID: "blender", Use: DesktopUseMCP}}, ComputerUse: ComputerUseApp},
			[]string{"can see and use the windows of an application you choose on your computer"},
			[]string{"no longer sees or uses the windows of blender on your computer"}},
		{"both to its windows only", &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp},
			&Desktop{Servers: []DesktopServer{{ID: "blender", Use: DesktopUseComputer}}, ComputerUse: ComputerUseApp},
			nil, []string{"no longer uses the MCP server of the application blender on your computer"}},
		{"a narrowing lifted", &Desktop{Servers: []DesktopServer{narrow}}, &Desktop{Servers: []DesktopServer{blender}},
			[]string{"lifts the tool narrowing of the application blender on your computer (every tool its server lists)"}, nil},
		{"a narrowing set", &Desktop{Servers: []DesktopServer{blender}}, &Desktop{Servers: []DesktopServer{narrow}},
			nil, []string{"narrows the application blender on your computer to tools look, get_scene_info"}},
		{"a tool added to a narrowing", &Desktop{Servers: []DesktopServer{narrow}},
			&Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"look", "get_scene_info", "execute_blender_code"}}}},
			[]string{"adds tool execute_blender_code of the application blender on your computer"}, nil},
		{"a tool dropped from a narrowing", &Desktop{Servers: []DesktopServer{narrow}},
			&Desktop{Servers: []DesktopServer{{ID: "blender", Tools: []string{"look"}}}},
			nil, []string{"drops tool get_scene_info of the application blender on your computer"}},
		{"computer use added", &Desktop{Servers: []DesktopServer{blender}}, &Desktop{Servers: []DesktopServer{blender}, ComputerUse: ComputerUseApp},
			[]string{"can see and use the windows of blender on your computer"}, nil},
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
// closed line, at most MaxDesktopServers entries, closed entries that are
// either an id of the grammar or the one that chooses, the three uses, and
// the two scopes.
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
									AdditionalProperties *bool `json:"additionalProperties"`
									OneOf                []struct {
										Required []string `json:"required"`
									} `json:"oneOf"`
									Properties struct {
										ID struct {
											Pattern   string `json:"pattern"`
											MaxLength int    `json:"maxLength"`
											Not       struct {
												Enum []string `json:"enum"`
											} `json:"not"`
										} `json:"id"`
										Choose struct {
											Const *bool `json:"const"`
										} `json:"choose"`
										Use struct {
											Enum []string `json:"enum"`
										} `json:"use"`
										Tools struct {
											MinItems    int  `json:"minItems"`
											UniqueItems bool `json:"uniqueItems"`
											Items       struct {
												Pattern string `json:"pattern"`
											} `json:"items"`
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
	items := s.Items
	if s.MaxItems != MaxDesktopServers || !s.UniqueItems || items.AdditionalProperties == nil || *items.AdditionalProperties ||
		items.Properties.Tools.MinItems != 1 || !items.Properties.Tools.UniqueItems {
		t.Fatalf("servers = %+v", s)
	}
	if len(items.OneOf) != 2 || !slices.Equal(items.OneOf[0].Required, []string{"id"}) || !slices.Equal(items.OneOf[1].Required, []string{"choose"}) {
		t.Fatalf("an entry is not an id or a chooser: %+v", items.OneOf)
	}
	if items.Properties.ID.Pattern != desktopIDPattern.String() || items.Properties.ID.MaxLength != MaxDesktopIDLength ||
		items.Properties.Tools.Items.Pattern != desktopToolPattern.String() {
		t.Fatalf("the schema's grammar is not V19's: id %q (%d), tool %q", items.Properties.ID.Pattern, items.Properties.ID.MaxLength, items.Properties.Tools.Items.Pattern)
	}
	if !slices.Equal(items.Properties.ID.Not.Enum, ReservedDesktopIDs) {
		t.Fatalf("the schema reserves %v; V19 reserves %v", items.Properties.ID.Not.Enum, ReservedDesktopIDs)
	}
	if c := items.Properties.Choose.Const; c == nil || !*c {
		t.Fatal("choose is not the constant true")
	}
	if !slices.Equal(items.Properties.Use.Enum, []string{string(DesktopUseMCP), string(DesktopUseComputer), string(DesktopUseBoth)}) {
		t.Fatalf("use = %v", items.Properties.Use.Enum)
	}
	if !slices.Equal(d.Properties.ComputerUse.Enum, []string{string(ComputerUseApp), string(ComputerUseScreen)}) {
		t.Fatalf("computerUse = %v", d.Properties.ComputerUse.Enum)
	}
}

// A release names the kind, never the instance: an application's id and
// nothing of where it listens, and the consent says it in the install's
// words. A line that tried to carry an endpoint, a port or a command is no
// manifest.
func TestAnApplicationIsNamedByItsIDAlone(t *testing.T) {
	if got := DescribeDesktopServer(DesktopServer{ID: "unreal"}); got != "the application unreal on your computer, through its MCP server (every tool it lists)" {
		t.Fatalf("unreal's consent = %q", got)
	}
	if got := DescribeDesktopServer(DesktopServer{ID: "kdenlive", Use: DesktopUseComputer}); got != "the application kdenlive on your computer, through its windows only" {
		t.Fatalf("a windows-only consent = %q", got)
	}
	if got := DescribeComputerUse(&Desktop{Servers: []DesktopServer{{ID: "unreal"}, {ID: "blender", Use: DesktopUseMCP}, {Choose: true, Use: DesktopUseComputer}}, ComputerUse: ComputerUseApp}); got != "can see and use the windows of unreal and an application you choose on your computer" {
		t.Fatalf("computer use = %q", got)
	}
	for _, extra := range []string{"        endpoint: http://127.0.0.1:8000/mcp\n", "        port: 8000\n", "        command: [uvx, mcp-for-blender]\n"} {
		doc := strings.Replace(v2YAML, "  secrets: [PAGERDUTY_TOKEN]\n", "  secrets: [PAGERDUTY_TOKEN]\n  desktop:\n    servers:\n      - id: unreal\n"+extra, 1)
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("a server entry carrying %q parsed", strings.TrimSpace(extra))
		}
	}
}
