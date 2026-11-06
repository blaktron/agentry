package appserver

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestTheBlenderEntryIsTheVettedServerAtItsPin(t *testing.T) {
	b, ok := Builtin().Lookup("blender")
	if !ok {
		t.Fatal("the catalogue has no blender entry")
	}
	if b.Application != "Blender" || b.Attachment != AttachmentStdio || b.Package.Ref() != "pypi:mcp-for-blender@2.2.7" {
		t.Fatalf("blender is %s, %s, %s", b.Application, b.Attachment, b.Package.Ref())
	}
	if want := []string{"uvx", "mcp-for-blender==2.2.7"}; !slices.Equal(b.Launch.Command, want) {
		t.Fatalf("launch %q, want %q", b.Launch.Command, want)
	}
	if want := map[string]string{"DISABLE_TELEMETRY": "true", "BLENDER_MCP_SAFE_MODE": "1"}; !maps.Equal(b.Launch.Env, want) {
		t.Fatalf("launch environment %v, want %v", b.Launch.Env, want)
	}
	if b.Listener.Port != 9876 {
		t.Fatalf("listener port %d, want the add-on's 9876", b.Listener.Port)
	}
	classes := map[string]Class{}
	for _, tool := range b.Tools {
		classes[tool.Name] = tool.Class
	}
	want := map[string]Class{
		"execute_blender_code": ClassExec,
		"generate_3d":          ClassAct, "import_asset": ClassAct,
		"search_assets": ClassRead, "look": ClassRead, "get_scene_info": ClassRead, "get_addon_status": ClassRead,
	}
	if !maps.Equal(classes, want) {
		t.Fatalf("tool classes %v, want %v", classes, want)
	}
	for _, off := range []string{"disable_telemetry", "record_trajectory_feedback"} {
		if _, given := b.Tool(off); given || !slices.Contains(b.Withheld, off) {
			t.Fatalf("%s is given to a run or not withheld", off)
		}
	}
	for _, host := range []string{"api.polyhaven.com", "api.sketchfab.com", "hyperhuman.deemos.com"} {
		if !slices.Contains(b.Egress, host) {
			t.Fatalf("egress %v lacks %s, which the asset and generation tools reach", b.Egress, host)
		}
	}
	for _, name := range []string{"generate_3d", "import_asset", "search_assets"} {
		if tool, _ := b.Tool(name); !tool.Egress {
			t.Fatalf("%s reaches the egress hosts and is not marked so", name)
		}
	}
}

func TestEveryEntryClassesEveryToolFromTheClosedSet(t *testing.T) {
	for _, e := range Builtin().All() {
		for _, tool := range e.Tools {
			if !slices.Contains(Classes(), tool.Class) {
				t.Errorf("%s: tool %s has class %q", e.ID, tool.Name, tool.Class)
			}
		}
	}
	for _, class := range []string{"", "admin", "READ", "write"} {
		doc := strings.Replace(validDoc, "class: exec", "class: "+class, 1)
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("a tool of class %q was accepted", class)
		}
	}
}

func TestAnEntryWithoutAnExactPinIsRefused(t *testing.T) {
	for name, doc := range map[string]string{
		"no version":              strings.Replace(validDoc, "version: 1.2.3", `version: ""`, 1),
		"a range":                 strings.Replace(validDoc, "version: 1.2.3", `version: ">=1.2"`, 1),
		"a wildcard":              strings.Replace(validDoc, "version: 1.2.3", `version: "1.*"`, 1),
		"latest":                  strings.Replace(validDoc, "version: 1.2.3", "version: latest", 1),
		"a launch without it":     strings.Replace(validDoc, "[uvx, example-mcp==1.2.3]", "[uvx, example-mcp]", 1),
		"a launch at another one": strings.Replace(validDoc, "[uvx, example-mcp==1.2.3]", "[uvx, example-mcp==1.2.4]", 1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(validDoc)); err != nil {
		t.Fatalf("the valid document: %v", err)
	}
}

func TestTheCatalogueRefusesWhatItCannotVouchFor(t *testing.T) {
	for name, doc := range map[string]string{
		"an unknown field":          strings.Replace(validDoc, "    attachment: stdio\n", "    attachment: stdio\n    shell: true\n", 1),
		"no catalogue version":      strings.Replace(validDoc, "version: 1\n", "", 1),
		"a malformed id":            strings.Replace(validDoc, "id: example", "id: Example_App", 1),
		"an unknown ecosystem":      strings.Replace(validDoc, "ecosystem: pypi", "ecosystem: cargo", 1),
		"an http source":            strings.Replace(validDoc, "https://example.com/src", "http://example.com/src", 1),
		"an unknown attachment":     strings.Replace(validDoc, "attachment: stdio", "attachment: tcp", 1),
		"an unknown platform":       strings.Replace(validDoc, "[linux]", "[plan9]", 1),
		"a port out of range":       strings.Replace(validDoc, "port: 9000", "port: 70000", 1),
		"a tool listed twice":       strings.Replace(validDoc, "{name: read_thing, class: read}", "{name: run_code, class: read}", 1),
		"a tool given and withheld": strings.Replace(validDoc, "[hidden_tool]", "[read_thing]", 1),
		"an address as egress":      strings.Replace(validDoc, "[api.example.com]", "[127.0.0.1]", 1),
		"a wildcard as egress":      strings.Replace(validDoc, "[api.example.com]", `["*.example.com"]`, 1),
		"no steps":                  strings.Replace(validDoc, "steps: [Install it.]", "steps: []", 1),
		"no tools": strings.Replace(validDoc, "      - {name: run_code, class: exec}\n      - {name: read_thing, class: read}\n",
			"      []\n", 1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestALoopbackServerIsReachedOnLoopbackAlone(t *testing.T) {
	loopback := strings.NewReplacer(
		"attachment: stdio", "attachment: loopback-http",
		"    launch:\n      command: [uvx, example-mcp==1.2.3]\n", "    endpoint: http://127.0.0.1:8000/mcp\n",
	).Replace(validDoc)
	if _, err := Parse([]byte(loopback)); err != nil {
		t.Fatalf("a loopback endpoint: %v", err)
	}
	for _, endpoint := range []string{"http://localhost:8000/mcp", "http://192.168.1.5:8000/mcp", "https://127.0.0.1:8000/mcp", "http://u@127.0.0.1:8000/mcp"} {
		doc := strings.Replace(loopback, "http://127.0.0.1:8000/mcp", endpoint, 1)
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("endpoint %s was accepted", endpoint)
		}
	}
}

// A step that names the server's release names the pinned one.
func TestTheStepsNameThePinnedRelease(t *testing.T) {
	for _, e := range Builtin().All() {
		re := regexp.MustCompile(regexp.QuoteMeta(e.Package.Name) + `(==|@)([0-9][^\s,]*)`)
		for _, step := range e.Steps {
			for _, m := range re.FindAllStringSubmatch(step, -1) {
				if m[2] != e.Package.Version {
					t.Errorf("%s: a step names %s, the pin is %s", e.ID, m[0], e.Package.Version)
				}
			}
		}
	}
}

func TestLookupHandsOutACopy(t *testing.T) {
	a, _ := Builtin().Lookup("blender")
	a.Tools[0].Class = ClassRead
	a.Launch.Env["BLENDER_MCP_SAFE_MODE"] = "0"
	b, _ := Builtin().Lookup("blender")
	if b.Tools[0].Class == ClassRead && b.Tools[0].Name == "execute_blender_code" {
		t.Fatal("a caller's change reached the catalogue's tool classes")
	}
	if b.Launch.Env["BLENDER_MCP_SAFE_MODE"] != "1" {
		t.Fatal("a caller's change reached the catalogue's launch environment")
	}
}

const validDoc = `version: 1
servers:
  - id: example
    application: Example
    platforms: [linux]
    server:
      ecosystem: pypi
      name: example-mcp
      version: 1.2.3
      source: https://example.com/src
    attachment: stdio
    launch:
      command: [uvx, example-mcp==1.2.3]
    listener:
      port: 9000
    tools:
      - {name: run_code, class: exec}
      - {name: read_thing, class: read}
    withheld: [hidden_tool]
    egress: [api.example.com]
    steps: [Install it.]
`
