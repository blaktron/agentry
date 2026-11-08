package manifest

import (
	"strings"
	"testing"
)

// TestParseErrorsSpeakTheManifestsTerms: a field the manifest does not take,
// and a value of the wrong shape, are reported with the line, the block, the
// shape expected and the nearest field name, never a Go type name.
func TestParseErrorsSpeakTheManifestsTerms(t *testing.T) {
	cases := []struct{ doc, want string }{
		{"schemaVersion: \"2\"\nname: a\nlicence: MIT\n", `line 3: the manifest has no field "licence" (did you mean "license"?)`},
		{"schemaVersion: \"2\"\ncapabilities:\n  network:\n    egres: none\n", `line 4: capabilities.network has no field "egres" (did you mean "egress"?)`},
		{"schemaVersion: \"2\"\nname: a\nmodes: autonomous\n", `line 3: expected a list`},
		{"schemaVersion: \"2\"\nname: [a]\n", "line 2: expected text, found a list"},
		{"schemaVersion: \"2\"\nintake:\n  - id: x\n    required: maybe\n", `line 4: expected true or false, found text ("maybe")`},
		{"schemaVersion: \"2\"\nzzzzzzzz: 1\n", `the manifest has no field "zzzzzzzz"`},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got %v, want it to contain %q", c.doc, err, c.want)
			continue
		}
		if goTypeRE.MatchString(strings.TrimPrefix(err.Error(), "manifest: agent.yaml")) {
			t.Errorf("%q: the error names a Go type: %v", c.doc, err)
		}
	}
	if _, err := Parse([]byte("schemaVersion: \"2\"\nzzzzzzzz: 1\n")); err != nil && strings.Contains(err.Error(), "did you mean") {
		t.Errorf("a key unlike every field got a suggestion: %v", err)
	}
}

// TestEveryManifestBlockHasAPath: each struct type the manifest decodes is
// named by its YAML path, so an unknown field in it is reported there.
func TestEveryManifestBlockHasAPath(t *testing.T) {
	for name := range manifestTypes() {
		block, fields := blockOf("manifest." + name)
		if strings.Contains(block, "manifest.") || strings.Contains(block, "[]") && !strings.Contains(block, ".") {
			t.Errorf("%s: block %q", name, block)
		}
		msg := typeErrorMessage("line 1: field x not found in type manifest." + name)
		if strings.Contains(msg, "manifest."+name) {
			t.Errorf("%s: message names the type: %s", name, msg)
		}
		_ = fields
	}
	if p := blockPaths()["Network"]; p != "capabilities.network" {
		t.Errorf("Network's path = %q", p)
	}
}
