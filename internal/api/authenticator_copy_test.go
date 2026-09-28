package api

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// What the directory enrols (a TOTP app, a security key) is an
// *authenticator*; a *device* in this estate is a remembered browser, the
// credential that skips the second factor (DEV-123, DEV-163). The words were
// split so the settings page no longer shows "devices" twice with two
// meanings (agentry#466). The routes, the `devices` fields and the operation
// id keep their names, since clients depend on them; only the prose moved.
// This keeps the prose from drifting back.

var deviceWordRe = regexp.MustCompile(`(?i)\bdevices?\b`)

// clientIdentifiersRe matches the names clients depend on, which keep "device".
var clientIdentifiersRe = regexp.MustCompile("`[^`]*`|/user/directory/devices/\\{kind\\}/\\{deviceId\\}")

func TestEnrolledAuthenticatorProseSaysAuthenticator(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths      map[string]yaml.Node `yaml:"paths"`
		Components struct {
			Schemas map[string]yaml.Node `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]yaml.Node{
		"GET /user/directory":            spec.Paths["/user/directory"],
		"DELETE /user/directory/devices": spec.Paths["/user/directory/devices/{kind}/{deviceId}"],
		"schema UserDirectory":           spec.Components.Schemas["UserDirectory"],
	}
	for where, n := range nodes {
		if n.Kind == 0 {
			t.Fatalf("the spec has no %s", where)
		}
		for _, text := range prose(&n) {
			if deviceWordRe.MatchString(clientIdentifiersRe.ReplaceAllString(text, "")) {
				t.Errorf("%s says device for an authenticator: %q", where, text)
			}
		}
	}

	page, err := os.ReadFile("../ui/templates/account.html")
	if err != nil {
		t.Fatal(err)
	}
	visible := regexp.MustCompile(`\{\{.*?\}\}|<[^>]*>`).ReplaceAllString(string(page), " ")
	for _, line := range strings.Split(visible, "\n") {
		if deviceWordRe.MatchString(line) {
			t.Errorf("the account page says device: %q", strings.TrimSpace(line))
		}
	}
}

// prose collects every summary and description under n.
func prose(n *yaml.Node) []string {
	var out []string
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k, v := n.Content[i].Value, n.Content[i+1]; (k == "summary" || k == "description") && v.Kind == yaml.ScalarNode {
				out = append(out, v.Value)
			}
		}
	}
	for _, c := range n.Content {
		out = append(out, prose(c)...)
	}
	return out
}
