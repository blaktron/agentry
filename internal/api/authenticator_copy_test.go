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
// credential that skips the second factor. The settings page must not
// show "devices" twice with two meanings. The routes, the `devices`
// fields and the operation id keep their names, since clients depend on
// them; only the prose uses the distinction. This keeps the prose from
// drifting back.

var (
	deviceWordRe       = regexp.MustCompile(`(?i)\bdevices?\b`)
	rememberedDeviceRe = regexp.MustCompile(`(?i)\bremembered devices?\b`)
)

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
		for _, text := range specProse(&n) {
			if deviceWordRe.MatchString(clientIdentifiersRe.ReplaceAllString(text, "")) {
				t.Errorf("%s says device for an authenticator: %q", where, text)
			}
		}
	}

	page, err := os.ReadFile("../ui/templates/account.html")
	if err != nil {
		t.Fatal(err)
	}
	// What a reader sees or hears: the text between tags, and the labels
	// inside them. A remembered device is the right word for that
	// credential, should the page ever list them.
	html := regexp.MustCompile(`\{\{.*?\}\}`).ReplaceAllString(string(page), " ")
	var heard []string
	for _, m := range regexp.MustCompile(`(?:title|aria-label|placeholder)="([^"]*)"`).FindAllStringSubmatch(html, -1) {
		heard = append(heard, m[1])
	}
	text := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(html, "\n")
	for _, line := range append(strings.Split(text, "\n"), heard...) {
		if deviceWordRe.MatchString(rememberedDeviceRe.ReplaceAllString(line, "")) {
			t.Errorf("the account page says device for an authenticator: %q", strings.TrimSpace(line))
		}
	}
}

// specProse collects every summary and description under n.
func specProse(n *yaml.Node) []string {
	var out []string
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k, v := n.Content[i].Value, n.Content[i+1]; (k == "summary" || k == "description") && v.Kind == yaml.ScalarNode {
				out = append(out, v.Value)
			}
		}
	}
	for _, c := range n.Content {
		out = append(out, specProse(c)...)
	}
	return out
}
