package config

import (
	"strings"
	"testing"
)

// brand.name, else the public host, else "Agentry" (DEV-091).
func TestDisplayName(t *testing.T) {
	if got := (Config{}).DisplayName(); got != "Agentry" {
		t.Fatalf("empty: %q", got)
	}
	if got := (Config{BaseURL: "https://reg.example/"}).DisplayName(); got != "reg.example" {
		t.Fatalf("host: %q", got)
	}
	if got := (Config{BaseURL: "https://reg.example", Brand: Brand{Name: "Acme"}}).DisplayName(); got != "Acme" {
		t.Fatalf("brand: %q", got)
	}
}

func TestValidateUIAndWeb(t *testing.T) {
	c := Default()
	c.UI.Mode = "sideways"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ui.mode") {
		t.Fatalf("ui.mode: %v", err)
	}
	c = Default()
	c.Web.URL = "site.example/path?x"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "web.url") {
		t.Fatalf("web.url: %v", err)
	}
	c = Default()
	c.Web.URL = "https://site.example"
	c.UI.Mode = "authorize"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
}
