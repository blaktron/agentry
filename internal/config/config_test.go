package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent-means-defaults-only.yaml"))
	if err == nil {
		t.Fatalf("expected error for explicit missing file")
	}
	// Empty path with no agentry.yaml in cwd yields pure defaults.
	cfg, err = Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "dev" || !cfg.DevMode {
		t.Errorf("defaults wrong: %+v", cfg)
	}
	if cfg.HTTP.Addr != ":8080" {
		t.Errorf("default addr: %q", cfg.HTTP.Addr)
	}
}

func TestLoadFileAndEnvPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentry.yaml")
	if err := os.WriteFile(path, []byte("env: staging\ndevMode: false\nhttp:\n  addr: \":9999\"\nlog:\n  level: debug\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTRY_HTTP_ADDR", ":7777")
	t.Setenv("AGENTRY_AUTH_SESSION_TTL", "8h")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "staging" {
		t.Errorf("file value lost: env=%q", cfg.Env)
	}
	if cfg.HTTP.Addr != ":7777" {
		t.Errorf("env must override file: addr=%q", cfg.HTTP.Addr)
	}
	if cfg.Auth.SessionTTL != 8*time.Hour {
		t.Errorf("duration env: %v", cfg.Auth.SessionTTL)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("nested file value: %q", cfg.Log.Level)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentry.yaml")
	if err := os.WriteFile(path, []byte("bogusKey: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown config keys must be rejected")
	}
}

func TestValidateGuards(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"prod devMode", func(c *Config) { c.Env = "prod"; c.DevMode = true }},
		{"prod unsigned", func(c *Config) { c.Env = "prod"; c.DevMode = false; c.Signing.Kind = "none" }},
		{"bad env", func(c *Config) { c.Env = "yolo" }},
		{"bad storage", func(c *Config) { c.Storage.Kind = "ftp" }},
		{"bad judge", func(c *Config) { c.Judge.Provider = "gpt" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}
