package scan

import (
	"context"
	"strings"
	"testing"
)

// The token-shaped values below are assembled at run time so the source
// carries no token-shaped literal (the repository's gitleaks scan is part
// of its open-source posture, agentry#209); the corpus fixtures, which
// are allowlisted, carry the literal ones.
func fakeProjectKey() string { return "sk-pr" + "oj-72s8FYVEEdGBOTbDNWDl7EkFSZu8LWWhZ6xuiz9Mxl6EEQA1" }
func fakeHexToken() string   { return "f7ef114b9c1a75ec" + "175c9ed6bfb65ecb227fc477" }
func fakePrefixedPAT() string {
	return "gh" + "p_corpusfixturenotarealtokenxxxxxxxxxx"
}

// TestEnvTokenShaped pins the token shape against the configuration
// values a declared server plausibly carries (agentry#288): the shape must
// see a bare credential and stay quiet on paths, URLs, names and ids.
func TestEnvTokenShaped(t *testing.T) {
	cases := map[string]bool{
		fakeProjectKey(): true,
		fakeHexToken():   true, // bare hex
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c": true, // a JWT
		"postgres://app:s3cr3t@db.internal/app":    true, // a password in a URL
		"read-only":                                false,
		"https://api.github.com/graphql":           false,
		"https://user@api.github.com/graphql":      false, // a user without a password
		"/var/lib/agentry/cache/issue-digest/logs": false,
		"../relative/path/with/digits/2026":        false,
		"America/Los_Angeles":                      false,
		"claude-sonnet-5-20260514":                 false,
		"2026-09-14T00:00:00Z":                     false,
		"sha256:ec62905f587d96dfd00710de3a9cbe8bde00212850f6524532fc1be2ac9d4421": false,
		"01a0a055-be73-77f3-9757-271d173115ce":                                    false, // uuid: runs of at most 12
		"list_issues,get_issue,search_issues,list_pull_requests":                  false, // no digits
		"Summarize the open issues of one repository":                             false, // prose
		"xxxxxxxxxxxxxxxxxxxx1":                                                   false, // a run with no entropy
		"120000":                                                                  false,
	}
	for v, want := range cases {
		if got := envTokenShaped(v); got != want {
			t.Errorf("envTokenShaped(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestEnvSecretNamed(t *testing.T) {
	for key, want := range map[string]bool{
		"GITHUB_TOKEN": true, "OPENAI_API_KEY": true, "AWS_SECRET_ACCESS_KEY": true, "DB_PASSWORD": true,
		"client_secret": true, "SMTP_PASSWD": true, "GCP_CREDENTIALS": true,
		"TOKEN_BUDGET": false, "GITHUB_TOKEN_FILE": false, "PASSWORD_POLICY": false, "SORT_KEY": false,
		"AUTH_MODE": false, "GITHUB_PERMISSION": false,
	} {
		if got := envSecretNamed(key); got != want {
			t.Errorf("envSecretNamed(%q) = %v, want %v", key, got, want)
		}
	}
}

// s2ManifestFixture builds the manifest JSON and a matching agent.yaml
// with two declared servers. The first carries a prefixed token, a bare
// one, a switch and a short punctuated password; the second reuses a key
// name of the first, so the line lookup must resolve per entry.
func s2ManifestFixture() (string, string) {
	yamlText := `schemaVersion: "2"
name: issue-digest
namespace: acme
capabilities:
  mcpServers:
    - npm: github-mcp-server-js
      version: 0.1.7
      env:
        GITHUB_PERMISSION: read-only
        GITHUB_TOKEN: ` + fakePrefixedPAT() + `
        LOGS_DIR: ` + fakeHexToken() + `
        API_KEY: none
        DB_PASSWORD: p@ss.w0rd!1
    - pypi: other-server
      version: 2.0.0
      env: {"LOGS_DIR": "/tmp/logs", "SECRET": "` + fakeHexToken() + `"}
`
	jsonText := `{"schemaVersion":"2","capabilities":{"mcpServers":[` +
		`{"npm":"github-mcp-server-js","version":"0.1.7","env":{"GITHUB_PERMISSION":"read-only","GITHUB_TOKEN":"` + fakePrefixedPAT() + `","LOGS_DIR":"` + fakeHexToken() + `","API_KEY":"none","DB_PASSWORD":"p@ss.w0rd!1"}},` +
		`{"pypi":"other-server","version":"2.0.0","env":{"LOGS_DIR":"/tmp/logs","SECRET":"` + fakeHexToken() + `"}}]}}`
	return yamlText, jsonText
}

// TestS2ManifestEnv runs S2 over the fixture: the prefix rule keeps its
// finding and the manifest pass adds exactly the name finding for the
// prefixed token, the value finding for the bare one, nothing for the
// switch, the name finding for the password, and both for the second
// server's SECRET — each at its own line, none carrying a value.
func TestS2ManifestEnv(t *testing.T) {
	yamlText, jsonText := s2ManifestFixture()
	in := &Input{
		ManifestJSON: []byte(jsonText),
		Files:        []FileEntry{{Path: "agent.yaml", IsText: true, Content: []byte(yamlText)}},
	}
	res := S2Secrets{}.Run(stageContext{ctx: context.Background()}, in)
	type at struct {
		scanner string
		key     any
	}
	got := map[at]Finding{}
	for _, f := range res.Findings {
		k := at{f.Scanner, f.Detail["key"]}
		if _, dup := got[k]; dup {
			t.Errorf("duplicate finding %v", k)
		}
		got[k] = f
	}
	want := map[at]int{
		{"S2/github-pat", nil}:                 10,
		{"S2/env-secret-name", "GITHUB_TOKEN"}: 10,
		{"S2/env-token-value", "LOGS_DIR"}:     11,
		{"S2/env-secret-name", "DB_PASSWORD"}:  13,
		{"S2/env-secret-name", "SECRET"}:       16,
		{"S2/env-token-value", "SECRET"}:       16,
	}
	for k, line := range want {
		f, ok := got[k]
		if !ok {
			t.Fatalf("missing %v in %v", k, res.Findings)
		}
		if f.FilePath != "agent.yaml" || f.LineStart != line {
			t.Errorf("%v at %s:%d, want agent.yaml:%d", k, f.FilePath, f.LineStart, line)
		}
		for _, secret := range []string{fakePrefixedPAT()[:12], fakeHexToken()[:12], "p@ss.w0rd!1", "w0rd"} {
			if strings.Contains(f.Excerpt, secret) || strings.Contains(f.Title, secret) {
				t.Errorf("%v leaks the value: %q / %q", k, f.Title, f.Excerpt)
			}
		}
	}
	if len(got) != len(want) {
		t.Errorf("findings = %v, want exactly %v", res.Findings, want)
	}
	if got[at{"S2/env-secret-name", "SECRET"}].Detail["server"] != "pypi:other-server" {
		t.Errorf("second server's finding names %v", got[at{"S2/env-secret-name", "SECRET"}].Detail["server"])
	}
	if !strings.Contains(got[at{"S2/env-secret-name", "DB_PASSWORD"}].Excerpt, "(11 characters)") {
		t.Errorf("excerpt = %q, want the length only", got[at{"S2/env-secret-name", "DB_PASSWORD"}].Excerpt)
	}
}

// TestS2ManifestEnvWithoutFile: the values are read from the stored
// manifest, so the findings come even when agent.yaml is not among the
// files — then without a line.
func TestS2ManifestEnvWithoutFile(t *testing.T) {
	in := &Input{ManifestJSON: []byte(`{"capabilities":{"mcpServers":[{"pypi":"x","version":"1.0.0","env":{"OPENAI_API_KEY":"` + fakeProjectKey() + `"}}]}}`)}
	res := S2Secrets{}.Run(stageContext{ctx: context.Background()}, in)
	ids := map[string]bool{}
	for _, f := range res.Findings {
		ids[f.Scanner] = true
		if f.FilePath != "" || f.LineStart != 0 {
			t.Errorf("%s names a file without one: %s:%d", f.Scanner, f.FilePath, f.LineStart)
		}
		if f.Detail["server"] != "pypi:x" {
			t.Errorf("%s names server %v, want pypi:x", f.Scanner, f.Detail["server"])
		}
	}
	if !ids["S2/env-secret-name"] || !ids["S2/env-token-value"] || len(ids) != 2 {
		t.Errorf("findings = %v", res.Findings)
	}
}

// TestS2ManifestOAuthValues: an oauth block is rendered into every run, so
// a credential written into it (a real client secret in a template, a
// token in an env value) is the same finding as one in env; the
// placeholders themselves, a path in the token folder and dummy client
// values are not (agentry#910).
func TestS2ManifestOAuthValues(t *testing.T) {
	in := &Input{ManifestJSON: []byte(`{"capabilities":{"mcpServers":[{"npm":"@cocal/google-calendar-mcp","version":"2.7.0","oauth":{` +
		`"issuer":"https://accounts.google.com",` +
		`"files":[{"path":"keys.json","template":"{\"installed\":{\"client_id\":\"agentry\",\"client_secret\":\"` + fakeHexToken() + `\"}}"},` +
		`{"path":"tokens.json","template":"{\"normal\":{\"access_token\":\"{access_token}\",\"expiry_date\":{expiry_ms}}}"}],` +
		`"env":{"GOOGLE_OAUTH_CREDENTIALS":"{dir}/keys.json","GITHUB_TOKEN":"{access_token}","EXTRA":"` + fakeHexToken() + `"}}}]}}`)}
	res := S2Secrets{}.Run(stageContext{ctx: context.Background()}, in)
	keys := map[any]bool{}
	for _, f := range res.Findings {
		if f.Scanner != "S2/oauth-token-value" {
			continue
		}
		keys[f.Detail["key"]] = true
		if f.Detail["server"] != "npm:@cocal/google-calendar-mcp" || f.Severity != SevMedium {
			t.Errorf("finding: %+v", f)
		}
		if strings.Contains(f.Excerpt, fakeHexToken()[:12]) || strings.Contains(f.Title, fakeHexToken()[:12]) {
			t.Errorf("%v leaks the value: %q / %q", f.Detail["key"], f.Title, f.Excerpt)
		}
	}
	if !keys["oauth.files[0]"] || !keys["oauth.env.EXTRA"] || len(keys) != 2 {
		t.Fatalf("oauth findings by key = %v; all: %+v", keys, res.Findings)
	}
}
