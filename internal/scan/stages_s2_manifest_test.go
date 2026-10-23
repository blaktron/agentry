package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The token-shaped values below are assembled at run time so the source
// carries no token-shaped literal (the repository's gitleaks scan covers
// the source); the corpus fixtures, which
// are allowlisted, carry the literal ones.
func fakeProjectKey() string { return "sk-pr" + "oj-72s8FYVEEdGBOTbDNWDl7EkFSZu8LWWhZ6xuiz9Mxl6EEQA1" }
func fakeHexToken() string   { return "f7ef114b9c1a75ec" + "175c9ed6bfb65ecb227fc477" }
func fakePrefixedPAT() string {
	return "gh" + "p_corpusfixturenotarealtokenxxxxxxxxxx"
}

// fakeShapedPAT is a prefixed token whose characters also make it token-shaped
// as an env value (the one above has no digit).
func fakeShapedPAT() string { return "gh" + "p_a1B2c3D4e5F6g7H8i9J0" + "k1L2m3N4o5P6q7R8" }

// TestEnvTokenShaped pins the token shape against the configuration
// values a declared server plausibly carries: the shape must
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
		// The length floor is 20 characters, the run floor 16 characters of
		// letters and digits, and the entropy floor 3 bits.
		"a1b2c3d4e5f6g7h8i9j":  false, // 19 characters
		"a1b2c3d4e5f6g7h8i9j0": true,  // 20 characters
		"a1b2c3d4e5f6g7h8.xyz": true,  // a run of 16
		"a1b2c3d4e5f6g7h.wxyz": false, // a run of 15
		"a1b2c3d4a1b2c3d4.xyz": true,  // a run of exactly 3 bits
		"a1b2c3da1b2c3da4.xyz": false, // a run of just under 3 bits
		// A run needs both a letter and a digit.
		"abcdefghijklmnopqrstuvwx": false,
		"1234567890123456789012":   false,
		// Prose is not a credential, whichever whitespace separates it.
		"a1b2c3d4e5f6g7h8i9j0 here":  false,
		"a1b2c3d4e5f6g7h8i9j0\there": false,
		// Paths, URLs and digests are configuration by their marker.
		"/a1b2c3d4e5f6g7h8i9j0xyz":                      false,
		"./a1b2c3d4e5f6g7h8i9j0xyz":                     false,
		"../a1b2c3d4e5f6g7h8i9j0xyz":                    false,
		"~a1b2c3d4e5f6g7h8i9j0xyz":                      false,
		"scheme://a1b2c3d4e5f6g7h8i9j0xyz/path":         false,
		"sha1:a1b2c3d4e5f6g7h8i9j0xyz":                  false,
		"postgres://app:@db.internal/app":               false, // no password
		"postgres://app:pw@db.internal/app":             true,
		"postgres://a1b2c3d4e5f6g7h8i9j0xyz@db.example": false, // a user, not a password
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
		// every suffix, in any case
		"OPENAI_APIKEY": true, "APP_SECRET_KEY": true, "SSH_PRIVATE_KEY": true, "GCP_CREDENTIAL": true,
		"api_key": true, "db_password": true, "Access_Key": true, "MY_TOKEN": true, "my_secret": true,
		"KEY": false, "PRIVATE": false, "CREDENTIALED": false, "TOKENS": false,
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

	// The excerpt names the key, masks the value and gives the value's length
	// (the key's is another number); the finding is medium, names the server's
	// place in the manifest, and the whole pass keeps a fixed order: the
	// prefix rule's line finding first, then each server's keys sorted.
	if want := "SECRET: ******** (40 characters)"; got[at{"S2/env-secret-name", "SECRET"}].Excerpt != want || got[at{"S2/env-token-value", "SECRET"}].Excerpt != want {
		t.Errorf("excerpts = %q / %q, want %q", got[at{"S2/env-secret-name", "SECRET"}].Excerpt, got[at{"S2/env-token-value", "SECRET"}].Excerpt, want)
	}
	for k, f := range got {
		if k.scanner == "S2/github-pat" {
			continue
		}
		wantEntry := 0
		if k.key == "SECRET" {
			wantEntry = 1
		}
		if f.Severity != SevMedium || f.Confidence != ConfMedium || f.Detail["entry"] != wantEntry {
			t.Errorf("%v: %s %s entry %v, want medium/medium entry %d", k, f.Severity, f.Confidence, f.Detail["entry"], wantEntry)
		}
	}
	var order []string
	for _, f := range res.Findings {
		order = append(order, fmt.Sprintf("%s:%v", f.Scanner, f.Detail["key"]))
	}
	wantOrder := []string{"S2/github-pat:<nil>", "S2/env-secret-name:DB_PASSWORD", "S2/env-secret-name:GITHUB_TOKEN", "S2/env-token-value:LOGS_DIR", "S2/env-secret-name:SECRET", "S2/env-token-value:SECRET"}
	if strings.Join(order, " ") != strings.Join(wantOrder, " ") {
		t.Errorf("findings in order %v, want %v", order, wantOrder)
	}

	// A prefixed token that is also token-shaped, under a key that is not
	// named like a credential, is the prefix rule's finding on its line and
	// not a second one from the manifest pass.
	pat := fakeShapedPAT()
	yaml2 := "schemaVersion: \"2\"\nname: x\ncapabilities:\n  mcpServers:\n    - npm: other\n      version: 1.0.0\n      env:\n        RELEASE_REF: " + pat + "\n"
	json2 := `{"schemaVersion":"2","capabilities":{"mcpServers":[{"npm":"other","version":"1.0.0","env":{"RELEASE_REF":"` + pat + `"}}]}}`
	res2 := S2Secrets{}.Run(stageContext{ctx: context.Background()}, &Input{
		ManifestJSON: []byte(json2),
		Files:        []FileEntry{{Path: "agent.yaml", IsText: true, Content: []byte(yaml2)}},
	})
	if len(res2.Findings) != 1 || res2.Findings[0].Scanner != "S2/github-pat" || res2.Findings[0].LineStart != 8 {
		t.Errorf("a prefixed, token-shaped value: %+v", res2.Findings)
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

	// A credential-named key carries a credential from 8 characters; shorter
	// values are switches ("none", "off").
	for _, tc := range []struct {
		value string
		named bool
	}{{"abcdefg", false}, {"abcdefgh", true}, {"none", false}} {
		in := &Input{ManifestJSON: []byte(`{"capabilities":{"mcpServers":[{"pypi":"x","version":"1.0.0","env":{"DB_PASSWORD":"` + tc.value + `"}}]}}`)}
		got := findScanner(S2Secrets{}.Run(stageContext{ctx: context.Background()}, in).Findings, "S2/env-secret-name")
		if (len(got) == 1) != tc.named || len(got) > 1 {
			t.Errorf("DB_PASSWORD=%q: %d name findings, want named=%v", tc.value, len(got), tc.named)
		}
	}
}

// TestS2ManifestOAuthValues: an oauth block is rendered into every run, so
// a credential written into it (a real client secret in a template, a
// token in an env value) is the same finding as one in env; the
// placeholders themselves, a path in the token folder and dummy client
// values are not.
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

	// Each finding is placed by the file's index and the variable's name, in
	// that order and by name, on the server it belongs to (the second one
	// here), and reports the length of the value, never the value. A path
	// after a colon is a path, and so no credential.
	tpl := `{"installed":{"client_secret":"` + fakeHexToken() + `"}}`
	jsonTpl, err := json.Marshal(tpl)
	if err != nil {
		t.Fatal(err)
	}
	in = &Input{ManifestJSON: []byte(`{"capabilities":{"mcpServers":[{"npm":"first","version":"1.0.0"},{"npm":"second","version":"2.0.0","oauth":{` +
		`"issuer":"https://accounts.example.com",` +
		`"files":[{"path":"a.json","template":"{access_token}"},{"path":"b.json","template":"{expiry_ms}"},{"path":"c.json","template":` + string(jsonTpl) + `}],` +
		`"env":{"ZED":"` + fakeHexToken() + `","ALPHA":"` + fakeHexToken() + `","TANGO":"` + fakeHexToken() + `","CHARLIE":"` + fakeHexToken() + `","MIKE":"` + fakeHexToken() + `","OK":"{dir}/keys.json","PATHISH":"dir:/var/cache/a1b2c3d4e5f6g7h8i9j0xyz"}}}]}}`)}
	var got []Finding
	for _, f := range (S2Secrets{}).Run(stageContext{ctx: context.Background()}, in).Findings {
		if f.Scanner == "S2/oauth-token-value" {
			got = append(got, f)
		}
	}
	var order []string
	for _, f := range got {
		order = append(order, f.Detail["key"].(string))
		if f.Detail["entry"] != 1 || f.Detail["server"] != "npm:second" || f.Severity != SevMedium || f.Confidence != ConfMedium {
			t.Errorf("%v: %s %s on entry %v server %v", f.Detail["key"], f.Severity, f.Confidence, f.Detail["entry"], f.Detail["server"])
		}
	}
	if want := "oauth.files[2] oauth.env.ALPHA oauth.env.CHARLIE oauth.env.MIKE oauth.env.TANGO oauth.env.ZED"; strings.Join(order, " ") != want {
		t.Fatalf("oauth findings in order %v, want %s", order, want)
	}
	if want := fmt.Sprintf("oauth.files[2]: ******** (%d characters)", len(tpl)); got[0].Excerpt != want {
		t.Errorf("excerpt = %q, want %q", got[0].Excerpt, want)
	}
	if want := fmt.Sprintf("oauth.env.ALPHA: ******** (%d characters)", len(fakeHexToken())); got[1].Excerpt != want {
		t.Errorf("excerpt = %q, want %q", got[1].Excerpt, want)
	}
}

// TestS2ManifestArgs: a package server's args are read by env's two
// rules. A credential flag's value is named, whether it follows `=` or
// stands as the next argument; a token-shaped value is found under any
// flag or alone; a plain flag, a short switch under a credential flag and
// a flag after a bare credential flag are configuration. Each finding
// names the argument's position and the value's length, never the value.
func TestS2ManifestArgs(t *testing.T) {
	args := []string{
		"mcp",                              // 0: a subcommand
		"--api-key=" + fakeHexToken()[:10], // 1: a credential flag's value
		"--token",                          // 2: a bare credential flag...
		"hunter22hunter",                   // 3: ...and its value
		"--workspace=" + fakeHexToken(),    // 4: token-shaped under a plain flag
		fakeHexToken(),                     // 5: token-shaped alone
		"--password",                       // 6: a bare credential flag...
		"--read-only",                      // 7: ...followed by a flag, not a value
		"--secret-key=off",                 // 8: a short switch
		"--log-file=/var/lib/agentry/cache/a1b2c3d4e5f6g7h8i9j0/log", // 9: a path
	}
	raw, err := json.Marshal(map[string]any{"capabilities": map[string]any{"mcpServers": []any{
		map[string]any{"npm": "first", "version": "1.0.0"},
		map[string]any{"pypi": "second", "version": "2.0.0", "args": args},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range (S2Secrets{}).Run(stageContext{ctx: context.Background()}, &Input{ManifestJSON: raw}).Findings {
		if !strings.HasPrefix(f.Scanner, "S2/args-") {
			continue
		}
		key := f.Detail["key"].(string)
		got[key] = f.Scanner
		if f.Detail["entry"] != 1 || f.Detail["server"] != "pypi:second" || f.Severity != SevMedium {
			t.Errorf("%s: %+v", key, f)
		}
		if strings.Contains(f.Excerpt, fakeHexToken()[:10]) || strings.Contains(f.Title, fakeHexToken()[:10]) || strings.Contains(f.Excerpt, "hunter22") {
			t.Errorf("%s leaks the value: %q / %q", key, f.Title, f.Excerpt)
		}
	}
	want := map[string]string{
		"args[1]": "S2/args-secret-name",
		"args[3]": "S2/args-secret-name",
		"args[4]": "S2/args-token-value",
		"args[5]": "S2/args-token-value",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("args findings = %v, want %v", got, want)
	}
}
