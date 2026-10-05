package scan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/pkg/manifest"
	"github.com/blaktron/agentry/pkg/rules"
)

// S2's manifest pass (agentry#288). A declared MCP server's plain `env`
// (DEV-098) is the first manifest field whose values are injected into a
// process, and the line rules need a value quoted or prefixed to notice
// it: an unquoted `OPENAI_API_KEY: sk-proj-…` in YAML gives them nothing.
// So S2 also reads the values out of the manifest the registry stores —
// the contract itself, whatever agent.yaml's spelling — and flags two
// shapes: a key named like a credential carrying a value at all (the
// manifest has `secrets` for that), and a token-shaped value under any
// key. Both are medium: the reviewer decides, the release does not
// auto-publish. The value itself never reaches the report.

// envSecretSuffixes are the key endings that name a credential; a value
// under such a key belongs in `secrets`, not in the contract.
var envSecretSuffixes = []string{
	"TOKEN", "SECRET", "PASSWORD", "PASSWD",
	"API_KEY", "APIKEY", "ACCESS_KEY", "SECRET_KEY", "PRIVATE_KEY",
	"CREDENTIAL", "CREDENTIALS",
}

// envSecretNamedMinLen is the length under a credential-named key from
// which a value is read as a credential rather than a switch: `none`,
// `off` and `false` are switches, and eight characters is the shortest
// password anyone is asked for.
const envSecretNamedMinLen = 8

// envSecretNamed reports whether an env key's name says credential.
func envSecretNamed(key string) bool {
	upper := strings.ToUpper(key)
	for _, suffix := range envSecretSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}

// The token shape: a value of at least envTokenMinLen characters holding
// one run of at least envTokenRunMinLen letters-and-digits with a digit
// and a letter in it and at least envTokenMinH bits of entropy — or a URL
// whose authority carries a password. Timestamps, versions, ids and
// names fail the run (short, or one class); a path or a URL is read as
// configuration by its marker, since its long runs are words.
const (
	envTokenMinLen    = 20
	envTokenRunMinLen = 16
	envTokenMinH      = 3.0
)

var (
	envAlnumRunRE = regexp.MustCompile(`[A-Za-z0-9]+`)
	// envDigestPrefixRE: a content digest is configuration that happens
	// to be hex (an image or archive pin), not a credential.
	envDigestPrefixRE = regexp.MustCompile(`^sha[0-9]+:`)
	// envURLPasswordRE: `scheme://user:password@host` — the one URL shape
	// that is a credential.
	envURLPasswordRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/@:]+:[^/@]+@`)
)

// envTokenShaped reports whether an env value looks like a credential
// rather than configuration.
func envTokenShaped(v string) bool {
	if envURLPasswordRE.MatchString(v) {
		return true
	}
	if len(v) < envTokenMinLen || strings.ContainsAny(v, " \t") {
		return false
	}
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") || strings.HasPrefix(v, "~") ||
		strings.Contains(v, "://") || envDigestPrefixRE.MatchString(v) {
		return false
	}
	for _, run := range envAlnumRunRE.FindAllString(v, -1) {
		if len(run) < envTokenRunMinLen {
			continue
		}
		var digit, letter bool
		for _, r := range run {
			if unicode.IsDigit(r) {
				digit = true
			} else {
				letter = true
			}
		}
		if digit && letter && rules.ShannonEntropy([]byte(run)) >= envTokenMinH {
			return true
		}
	}
	return false
}

// s2ManifestEnv returns the findings over the declared servers' env
// values. lineSeen holds the agent.yaml lines a line rule already flagged
// (a `ghp_…` value is one finding, not two); the name rule is independent
// of it because it says something the prefix rule does not — where the
// value belongs.
func s2ManifestEnv(in *Input, lineSeen map[string]bool) []Finding {
	if len(in.ManifestJSON) == 0 {
		return nil
	}
	var m manifest.Manifest
	if err := json.Unmarshal(in.ManifestJSON, &m); err != nil {
		return nil
	}
	lineOf := envKeyLines(in.Files)
	var findings []Finding
	for i, srv := range m.Capabilities.MCPServers {
		keys := make([]string, 0, len(srv.Env))
		for k := range srv.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := srv.Env[key]
			line := lineOf(i, key)
			if envSecretNamed(key) && len(value) >= envSecretNamedMinLen {
				findings = append(findings, envFinding("env-secret-name",
					"Possible secret in declared env "+key+": named like a credential; declare it under secrets",
					srv, i, key, line))
			}
			if line > 0 && lineSeen["agent.yaml|"+strconv.Itoa(line)] {
				continue
			}
			if envTokenShaped(value) {
				findings = append(findings, envFinding("env-token-value",
					"Possible secret in declared env "+key+": token-shaped value; configuration is literal, a credential is a secret",
					srv, i, key, line))
			}
		}
	}
	for i, srv := range m.Capabilities.MCPServers {
		findings = append(findings, s2ManifestOAuth(i, srv)...)
	}
	return findings
}

// oauthQuotedRE finds the string literals of a template, where a value a
// file carries sits whatever the file's format.
var oauthQuotedRE = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'([^']*)'`)

// s2ManifestOAuth reads a server's oauth block (agentry#910): every env
// value and every quoted value of a template, with the placeholders the
// runner fills taken out, by the same token shape as env. The name rule
// does not apply: a credential-named variable is exactly where the
// placeholder {access_token} belongs.
func s2ManifestOAuth(entry int, srv manifest.MCPServer) []Finding {
	if srv.OAuth == nil {
		return nil
	}
	strip := func(v string) string { return oauthPlaceholderRE.ReplaceAllString(v, "") }
	var out []Finding
	for i, f := range srv.OAuth.Files {
		for _, m := range oauthQuotedRE.FindAllStringSubmatch(f.Template, -1) {
			v := m[1] + m[2]
			if envTokenShaped(strip(v)) {
				out = append(out, oauthFinding(srv, entry, fmt.Sprintf("oauth.files[%d]", i), len(v)))
				break
			}
		}
	}
	keys := make([]string, 0, len(srv.OAuth.Env))
	for k := range srv.OAuth.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := srv.OAuth.Env[k]; envTokenShaped(strip(v)) {
			out = append(out, oauthFinding(srv, entry, "oauth.env."+k, len(v)))
		}
	}
	return out
}

// oauthPlaceholderRE is the runner's placeholder shape (manifest's).
var oauthPlaceholderRE = regexp.MustCompile(`\{[a-z_]+\}`)

func oauthFinding(srv manifest.MCPServer, entry int, key string, n int) Finding {
	return Finding{
		Scanner: "S2/oauth-token-value", Severity: SevMedium, Confidence: ConfMedium,
		Title:    "Possible credential in the oauth block of MCP server " + srv.SourceID() + " (" + key + "): Agentry supplies the token, and a value written here reaches every run",
		Excerpt:  key + ": " + strings.Repeat("*", 8) + " (" + strconv.Itoa(n) + " characters)",
		Detail:   map[string]any{"rule": "oauth-token-value", "server": srv.SourceID(), "key": key, "entry": entry},
		Taxonomy: []string{"LLM03"},
	}
}

// envFinding shapes one manifest-pass finding. The excerpt names the key
// and the value's length only: the value is the thing that must not
// appear in a report, and the line rules' mask does not cover every
// shape a short password takes.
func envFinding(rule, title string, srv manifest.MCPServer, entry int, key string, line int) Finding {
	f := Finding{
		Scanner: "S2/" + rule, Severity: SevMedium, Confidence: ConfMedium,
		Title:    title,
		Excerpt:  key + ": " + strings.Repeat("*", 8) + " (" + strconv.Itoa(len(srv.Env[key])) + " characters)",
		Detail:   map[string]any{"rule": rule, "server": srv.SourceID(), "key": key, "entry": entry},
		Taxonomy: []string{"LLM03"},
	}
	if line > 0 {
		f.FilePath, f.LineStart, f.LineEnd = "agent.yaml", line, line
	}
	return f
}

// envKeyLines parses agent.yaml once and returns the 1-based line of
// `capabilities.mcpServers[entry].env.<key>`, or 0 when the file is not
// among the inventory, does not parse, or has no such key — which is what
// a flow-style or quoted spelling still resolves, because the node tree,
// not a text search, answers.
func envKeyLines(files []FileEntry) func(entry int, key string) int {
	none := func(int, string) int { return 0 }
	var root yaml.Node
	for _, f := range files {
		if f.Path != "agent.yaml" || !f.IsText || f.Content == nil {
			continue
		}
		if yaml.Unmarshal(f.Content, &root) != nil {
			return none
		}
		break
	}
	doc := &root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = doc.Content[0]
	}
	servers := yamlMappingValue(yamlMappingValue(doc, "capabilities"), "mcpServers")
	if servers == nil || servers.Kind != yaml.SequenceNode {
		return none
	}
	return func(entry int, key string) int {
		if entry >= len(servers.Content) {
			return 0
		}
		env := yamlMappingValue(servers.Content[entry], "env")
		if env == nil || env.Kind != yaml.MappingNode {
			return 0
		}
		for i := 0; i+1 < len(env.Content); i += 2 {
			if env.Content[i].Value == key {
				return env.Content[i].Line
			}
		}
		return 0
	}
}

// yamlMappingValue returns the value node under key in a mapping node,
// or nil.
func yamlMappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
