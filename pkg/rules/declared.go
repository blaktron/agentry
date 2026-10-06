package rules

// declared.go rates the S4 hits of the capability families by what the
// release's manifest declares (ruleset 0.4.0; plan quickagents-that-run.md
// M8, D7 as answered by the operator on 2026-10-05; agentry#893, DEV-221).
//
// The rule by declaration: text holds a release from publishing (high) only
// when it instructs the use of a capability the manifest does not declare,
// or when it is a prompt-injection technique. A hit about a declared
// capability that a hosted run provides is low; one about declared internet
// hosts, or declared commands a hosted run cannot provide, is medium. Both
// publish under the baseline threshold and are shown on the report.
//
// Only three families are about a capability: credential-harvest (reading
// secrets, and for -002 sending them somewhere), exfiltration (sending data
// to a destination) and destructive (removing data). The other four
// (instruction-override, obfuscation, tool-coercion, persistence) are
// injection techniques and keep the bundle's rating.

import (
	"regexp"
	"slices"
	"strings"
)

// Declared is what a release's manifest declares, as the rating by
// declaration reads it. The zero value declares nothing.
type Declared struct {
	// Egress is the hosts network.egress names, lowercased.
	Egress []string
	// EgressAny is wildcard egress ("*"), which names no host.
	EgressAny bool
	// ServerHosts are the hosts of the remote MCP servers the manifest
	// declares, lowercased: what the release reaches through a declared
	// server, which is low, as every declared server is (D7).
	ServerHosts []string
	// MCPServers reports any declared MCP server, packaged or remote.
	MCPServers bool
	// Secrets are the declared secret names.
	Secrets []string
	// Exec is the declared commands; nil when exec is none or absent.
	Exec []string
	// FileWrite reports a filesystem.write that declares more than none.
	FileWrite bool
	// BaseCommands are the commands a hosted run provides to every release
	// (manifest.BaseExecCommands, DR-64). A declared command outside them is
	// one only a run on the person's own computer can provide.
	BaseCommands []string
}

// DeclarationDetail is the Detail key a rated finding carries: what the
// rating by declaration decided, one of the Declaration* values.
const DeclarationDetail = "declaration"

// The ratings by declaration a finding can carry in its DeclarationDetail,
// from the most to the least severe.
const (
	// DeclarationUndeclared: the text uses a host, a secret or a program the
	// manifest does not declare. High.
	DeclarationUndeclared = "undeclared"
	// DeclarationInternet: the text reaches internet hosts the manifest
	// declares in network.egress, or names none and egress is declared.
	// Medium.
	DeclarationInternet = "declared-internet"
	// DeclarationLocalExec: the text names a declared program outside the
	// base commands, which a hosted run does not provide. Medium.
	DeclarationLocalExec = "declared-local-exec"
	// DeclarationUnnamed: the text names no secret or program, and the
	// manifest declares the capability; what it reaches cannot be told from
	// the text, so it is not rated as a hosted run's. Medium.
	DeclarationUnnamed = "declared-unnamed"
	// DeclarationHosted: every secret, program or server the text names is
	// declared and one a hosted run provides (declared secrets, the base
	// commands, declared MCP servers). Low.
	DeclarationHosted = "declared-hosted"
)

// capability is what a capability family's hits are about.
type capability int

const (
	capNone capability = iota
	capSecrets
	capNetwork
	capExec
)

// capabilityOf maps the capability families to what their hits use. The
// mapping lives in Go, not in the bundle's YAML: installed CLIs decode the
// bundle strictly and would refuse every bundle with a new key (DEV-186).
var capabilityOf = map[string]capability{
	"credential-harvest": capSecrets,
	"exfiltration":       capNetwork,
	"destructive":        capExec,
}

// IsCapabilityFamily reports whether a family's hits are rated by
// declaration rather than by the bundle.
func IsCapabilityFamily(family string) bool { return capabilityOf[family] != capNone }

// RateByDeclaration re-rates the S4 hits of the capability families against
// what d declares, and returns findings (the same slice, changed in place).
// Every other finding is left as the bundle rated it. A rated finding names
// its rating in Detail[DeclarationDetail], and its Severity is the
// rating's. Where the text's lines name something the extraction cannot
// place, it is rated as undeclared: the rating fails toward holding.
func RateByDeclaration(findings []Finding, d Declared) []Finding {
	for i := range findings {
		f := &findings[i]
		if f.Scanner != scannerS4 {
			continue
		}
		var rating string
		switch capabilityOf[f.Detail["family"]] {
		case capSecrets:
			rating = rateSecrets(d, f.Detail["secrets"])
			// credential-harvest-002 places a secret in a request: a
			// secret read and a destination both, rated by the worse.
			if f.RuleID == "S4/credential-harvest-002" {
				rating = worse(rating, rateNetwork(d, f.Detail["destinations"]))
			}
		case capNetwork:
			rating = rateNetwork(d, f.Detail["destinations"])
		case capExec:
			rating = rateExec(d, f.Detail["commands"])
		default:
			continue
		}
		f.Detail[DeclarationDetail] = rating
		f.Severity = declarationSeverity(rating)
	}
	return findings
}

func declarationSeverity(rating string) Severity {
	switch rating {
	case DeclarationUndeclared:
		return SeverityHigh
	case DeclarationHosted:
		return SeverityLow
	}
	return SeverityMedium
}

// worse is the more severe of two ratings.
func worse(a, b string) string {
	rank := func(r string) int {
		switch r {
		case DeclarationUndeclared:
			return 2
		case DeclarationHosted:
			return 0
		}
		return 1
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// rateSecrets: a named secret must be declared, and a credential file
// (an SSH key, a cloud CLI's credentials) never is; a text that names none
// reads whatever the run holds, which is medium with secrets declared.
func rateSecrets(d Declared, named string) string {
	names := splitList(named)
	if len(names) == 0 {
		if len(d.Secrets) == 0 {
			return DeclarationUndeclared
		}
		return DeclarationUnnamed
	}
	for _, n := range names {
		if strings.HasPrefix(n, credentialFileMark) || !slices.Contains(d.Secrets, n) {
			return DeclarationUndeclared
		}
	}
	return DeclarationHosted
}

// rateNetwork: an email recipient is never declared (postmark-mcp's BCC
// line), nor is an address the manifest does not list; a named host is
// medium when egress declares it and low when only a declared MCP server
// reaches it. With no destination named, the release must declare some way
// out.
func rateNetwork(d Declared, destinations string) string {
	named := splitList(destinations)
	if len(named) == 0 {
		switch {
		case len(d.Egress) > 0 || d.EgressAny:
			return DeclarationInternet
		case len(d.ServerHosts) > 0 || d.MCPServers:
			return DeclarationHosted
		}
		return DeclarationUndeclared
	}
	rating := DeclarationHosted
	for _, dest := range named {
		switch {
		case strings.Contains(dest, "@"):
			return DeclarationUndeclared
		case d.inEgress(dest):
			rating = worse(rating, DeclarationInternet)
		case d.isServerHost(dest):
		default:
			return DeclarationUndeclared
		}
	}
	return rating
}

// rateExec: a program the text names must be declared, and one outside the
// base commands is medium; a destructive instruction that names none needs
// exec or a file write declared, and is medium with either.
func rateExec(d Declared, commands string) string {
	named := splitList(commands)
	if len(named) == 0 {
		if d.Exec == nil && !d.FileWrite {
			return DeclarationUndeclared
		}
		return DeclarationUnnamed
	}
	rating := DeclarationHosted
	for _, c := range named {
		if !slices.Contains(d.Exec, c) {
			return DeclarationUndeclared
		}
		if !slices.Contains(d.BaseCommands, c) {
			rating = DeclarationLocalExec
		}
	}
	return rating
}

// inEgress reports whether egress names host, or is "*". Egress holds exact
// host names (V5 refuses partial wildcards).
func (d Declared) inEgress(host string) bool {
	return d.EgressAny || slices.Contains(d.Egress, host)
}

// isServerHost reports whether a declared remote MCP server is at host.
func (d Declared) isServerHost(host string) bool {
	return slices.Contains(d.ServerHosts, host)
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// The destinations a hit's lines name: a URL's host (any scheme), an email
// recipient, an IPv4 address, a bare host name. The host pattern takes any
// dotted name ending in a label of letters, with no list of top-level
// domains, so `webhook.site` and `interact.sh` are hosts; a file name such
// as `report.md` reads as one too, which rates a directive that names it as
// undeclared, the side this rating fails toward.
var (
	destinationURLRe   = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*://[^\s"'<>()\[\]` + "`" + `]+`)
	destinationEmailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	destinationIPRe    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	destinationHostRe  = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9\-]{0,61}[a-z0-9]\b`)
)

// destinations returns the hosts, addresses and email recipients text
// names, each once, in order, joined by commas.
func destinations(text string) string {
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSuffix(s, "."))
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	rest := text
	for _, u := range destinationURLRe.FindAllString(text, -1) {
		add(urlHostOf(u))
		rest = strings.Replace(rest, u, " ", 1)
	}
	for _, a := range destinationEmailRe.FindAllString(rest, -1) {
		add(a)
		rest = strings.Replace(rest, a, " ", 1)
	}
	for _, ip := range destinationIPRe.FindAllString(rest, -1) {
		add(ip)
		rest = strings.Replace(rest, ip, " ", 1)
	}
	for _, h := range destinationHostRe.FindAllString(rest, -1) {
		add(h)
	}
	return strings.Join(out, ",")
}

// urlHostOf is the host a URL reaches: its authority ends at "/", "?", "#"
// or a backslash (which browsers read as "/"), any userinfo goes up to its
// last "@", and any port is cut, so a URL that dresses one host up as
// another (https://evil.example\@declared.example/) is keyed by the one it
// reaches.
func urlHostOf(u string) string {
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#\\"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.Index(rest, ":"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// credentialFileMark prefixes a credential file named in place of a
// secret: it is never a declared secret.
const credentialFileMark = "file:"

// secretNameRe finds an environment variable's name (upper case with an
// underscore: GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY), and credentialFileRe a
// file that holds credentials.
var (
	secretNameRe     = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b`)
	credentialFileRe = regexp.MustCompile(`(?i)(?:~/|\$HOME/|/root/|/home/[^/\s]+/)?\.(?:ssh|aws/credentials|aws|kube/config|docker/config\.json|netrc|npmrc|pypirc|git-credentials|gnupg)\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|/etc/shadow\b`)
)

// secretsNamed returns the secrets a hit's lines name: each environment
// variable's name, and each credential file marked with
// credentialFileMark, each once, joined by commas.
func secretsNamed(text string) string {
	var out []string
	add := func(s string) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, f := range credentialFileRe.FindAllString(text, -1) {
		add(credentialFileMark + strings.ToLower(f))
	}
	for _, n := range secretNameRe.FindAllString(text, -1) {
		add(n)
	}
	return strings.Join(out, ",")
}

// commandRe finds the program a destructive hit names, bare or by path
// (/bin/rm): rm, shred, dd, mkfs, a cloud or cluster CLI, git or a
// database client.
var commandRe = regexp.MustCompile(`(?i)(?:^|[\s` + "`" + `"'(;|&/])(rm|rmdir|shred|dd|mkfs(?:\.[a-z0-9]+)?|wipefs|aws|gcloud|az|kubectl|terraform|git|psql|mysql|redis-cli)\b`)

// commands returns the programs a destructive hit's lines name, each once.
func commands(text string) string {
	var out []string
	for _, m := range commandRe.FindAllStringSubmatch(text, -1) {
		c := strings.ToLower(m[1])
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return strings.Join(out, ",")
}
