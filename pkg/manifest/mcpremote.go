package manifest

// Remote MCP servers and an OAuth sign-in on a declared server (V5, v2;
// plan agentry-notes/plans/mcp-oauth-connections.md §4, agentry#910).
//
// A remote server is declared by its HTTPS address and runs at its vendor;
// the runner reaches it through its bridge behind one relay to the
// address's host. A package server may carry an oauth block: the runner
// makes or reuses the person's connection with the issuer and renders the
// access token, and only the access token, into the server's environment
// or token folder. The placeholder grammar below is the one both this
// package's validation and the runner's rendering use.

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on the remote-server and oauth fields (V5).
const (
	MaxRemoteURLLength    = 512
	MaxMCPScopes          = 32
	MaxMCPScopeLength     = 256
	MaxOAuthFiles         = 4
	MaxOAuthEnvEntries    = 8
	MaxOAuthTemplateBytes = 2048
)

// The placeholders a template may use: the access token, and its expiry
// as RFC 3339 UTC and as Unix milliseconds (the shapes the measured
// servers read: workspace-mcp's "expiry", google-auth-library's
// "expiry_date"). The placeholders an env value may use: the access token,
// and the token folder's path inside the server's container.
var (
	oauthTemplatePlaceholders = []string{"access_token", "expiry", "expiry_ms"}
	oauthEnvPlaceholders      = []string{"access_token", "dir"}
)

// placeholderRE matches `{name}` with a name of letters and underscores,
// any case, so a mis-cased placeholder is refused rather than left in a
// file. JSON's own braces never match it: a key or a string inside an
// object starts with `"`. doubleBracedRE is a placeholder written in two
// braces, which would render as the value in one.
var (
	placeholderRE  = regexp.MustCompile(`\{([A-Za-z_]+)\}`)
	doubleBracedRE = regexp.MustCompile(`\{\{[A-Za-z_]+\}\}`)
)

// oauthFileNameRE is a plain file name in the token folder.
var oauthFileNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// unsupportedOAuthPackages are npm/PyPI servers known not to run on an
// access token alone (they insist on a refresh token, or open a browser
// at run time), each with the server to declare instead (plan D25). An
// oauth block on one is refused by name. docs/quickagents.md prints the
// list, and a test holds the page to it.
var unsupportedOAuthPackages = map[string]string{
	// Waits on a browser on port 4100 when it has no credentials of its
	// own, so a tool call hangs; rewrites its credentials on every call.
	"pypi:mcp-gsuite": "pypi:workspace-mcp",
}

// UnsupportedOAuthPackage reports whether a package (its SourceID) is on
// the unsupported list, and the alternative to declare.
func UnsupportedOAuthPackage(sourceID string) (alternative string, unsupported bool) {
	alt, ok := unsupportedOAuthPackages[sourceID]
	return alt, ok
}

// ExpandOAuthTemplate renders a token-folder file's template: `{access_token}`,
// `{expiry}` and `{expiry_ms}` from vals. A placeholder outside those, or one
// with no value, is an error: nothing is left half-rendered.
func ExpandOAuthTemplate(template string, vals map[string]string) (string, error) {
	return expandPlaceholders(template, oauthTemplatePlaceholders, vals)
}

// ExpandOAuthEnvValue renders an oauth env value: `{access_token}` and
// `{dir}` from vals, as ExpandOAuthTemplate does.
func ExpandOAuthEnvValue(value string, vals map[string]string) (string, error) {
	return expandPlaceholders(value, oauthEnvPlaceholders, vals)
}

// StripOAuthPlaceholders removes every placeholder-shaped `{name}` from s,
// for a scanner that reads what an author wrote around them.
func StripOAuthPlaceholders(s string) string {
	return placeholderRE.ReplaceAllString(s, "")
}

func expandPlaceholders(s string, allowed []string, vals map[string]string) (string, error) {
	var err error
	out := placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		if !slices.Contains(allowed, name) {
			if err == nil {
				err = fmt.Errorf("manifest: oauth: unknown placeholder %s", m)
			}
			return m
		}
		v, ok := vals[name]
		if !ok && err == nil {
			err = fmt.Errorf("manifest: oauth: no value for placeholder %s", m)
		}
		return v
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

// placeholdersIn returns the placeholder names in s, and the first one
// outside allowed.
func placeholdersIn(s string, allowed []string) (names []string, unknown string) {
	for _, m := range placeholderRE.FindAllStringSubmatch(s, -1) {
		names = append(names, m[1])
		if unknown == "" && !slices.Contains(allowed, m[1]) {
			unknown = m[0]
		}
	}
	return names, unknown
}

// What is wrong with an address.
var (
	errNotHTTPS     = errors.New("must be https:// (lowercase)")
	errUserinfo     = errors.New("must carry no user information")
	errQuery        = errors.New("must carry no query: a key belongs in a declared secret")
	errFragment     = errors.New("must carry no fragment")
	errPort         = errors.New("must use port 443 (the default)")
	errIPLiteral    = errors.New("must name a host, not an IP address")
	errNotPublic    = errors.New("must be a public host name (a dotted DNS name, not localhost or an internal name)")
	errHostCase     = errors.New("must spell its host in lowercase")
	errAddressChars = errors.New("may hold only printable ASCII without spaces, quotes, `$`, braces, `<`, `>`, `\\`, `^`, `|` or a backtick (the gateway would expand a `$` or a `{{ }}`)")
	errAddressParse = errors.New("is not a URL")
)

// internalSuffixes are names that never resolve on the public internet.
var internalSuffixes = []string{".localhost", ".local", ".internal", ".lan", ".home.arpa", ".corp", ".intranet"}

// addressBadChars are refused anywhere in an address: what the gateway
// expands (`$`, braces), what a URL never carries unescaped, and quoting.
const addressBadChars = " \"<>\\^`{|}$'"

// checkHTTPSAddress holds a remote server's address or an issuer to the
// shape the runner can reach through a relay and the guard: https, a
// public lowercase DNS name whose top-level label starts with a letter (so
// no numeric or hex form of an address, which a resolver may read as one:
// `127.1`, `0x7f.1`), port 443, and nothing a credential or a gateway
// expansion could ride in. Whether a public name resolves to a private
// address is the runner's guard's to refuse at run time.
func checkHTTPSAddress(raw string) error {
	if !strings.HasPrefix(raw, "https://") {
		return errNotHTTPS
	}
	for _, r := range raw {
		if r < 0x21 || r > 0x7e || strings.ContainsRune(addressBadChars, r) {
			return errAddressChars
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errAddressParse
	}
	switch {
	case u.User != nil:
		return errUserinfo
	case u.RawQuery != "" || u.ForceQuery:
		return errQuery
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return errFragment
	case u.Port() != "" && u.Port() != "443":
		return errPort
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil || strings.HasPrefix(u.Host, "[") {
		return errIPLiteral
	}
	if host != strings.ToLower(host) {
		return errHostCase
	}
	if !validDNSHost(host) || !strings.Contains(host, ".") || host == "localhost" {
		return errNotPublic
	}
	if tld := host[strings.LastIndexByte(host, '.')+1:]; tld[0] < 'a' || tld[0] > 'z' {
		return errIPLiteral
	}
	for _, suf := range internalSuffixes {
		if strings.HasSuffix(host, suf) {
			return errNotPublic
		}
	}
	return nil
}

// checkScopes holds a scope list to single tokens, without duplicates,
// at most MaxMCPScopes of at most MaxMCPScopeLength characters each.
func checkScopes(s *issues, p string, scopes []string) {
	if len(scopes) > MaxMCPScopes {
		s.errf("V5", p, "at most %d scopes may be declared (got %d)", MaxMCPScopes, len(scopes))
	}
	seen := map[string]bool{}
	for i, sc := range scopes {
		sp := fmt.Sprintf("%s[%d]", p, i)
		switch {
		case sc == "":
			s.errf("V5", sp, "scope must not be empty")
			continue
		case utf8.RuneCountInString(sc) > MaxMCPScopeLength:
			s.errf("V5", sp, "scope must be at most %d characters", MaxMCPScopeLength)
			continue
		case strings.IndexFunc(sc, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
			s.errf("V5", sp, "scope %q must be a single token without whitespace", sc)
			continue
		case seen[sc]:
			s.errf("V5", sp, "duplicate scope %q", sc)
			continue
		}
		seen[sc] = true
	}
}

// validateRemoteServer checks one remote server entry (v2): its address,
// its auth, and that it carries none of a package's fields.
func validateRemoteServer(s *issues, p string, major int, srv MCPServer) {
	if major != 2 {
		s.errf("V1", p+".url", "url is a v2 field; set schemaVersion: 2")
		return
	}
	if n := len(srv.URL); n > MaxRemoteURLLength {
		s.errf("V5", p+".url", "a remote server's address must be at most %d characters (got %d)", MaxRemoteURLLength, n)
	} else if err := checkHTTPSAddress(srv.URL); err != nil {
		s.errf("V5", p+".url", "%q %v", srv.URL, err)
	}
	switch srv.Auth {
	case "":
		s.errf("V5", p+".auth", "auth is required for a remote server: oauth, secret or none")
	case AuthOAuth, AuthSecret, AuthNone:
	default:
		s.errf("V5", p+".auth", "auth %q is not one of oauth, secret or none", srv.Auth)
	}
	if srv.Version != "" {
		s.errf("V5", p+".version", "a remote server takes no version: it runs at its vendor, at the address declared")
	}
	if len(srv.Egress) > 0 {
		s.errf("V5", p+".egress", "a remote server takes no egress: its one host is its address's")
	}
	if len(srv.Env) > 0 {
		s.errf("V5", p+".env", "a remote server takes no env: it runs at its vendor")
	}
	if srv.OAuth != nil {
		s.errf("V5", p+".oauth", "a remote server takes no oauth block: declare auth: oauth and its scopes")
	}
	for j, name := range srv.Secrets {
		checkEnvName(s, fmt.Sprintf("%s.secrets[%d]", p, j), name)
	}
	switch {
	case srv.Auth == AuthSecret && len(srv.Secrets) != 1:
		s.errf("V5", p+".secrets", "auth: secret sends exactly one secret as the bearer header; declare exactly one secret (got %d)", len(srv.Secrets))
	case srv.Auth != AuthSecret && len(srv.Secrets) > 0:
		s.errf("V5", p+".secrets", "a remote server declares a secret only with auth: secret")
	}
	if len(srv.Scopes) > 0 && srv.Auth != AuthOAuth {
		s.errf("V5", p+".scopes", "scopes are declared only with auth: oauth")
	}
	checkScopes(s, p+".scopes", srv.Scopes)
}

// validatePackageRemoteFields refuses a remote server's fields on a
// package server: auth and scopes belong to an address; a package's
// sign-in is its oauth block.
func validatePackageRemoteFields(s *issues, p string, srv MCPServer) {
	if srv.Auth != "" {
		s.errf("V5", p+".auth", "auth is a remote server's field; a package server signs in through an oauth block")
	}
	if len(srv.Scopes) > 0 {
		s.errf("V5", p+".scopes", "scopes on a package server go in its oauth block")
	}
}

// validateMCPOAuth checks a package server's oauth block (v2): the
// issuer, the scopes, the token folder's files and the environment, the
// placeholders each may use, that the access token reaches the server at
// all, and the unsupported list.
func validateMCPOAuth(s *issues, p string, major int, srv MCPServer, agentSecrets map[string]bool) {
	o := srv.OAuth
	if o == nil {
		return
	}
	op := p + ".oauth"
	if major != 2 {
		s.errf("V1", op, "oauth is a v2 field; set schemaVersion: 2")
		return
	}
	if alt, bad := UnsupportedOAuthPackage(srv.SourceID()); bad {
		s.errf("V5", op, "%s cannot run on an access token alone, so it cannot take a connection; declare %s instead", srv.SourceID(), alt)
	}
	switch {
	case o.Issuer == "":
		s.errf("V5", op+".issuer", "issuer is required: the https:// address of the authorization server the connection is made with")
	case len(o.Issuer) > MaxRemoteURLLength:
		s.errf("V5", op+".issuer", "issuer must be at most %d characters", MaxRemoteURLLength)
	default:
		if err := checkHTTPSAddress(o.Issuer); err != nil {
			s.errf("V5", op+".issuer", "%q %v", o.Issuer, err)
		}
	}
	checkScopes(s, op+".scopes", o.Scopes)

	tokenUsed := false
	if len(o.Files) > MaxOAuthFiles {
		s.errf("V5", op+".files", "at most %d files may be declared (got %d)", MaxOAuthFiles, len(o.Files))
	}
	seenFile := map[string]bool{}
	for i, f := range o.Files {
		fp := fmt.Sprintf("%s.files[%d]", op, i)
		switch {
		case !oauthFileNameRE.MatchString(f.Path) || strings.Trim(f.Path, ".") == "":
			s.errf("V5", fp+".path", "%q must be a plain file name in the token folder (letters, digits, '.', '_', '-'; at most 64)", f.Path)
		case seenFile[f.Path]:
			s.errf("V5", fp+".path", "duplicate file %q", f.Path)
		}
		seenFile[f.Path] = true
		if n := len(f.Template); n > MaxOAuthTemplateBytes {
			s.errf("V5", fp+".template", "a template must be at most %d bytes (got %d)", MaxOAuthTemplateBytes, n)
		}
		if strings.IndexFunc(f.Template, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0 {
			s.errf("V5", fp+".template", "a template may hold no control character but newline and tab")
		}
		names, unknown := placeholdersIn(f.Template, oauthTemplatePlaceholders)
		if unknown != "" {
			s.errf("V5", fp+".template", "unknown placeholder %s: a template may use only {access_token}, {expiry} and {expiry_ms}", unknown)
		}
		if m := doubleBracedRE.FindString(f.Template); m != "" {
			s.errf("V5", fp+".template", "%s: write a placeholder in single braces", m)
		}
		if slices.Contains(names, "access_token") {
			tokenUsed = true
		}
	}

	if len(o.Env) > MaxOAuthEnvEntries {
		s.errf("V5", op+".env", "at most %d env entries may be declared (got %d)", MaxOAuthEnvEntries, len(o.Env))
	}
	taken := make(map[string]bool, len(srv.Env)+len(srv.Secrets))
	for name := range srv.Env {
		taken[name] = true
	}
	for _, name := range srv.Secrets {
		taken[name] = true
	}
	keys := make([]string, 0, len(o.Env))
	for k := range o.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range keys {
		np := op + ".env." + name
		if !checkEnvName(s, np, name) {
			continue
		}
		if taken[name] || agentSecrets[name] {
			s.errf("V5", np, "%q is declared more than once: as an oauth env entry and as the server's env or a secret", name)
		}
		value := o.Env[name]
		if n := utf8.RuneCountInString(value); n > MaxMCPServerEnvValue {
			s.errf("V5", np, "value must be at most %d characters (got %d)", MaxMCPServerEnvValue, n)
		}
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			s.errf("V5", np, "value must be a single line with no control characters")
		}
		if !LiteralEnvValue(value) {
			s.errf("V5", np, "value contains a $ the runner's gateway would expand, or a {{ }} template; use the placeholders {access_token} and {dir}")
		}
		names, unknown := placeholdersIn(value, oauthEnvPlaceholders)
		if unknown != "" {
			s.errf("V5", np, "unknown placeholder %s: an env value may use only {access_token} and {dir}", unknown)
		}
		if slices.Contains(names, "dir") && len(o.Files) == 0 {
			s.errf("V5", np, "{dir} names the token folder, which holds only the files declared; declare the files it should hold")
		}
		if slices.Contains(names, "access_token") {
			tokenUsed = true
		}
	}
	if !tokenUsed {
		s.errf("V5", op, "{access_token} must appear in a file template or an env value, or the connection never reaches the server")
	}
}
