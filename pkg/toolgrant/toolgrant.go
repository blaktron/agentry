// Package toolgrant compares the runner tools a QuickAgent's instruction
// names with what its manifest grants. The runner builds a run's tool
// surface from the capability contract: a tool whose capability is not
// declared is absent, not present and refusing. An instruction that works
// a website through browser_click, runs a program through run_command or
// reaches a host through fetch, in a release that declares no browser, no
// command or no egress, describes a run that cannot happen: the agent
// meets a tool list without the tools its instruction depends on.
//
// Check reads the instruction for tool names and reports each one whose
// grant the manifest lacks, with the line to add. The publication scan
// records what it reports as a finding that holds the version for a
// person, the draft check returns it before Submit, and a client can ask
// the same question of a local draft.
//
// What the reading counts as naming a tool: a tool name with an
// underscore (run_command, browser_click, host_run) anywhere as a word of
// its own; a one-word tool name (fetch) only where it is written alone in
// backticks or followed by "tool" (fetch( is JavaScript's, which a
// browser script calls); a harness's prefixed
// form (mcp__gateway__fetch); browser_* and host_* for the whole family;
// and <server>__<tool>, a declared MCP server's tool by its server's
// name. A mention in a sentence that turns the tool away ("not
// browser_pdf_save", "never call fetch", "if you have run_command") is not
// a need, and neither is a list continuing one, nor a paragraph that
// speaks of a QuickAgent in the third person ("a QuickAgent", "the
// QuickAgent's own fetch"), which describes another package's tools (an
// instruction that drafts or reviews QuickAgents). Words such as
// "browser" or "fetch the page" in prose are not tool names.
package toolgrant

import (
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/blaktron/agentry/pkg/manifest"
)

// Grant is the line of the capability contract a tool needs.
type Grant string

// The grants a runner tool can need.
const (
	// GrantBrowser is capabilities.browser: the browser server's tools.
	GrantBrowser Grant = "browser"
	// GrantExec is capabilities.exec with at least one command:
	// run_command.
	GrantExec Grant = "exec"
	// GrantEgress is capabilities.network.egress naming at least one host:
	// fetch.
	GrantEgress Grant = "egress"
	// GrantTargetHosts is capabilities.targetHosts: the host link's tools.
	GrantTargetHosts Grant = "targetHosts"
	// GrantFSRead is capabilities.filesystem.read other than none:
	// fs_read and fs_list.
	GrantFSRead Grant = "filesystem.read"
	// GrantFSWrite is capabilities.filesystem.write other than none:
	// fs_write.
	GrantFSWrite Grant = "filesystem.write"
	// GrantMCPServer is capabilities.mcpServers: a declared server's
	// tools.
	GrantMCPServer Grant = "mcpServers"
)

// Grants returns every grant, in a fixed order.
func Grants() []Grant {
	return []Grant{GrantBrowser, GrantExec, GrantEgress, GrantTargetHosts, GrantFSRead, GrantFSWrite, GrantMCPServer}
}

// Path is the manifest path a release adds to hold the grant.
func (g Grant) Path() string {
	switch g {
	case GrantBrowser:
		return "capabilities.browser"
	case GrantExec:
		return "capabilities.exec.commands"
	case GrantEgress:
		return "capabilities.network.egress"
	case GrantTargetHosts:
		return "capabilities.targetHosts"
	case GrantFSRead:
		return "capabilities.filesystem.read"
	case GrantFSWrite:
		return "capabilities.filesystem.write"
	case GrantMCPServer:
		return "capabilities.mcpServers"
	}
	return ""
}

// What the grant gives, in the words a finding uses.
func (g Grant) what() string {
	switch g {
	case GrantBrowser:
		return "a browser"
	case GrantExec:
		return "a declared command"
	case GrantEgress:
		return "an egress host"
	case GrantTargetHosts:
		return "a target host"
	case GrantFSRead:
		return "workspace read access"
	case GrantFSWrite:
		return "workspace write access"
	case GrantMCPServer:
		return "a declared MCP server"
	}
	return string(g)
}

// The browser server's tools a run with a browser has: the runner's
// allowlist of the server's core, testing and pdf tools.
var browserTools = []string{
	"browser_click", "browser_close", "browser_console_messages", "browser_drag", "browser_drop",
	"browser_emulate_media", "browser_evaluate", "browser_fill_form", "browser_find",
	"browser_generate_locator", "browser_handle_dialog", "browser_hover", "browser_navigate",
	"browser_navigate_back", "browser_network_request", "browser_network_requests",
	"browser_pdf_save", "browser_press_key", "browser_resize", "browser_select_option",
	"browser_snapshot", "browser_tabs", "browser_take_screenshot", "browser_type",
	"browser_verify_element_visible", "browser_verify_list_visible", "browser_verify_text_visible",
	"browser_verify_value", "browser_wait_for",
}

// browserEvaluate is left out of a browser that may type secrets: with it
// the agent could read a typed value back transformed.
const browserEvaluate = "browser_evaluate"

// The host link's tools, which a run with a target host has.
var hostTools = []string{
	"host_run", "host_read", "host_write", "host_put", "host_get",
	"host_shell_open", "host_shell_send", "host_shell_read", "host_shell_close",
}

// table maps every runner tool the contract grants to its grant.
var table = func() map[string]Grant {
	t := map[string]Grant{
		"fs_read":     GrantFSRead,
		"fs_list":     GrantFSRead,
		"fs_write":    GrantFSWrite,
		"fetch":       GrantEgress,
		"run_command": GrantExec,
	}
	for _, n := range browserTools {
		t[n] = GrantBrowser
	}
	for _, n := range hostTools {
		t[n] = GrantTargetHosts
	}
	return t
}()

// notContract are the runner's tools no line of the contract grants: the
// inputs, the scratch folder and its search, the report, the knowledge
// and voice a person attaches, and the built-ins' own. An instruction may
// name them freely.
var notContract = []string{
	"list_inputs", "read_input", "search_inputs", "write_report", "export_pdf",
	"scratch_list", "scratch_read", "scratch_write", "scratch_search", "grep", "glob",
	"knowledge_list", "knowledge_search", "knowledge_read", "voice_read", "end_blocked",
	"web_search", "web_read", "registry_search", "ai_review",
}

// Table returns every runner tool the contract grants, with its grant.
func Table() map[string]Grant {
	out := make(map[string]Grant, len(table))
	for k, v := range table {
		out[k] = v
	}
	return out
}

// ToolsOf returns the tools a grant gives, sorted. (A browser that may
// type secrets is given every one of its tools but browser_evaluate.)
func ToolsOf(g Grant) []string {
	var out []string
	for k, v := range table {
		if v == g {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// NotContract returns the runner's tools no contract line grants, sorted.
func NotContract() []string {
	out := slices.Clone(notContract)
	sort.Strings(out)
	return out
}

// reservedServers are the gateway catalog's own names: the tools server,
// the host link and the browser. A prefix naming one of them is not a
// declared MCP server.
var reservedServers = map[string]bool{
	"gateway": true, "agentry-tools": true, "agentry_tools": true,
	"agentry-hostlink": true, "agentry_hostlink": true, "browser": true,
}

// Missing is one tool the instruction calls for that the run will not
// have.
type Missing struct {
	// Tool is the tool as the instruction names it, without a harness's
	// mcp__<server>__ prefix for a runner tool; browser_* or host_* for
	// a whole family; <server>__<tool> for a declared server's tool.
	Tool string
	// Grant is what the tool needs; Path is the manifest line to change:
	// Grant.Path(), or capabilities.browser.secrets for browser_evaluate,
	// which a browser that may type secrets is not given.
	Grant Grant
	Path  string
	// Line is the first line, from 1, that names the tool as a need.
	Line int
	// Reason says why in a sentence that quotes no instruction text.
	Reason string
}

// Bounds on what Check answers, which callers return and record: a name
// longer than MaxNameBytes is not a tool name, and at most MaxMissing
// tools are reported.
const (
	MaxNameBytes = 80
	MaxMissing   = 50
)

// Check returns each tool the instruction calls for that the
// capabilities do not grant, in the order the instruction first names
// them, at most MaxMissing. A tool named only where the instruction turns
// it away is not reported.
func Check(c manifest.Capabilities, instruction string) []Missing {
	var out []Missing
	seen := map[string]bool{}
	for _, m := range mentions(strings.ReplaceAll(instruction, "\r\n", "\n")) {
		if m.negated || seen[m.key] {
			continue
		}
		seen[m.key] = true
		var miss Missing
		if m.server != "" {
			if serverDeclared(c.MCPServers, m.server) {
				continue
			}
			miss = Missing{Tool: m.key, Grant: GrantMCPServer, Path: GrantMCPServer.Path(),
				Reason: "The instruction calls " + m.key + ", a tool of an MCP server named " + m.server + ", and the manifest declares no such server."}
		} else {
			g := m.grant
			switch {
			case !granted(c, g):
				miss = Missing{Tool: m.key, Grant: g, Path: g.Path(),
					Reason: "The instruction calls " + m.key + ", which only a run with " + g.what() + " has, and the manifest does not declare " + g.Path() + "."}
			case m.key == browserEvaluate && len(c.Browser.Secrets) > 0:
				miss = Missing{Tool: m.key, Grant: g, Path: "capabilities.browser.secrets",
					Reason: "The instruction calls browser_evaluate, which a browser that may type secrets (capabilities.browser.secrets) is not given."}
			default:
				continue
			}
		}
		miss.Line = m.line
		out = append(out, miss)
		if len(out) == MaxMissing {
			break
		}
	}
	return out
}

// granted reports whether the capabilities hold g, as the runner reads
// them when it builds a run's tools. A server's tools are judged by
// serverDeclared, never here.
func granted(c manifest.Capabilities, g Grant) bool {
	switch g {
	case GrantBrowser:
		return c.Browser != nil
	case GrantExec:
		return !c.Exec.None && len(c.Exec.Commands) > 0
	case GrantEgress:
		if c.Network.Egress.None {
			return false
		}
		for _, h := range c.Network.Egress.Hosts {
			if h != "" && h != "none" {
				return true
			}
		}
		return false
	case GrantTargetHosts:
		return len(c.TargetHosts) > 0
	case GrantFSRead:
		return fsGranted(c.Filesystem.Read)
	case GrantFSWrite:
		return fsGranted(c.Filesystem.Write)
	}
	return false
}

func fsGranted(a manifest.FSAccess) bool {
	return a.Mode == manifest.FSModeWorkspace || a.Mode == manifest.FSModePaths
}

// serverDeclared reports whether a prefix names one of the declared
// servers: the server's package name, its last path segment, or a word of
// either other than the generic mcp and server; for a remote server, a
// label of its host. It reads leniently, since the prefix is the
// author's own shorthand.
func serverDeclared(servers []manifest.MCPServer, prefix string) bool {
	want := words(prefix)
	if len(want) == 0 {
		return true
	}
	joined := strings.Join(want, "")
	for _, s := range servers {
		var name string
		switch {
		case s.NPM != "":
			name = s.NPM
		case s.PyPI != "":
			name = s.PyPI
		default:
			name = s.RemoteHost()
		}
		have := words(name)
		if strings.Join(have, "") == joined {
			return true
		}
		for _, w := range want {
			if slices.Contains(have, w) {
				return true
			}
		}
	}
	return false
}

// genericWords are left out when a server prefix is matched: nearly every
// server's name carries one.
var genericWords = map[string]bool{"mcp": true, "server": true, "com": true, "io": true, "app": true, "www": true, "api": true}

func words(s string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if !genericWords[w] {
			out = append(out, w)
		}
	}
	return out
}

// mention is one place the instruction names a tool.
type mention struct {
	key     string
	grant   Grant
	server  string
	line    int
	start   int
	end     int
	negated bool
}

// token is a candidate tool name: lower-case letters, digits, underscores
// and hyphens, with a trailing * for a family.
var token = regexp.MustCompile(`[a-z0-9][a-z0-9_-]*\*?`)

// families are the prefixes an instruction may name a whole family by.
var families = map[string]Grant{"browser_*": GrantBrowser, "host_*": GrantTargetHosts}

func mentions(text string) []mention {
	var out []mention
	line, counted := 1, 0
	for _, loc := range token.FindAllStringIndex(text, -1) {
		s, e := loc[0], loc[1]
		if s > 0 && strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-@:$", rune(text[s-1])) {
			continue
		}
		if e < len(text) && (text[e] == '.' || text[e] == '/') && e+1 < len(text) && isWordByte(text[e+1]) {
			continue // a file name or a path: browser_snapshot.png
		}
		m, ok := classify(text, s, e)
		if !ok {
			continue
		}
		line += strings.Count(text[counted:s], "\n")
		counted = s
		m.start, m.end, m.line = s, e, line
		out = append(out, m)
	}
	// Every pass below is linear in the text, however many mentions it
	// holds: the paragraphs are found once, each is read for the word
	// QuickAgent once, and a clause is read back a bounded distance.
	paras := paragraphStarts(text)
	about := make(map[int]bool, len(paras))
	p := 0
	for i := range out {
		for p+1 < len(paras) && paras[p+1] <= out[i].start {
			p++
		}
		if i > 0 && continuesList(text[out[i-1].end:out[i].start]) {
			out[i].negated = out[i-1].negated
			continue
		}
		q, ok := about[p]
		if !ok {
			end := len(text)
			if p+1 < len(paras) {
				end = paras[p+1]
			}
			q = aboutAQuickAgent(text[paras[p]:end])
			about[p] = q
		}
		cs := clauseStart(text, out[i].start)
		out[i].negated = q || turnedAway(text[cs:out[i].start]) || colonTurnsAway(text, cs)
	}
	return out
}

// paragraphStarts are the offsets where the text's paragraphs and list
// items begin: the start, and after each line break that ends a clause.
func paragraphStarts(text string) []int {
	starts := []int{0}
	for j := 0; j < len(text); j++ {
		if text[j] == '\n' && lineBreaksClause(text, j) {
			starts = append(starts, j+1)
		}
	}
	return starts
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// classify reads one token. ok is false for a token that names no tool
// this package knows.
func classify(text string, s, e int) (mention, bool) {
	if e-s > MaxNameBytes {
		return mention{}, false
	}
	t := text[s:e]
	if g, ok := families[t]; ok {
		return mention{key: t, grant: g}, true
	}
	t = strings.TrimSuffix(t, "*")
	prefixed := false
	if rest, ok := strings.CutPrefix(t, "mcp__"); ok {
		t, prefixed = rest, true
	}
	if server, tool, ok := strings.Cut(t, "__"); ok {
		if server == "" || tool == "" || strings.HasPrefix(tool, "_") {
			return mention{}, false
		}
		if g, ok := table[tool]; ok {
			return mention{key: tool, grant: g}, true
		}
		if reservedServers[server] || slices.Contains(notContract, tool) {
			return mention{}, false
		}
		return mention{key: server + "__" + tool, server: server}, true
	}
	g, ok := table[t]
	if !ok {
		return mention{}, false
	}
	if !strings.Contains(t, "_") && !prefixed && !writtenAsCode(text, s, e) {
		return mention{}, false
	}
	return mention{key: t, grant: g}, true
}

// asTool follows a one-word name written as a tool.
var asTool = regexp.MustCompile(`^\s+tool\b`)

// writtenAsCode reports whether a one-word tool name is written as a
// tool: alone in backticks, or followed by "tool".
func writtenAsCode(text string, s, e int) bool {
	if s > 0 && e < len(text) && text[s-1] == '`' && text[e] == '`' {
		return true
	}
	return asTool.MatchString(text[e:])
}

// clauseStart is where the clause holding offset i begins: after the last
// sentence end, semicolon, colon, comma, parenthesis, table cell, dash, or
// line break that is not a wrap within a paragraph, at most clauseLookback
// bytes back.
func clauseStart(text string, i int) int {
	stop := max(0, i-clauseLookback)
	for j := i - 1; j >= stop; j-- {
		switch text[j] {
		case '\n':
			if lineBreaksClause(text, j) {
				return j + 1
			}
		case ';', ':', ',', '(', ')', '|':
			return j + 1
		case '.', '!', '?':
			if j+1 < len(text) && (text[j+1] == ' ' || text[j+1] == '\t' || text[j+1] == '\n') {
				return j + 1
			}
		}
		if j >= 2 && text[j-2:j+1] == "—" {
			return j + 1
		}
	}
	return stop
}

// clauseLookback bounds how far back a clause is read: only its last
// three words matter.
const clauseLookback = 256

// listItem opens a Markdown list item, heading or table row.
var listItem = regexp.MustCompile(`^[ \t]*(?:[-*+][ \t]|\d+[.)][ \t]|#|\|)`)

// lineBreaksClause reports whether the line break at j ends a clause: a
// blank line, or a next line that opens a list item, a heading or a table
// row. Any other break is prose wrapping.
func lineBreaksClause(text string, j int) bool {
	if j > 0 && text[j-1] == '\n' {
		return true
	}
	rest := text[j+1:]
	if strings.HasPrefix(strings.TrimLeft(rest, " \t"), "\n") {
		return true
	}
	return listItem.MatchString(rest)
}

// turnAway is a word that turns a tool away when it is among the last
// three words before the tool in its clause: do not, never, without,
// instead of, rather than, avoid, unless, except, and the hedges of a tool
// the run may lack (if you have, if the run has).
var turnAway = regexp.MustCompile(`(?i)\b(?:not|never|no|without|avoid|avoiding|unless|except|instead\s+of|rather\s+than|if\s+(?:you|the\s+run|this\s+run|it)\s+(?:have|has))\b`)

// turnedAway reads the last three words of the clause before a tool,
// leaving out list joiners and other tool names, so "do not call fetch or
// run_command" turns both away.
func turnedAway(clause string) bool {
	all := strings.FieldsFunc(normalizeQuotes(clause), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '`' || r == '*' || r == '"' || r == ','
	})
	var fields []string
	for _, f := range all {
		lf := strings.ToLower(f)
		if _, tool := table[lf]; tool || lf == "or" || lf == "and" || lf == "nor" {
			continue
		}
		fields = append(fields, f)
	}
	if len(fields) > 3 {
		fields = fields[len(fields)-3:]
	}
	return turnAway.MatchString(strings.Join(fields, " "))
}

// colonTurnsAway reports whether a clause starting at cs follows a colon
// that ends a clause turning tools away ("Never use these tools: …").
func colonTurnsAway(text string, cs int) bool {
	if cs == 0 || text[cs-1] != ':' {
		return false
	}
	before := normalizeQuotes(text[clauseStart(text, cs-1) : cs-1])
	return turnAway.MatchString(before) && toolWord.MatchString(before)
}

// toolWord marks a clause about using tools.
var toolWord = regexp.MustCompile(`(?i)\b(?:tools?|use|using|call|calling)\b`)

func normalizeQuotes(s string) string {
	s = strings.ReplaceAll(s, "’", "'")
	return strings.ReplaceAll(s, "n't", " not")
}

// quickAgent is the product's word for a package used of another
// package: a, the, each or another QuickAgent, or QuickAgents. An
// instruction that calls its own run a QuickAgent ("you are a QuickAgent",
// "this QuickAgent") is speaking of itself (selfQuickAgent).
var (
	quickAgent     = regexp.MustCompile(`(?i)\b(?:a|an|the|each|every|any|another|other|that)\s+quickagent\b|\bquickagents\b`)
	selfQuickAgent = regexp.MustCompile(`(?i)\b(?:you\s+are|you['’]re|i\s+am|i['’]m|as)\s+(?:a|an|the)\s+quickagent\b|\bthis\s+quickagent\b`)
)

// aboutAQuickAgent reports whether a paragraph speaks of another package.
func aboutAQuickAgent(para string) bool {
	return quickAgent.MatchString(para) && !selfQuickAgent.MatchString(para)
}

// listJoin is the text between two tool names in one list: spaces,
// backticks, commas, slashes, and "or", "and", "nor", on one line or
// wrapped onto the next.
var listJoin = regexp.MustCompile("(?i)^(?:[ \\t\\n`*,/]|\\bor\\b|\\band\\b|\\bnor\\b)*$")

func continuesList(gap string) bool {
	return !strings.Contains(gap, "\n\n") && listJoin.MatchString(gap)
}
