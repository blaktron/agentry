package scan

import (
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/blaktron/agentry/internal/manifestcaps"
)

// scannerUndeclaredEnv is S6's finding for an environment read the manifest
// does not declare; high (see reratedToHigh).
const scannerUndeclaredEnv = "S6/undeclared-env"

// S6 — Support scripts. An instruction package
// may ship scripts its instructions tell the host to run. This stage reads
// the shell, Python and JavaScript/TypeScript files in the package and
// compares what they do with what the manifest declares: network calls
// against `network.egress` (a host counts only inside a network call, so a
// documentation URL in a comment or string is not a finding; a shell
// script's /dev/tcp redirection, socat address, git remote and container
// registry name their host themselves, see netFormHosts), writes
// against `filesystem.write`, environment reads against `secrets`, and a
// script's very presence against `exec` — a package that ships a script
// under `exec: none` is a high finding. Remote and
// obfuscated execution (`curl … | sh`, decoded payloads, eval) is reported
// regardless of declarations. The stage records what it scanned and what it
// skipped in an informational finding, so the report never implies coverage
// it did not have.
//
// It also reads the other direction, needed but not declared: the runner
// tools the instruction calls for (browser_click, run_command, fetch,
// host_run, fs_write, a declared server's tool) against the grants the
// manifest declares (pkg/toolgrant). A run of a release that does not
// declare the grant has no such tool, so the instruction describes a run
// that cannot happen. Each grant missing is one high finding: the version
// goes to a person, who can see the instruction and the manifest
// disagree; it is never rejected.
//
// Not done here, and said so in the trust docs
// (https://docs.secureagentry.net/trust/): data-flow analysis, evaluating
// what a fetch returns, other languages.
type S6Scripts struct{}

func (S6Scripts) ID() string { return "S6" }

type scriptClass string

const (
	scriptShell  scriptClass = "shell"
	scriptPython scriptClass = "python"
	scriptJS     scriptClass = "javascript"
)

// classifyScript names the script class of a text file by extension, else
// by its shebang; "" for anything this stage does not read.
func classifyScript(p string, content []byte) scriptClass {
	switch strings.ToLower(path.Ext(p)) {
	case ".sh", ".bash", ".zsh":
		return scriptShell
	case ".py":
		return scriptPython
	case ".js", ".mjs", ".cjs", ".ts":
		return scriptJS
	}
	if len(content) > 2 && content[0] == '#' && content[1] == '!' {
		first := content
		if i := strings.IndexByte(string(content), '\n'); i >= 0 {
			first = content[:i]
		}
		line := string(first)
		switch {
		case strings.Contains(line, "python"):
			return scriptPython
		case strings.Contains(line, "node"):
			return scriptJS
		case strings.Contains(line, "sh"):
			return scriptShell
		}
	}
	return ""
}

// s6Declared is the manifest's declaration as this stage reads it.
type s6Declared struct {
	anyHost  bool
	hosts    map[string]bool
	fsWrite  bool
	exec     bool
	secrets  map[string]bool
	declared bool
}

func s6DeclaredFromManifest(manifestJSON []byte) s6Declared {
	d := s6Declared{hosts: map[string]bool{}, secrets: map[string]bool{}}
	c, ok := manifestcaps.Read(manifestJSON)
	if !ok {
		return d
	}
	d.declared = true
	for _, h := range c.Network.Egress.Hosts {
		switch h {
		case "", "none":
		case "*":
			d.anyHost = true
		default:
			d.hosts[strings.ToLower(h)] = true
		}
	}
	d.fsWrite = manifestcaps.NotNone(c.Filesystem.Write)
	d.exec = manifestcaps.NotNone(c.Exec)
	for _, s := range c.Secrets {
		d.secrets[s] = true
	}
	return d
}

// s6ShellPath is a path before a pipe's shell target (| /bin/sh); the
// target must end the word, so | /opt/sh/tool is not a shell.
const (
	s6ShellPath    = "[^\\s;|&()<>`'\":\\\\]*/"
	s6ShellTargets = "sh|bash|zsh|python[0-9.]*|node|perl"
	s6Shell        = "\\|\\s*(?:sudo\\s+)?(?:(?:" + s6ShellTargets + ")\\b|" + s6ShellPath + "(?:" + s6ShellTargets + ")(?:$|[\\s;|&)`<>]))"
)

var (
	s6URLHost   = regexp.MustCompile(`(?i)\b(?:https?|ftps?|sftp|scp|ssh|rsync|telnet|wss?)://(?:[^\s/?#'"@]*@)*(\[[0-9a-f:.]+\]|[a-z0-9.-]+)`)
	s6BareHost  = regexp.MustCompile(`(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?\b`)
	s6ShellNet  = regexp.MustCompile(`(?m)(?:^|[\s;|&(])(?:curl|wget|nc|ncat|netcat|ssh|scp|sftp|rsync|telnet|openssl\s+s_client)\b`)
	s6PyNet     = regexp.MustCompile(`\b(?:requests|httpx|aiohttp|urllib\.request|urllib2|http\.client|socket)\.[a-zA-Z_]+\s*\(|\bimport\s+(?:requests|httpx|aiohttp|socket)\b|\bfrom\s+(?:urllib|http|requests|httpx|aiohttp)\b`)
	s6JSNet     = regexp.MustCompile(`\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(|require\(\s*['"](?:https?|net|http2|dgram|axios|node-fetch|got|undici)['"]\s*\)|\bimport\b[^;\n]*['"](?:node:)?(?:https?|net|axios|node-fetch|got|undici)['"]`)
	s6ShellFSW  = regexp.MustCompile(`(?:^|[\s;|&(])(?:rm|mv|cp|tee|mkdir|chmod|chown|truncate|dd)\b|\bsed\s+-[a-zA-Z]*i\b|(?:^|[^<>0-9&])>{1,2}\s*[^&>\s]`)
	s6PyFSW     = regexp.MustCompile(`\bopen\s*\([^)]*['"][wax]\+?b?['"]|\b(?:os\.remove|os\.unlink|os\.rename|shutil\.rmtree|shutil\.move|shutil\.copy|os\.mkdir|os\.makedirs|pathlib\.Path\([^)]*\)\.write_text)\s*\(`)
	s6JSFSW     = regexp.MustCompile(`\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|rmSync|rm|unlinkSync|unlink|mkdirSync|mkdir|renameSync|rename)\s*\(`)
	s6PyExec    = regexp.MustCompile(`\bimport\s+subprocess\b|\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(|\bos\.(?:system|popen|exec[lv]?p?e?)\s*\(`)
	s6JSExec    = regexp.MustCompile(`require\(\s*['"](?:node:)?child_process['"]\s*\)|\b(?:execSync|execFileSync|spawnSync|exec|spawn|execFile)\s*\(`)
	s6ShellEnv  = regexp.MustCompile(`\$\{?([A-Z][A-Z0-9_]*)\}?`)
	s6PyEnv     = regexp.MustCompile(`os\.environ(?:\.get)?\s*[\[(]\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]|os\.getenv\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]`)
	s6JSEnv     = regexp.MustCompile(`process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]`)
	s6RemoteExe = regexp.MustCompile(`\b(?:curl|wget)\b[^|\n]*` + s6Shell)
	s6Decoded   = regexp.MustCompile(`base64\s+(?:-d|--decode)[^|\n]*` + s6Shell + `|\b(?:sh|bash|zsh)\s+-c\s+["']?\$\(|\b(?:python[0-9.]*\s+-c|node\s+-e)\b[^\n]*(?:base64|\\x[0-9a-fA-F]{2})`)
	s6Eval      = regexp.MustCompile(`(?:^|[\s;|&(])eval\b|\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(`)
	s6HexBlob   = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){24,}`)
)

// s6ShellVars are the environment names a shell script reads without
// meaning a secret; they are never reported.
var s6ShellVars = map[string]bool{
	"PATH": true, "HOME": true, "PWD": true, "OLDPWD": true, "USER": true, "SHELL": true, "TMPDIR": true, "TMP": true, "TEMP": true,
	"IFS": true, "LANG": true, "LC_ALL": true, "TERM": true, "HOSTNAME": true, "UID": true, "EUID": true, "PPID": true, "RANDOM": true,
	"SECONDS": true, "LINENO": true, "SHLVL": true, "PS1": true, "PS4": true, "EDITOR": true, "PAGER": true, "COLUMNS": true, "LINES": true,
	"XDG_CONFIG_HOME": true, "XDG_CACHE_HOME": true, "XDG_DATA_HOME": true, "XDG_RUNTIME_DIR": true, "DISPLAY": true, "TZ": true,
}

type s6Hit struct {
	file string
	line int
}

func isCommentLineOf(class scriptClass, line string) bool {
	t := strings.TrimSpace(line)
	switch class {
	case scriptJS:
		return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*")
	default:
		return strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#!")
	}
}

func (S6Scripts) Run(sc stageContext, in *Input) StageResult {
	decl := s6DeclaredFromManifest(in.ManifestJSON)
	findings := s6UngrantedTools(in)
	var scanned []string
	var skipped []map[string]any
	undeclaredNet := map[string]s6Hit{} // host → first hit
	fsWrite := map[string]s6Hit{}       // file → first hit
	envReads := map[string]s6Hit{}      // name → first hit
	subprocess := map[string]s6Hit{}    // file → first hit
	var scripts []string
	referenced := map[string]bool{} // declared hosts seen anywhere in text

	for _, f := range in.Files {
		if !f.IsText || f.Content == nil {
			continue
		}
		content := string(f.Content)
		var vars map[string][]string // a shell script's assignments, read where a network line uses them
		for h := range decl.hosts {
			if strings.Contains(strings.ToLower(content), h) {
				referenced[h] = true
			}
		}
		class := classifyScript(f.Path, f.Content)
		if class == "" {
			if ext := strings.ToLower(path.Ext(f.Path)); ext == ".ps1" || ext == ".rb" || ext == ".pl" || ext == ".php" || ext == ".lua" {
				skipped = append(skipped, map[string]any{"path": f.Path, "reason": "language not covered by S6"})
			}
			continue
		}
		scripts = append(scripts, f.Path)
		if class == scriptShell {
			vars = s6Assignments(content)
		}
		scanned = append(scanned, f.Path)
		for i, line := range strings.Split(content, "\n") {
			hit := s6Hit{file: f.Path, line: i + 1}
			comment := isCommentLineOf(class, line)
			// Remote execution is reported even in a comment — a commented
			// `curl … | sh` is an instruction to whoever reads the script.
			if s6RemoteExe.MatchString(line) {
				sev := SevHigh
				if comment {
					sev = SevLow
				}
				findings = append(findings, Finding{
					Scanner: "S6/remote-exec", Severity: sev, Confidence: ConfHigh,
					Title:    "Script fetches from the network and executes the result",
					FilePath: f.Path, LineStart: hit.line, LineEnd: hit.line, Excerpt: truncateStr(strings.TrimSpace(line), 160),
					Detail:   map[string]any{"inComment": comment},
					Taxonomy: []string{"ASI05", "LLM03"},
				})
			}
			if comment {
				continue
			}
			var cmdNet, cmdWrite, cmdEval bool
			if class == scriptShell {
				cmdNet, cmdWrite, cmdEval = shellCommands(line)
			}
			if s6Decoded.MatchString(line) || s6HexBlob.MatchString(line) || (s6Eval.MatchString(line) && class != scriptShell) || (class == scriptShell && (s6Eval.MatchString(line) || cmdEval)) {
				findings = append(findings, Finding{
					Scanner: "S6/obfuscated-exec", Severity: SevHigh, Confidence: ConfMedium,
					Title:    "Script executes decoded or dynamically built code",
					FilePath: f.Path, LineStart: hit.line, LineEnd: hit.line, Excerpt: truncateStr(strings.TrimSpace(line), 160),
					Taxonomy: []string{"ASI05", "LLM01"},
				})
			}
			var net, fsw, exe bool
			var envNames []string
			switch class {
			case scriptShell:
				net = s6ShellNet.MatchString(line) || cmdNet
				fsw = s6ShellFSW.MatchString(line) || cmdWrite
				for _, m := range s6ShellEnv.FindAllStringSubmatch(line, -1) {
					if n := m[1]; !s6ShellVars[n] {
						envNames = append(envNames, n)
					}
				}
			case scriptPython:
				net = s6PyNet.MatchString(line)
				fsw = s6PyFSW.MatchString(line)
				exe = s6PyExec.MatchString(line)
				for _, m := range s6PyEnv.FindAllStringSubmatch(line, -1) {
					envNames = append(envNames, s6First(m[1:]))
				}
			case scriptJS:
				net = s6JSNet.MatchString(line)
				fsw = s6JSFSW.MatchString(line)
				exe = s6JSExec.MatchString(line)
				for _, m := range s6JSEnv.FindAllStringSubmatch(line, -1) {
					envNames = append(envNames, s6First(m[1:]))
				}
			}
			if !decl.anyHost {
				var hosts []string
				if net {
					hosts = hostsOnLineWith(line, class, vars)
				}
				if class == scriptShell {
					// These forms name their own host and are no network
					// command's word, so they are read whether or not the
					// line is a network call.
					hosts = append(hosts, netFormHostsWith(line, vars)...)
				}
				for _, h := range hosts {
					if !decl.hosts[h] {
						if _, seen := undeclaredNet[h]; !seen {
							undeclaredNet[h] = hit
						}
					}
				}
			}
			if fsw && !decl.fsWrite {
				if _, seen := fsWrite[f.Path]; !seen {
					fsWrite[f.Path] = hit
				}
			}
			if exe && !decl.exec {
				if _, seen := subprocess[f.Path]; !seen {
					subprocess[f.Path] = hit
				}
			}
			for _, n := range envNames {
				if n == "" || decl.secrets[n] {
					continue
				}
				if _, seen := envReads[n]; !seen {
					envReads[n] = hit
				}
			}
		}
	}
	if len(scripts) == 0 && len(skipped) == 0 {
		return StageResult{Scanner: "S6", Findings: findings}
	}

	// Findings in a fixed order: the report is hashed and signed.
	if len(scripts) > 0 && !decl.exec {
		sort.Strings(scripts)
		findings = append(findings, Finding{
			Scanner: "S6/script-without-exec", Severity: SevHigh, Confidence: ConfHigh,
			Title:    "Package ships a script but declares no exec capability",
			FilePath: scripts[0],
			Detail:   map[string]any{"scripts": scripts, "declaredExec": decl.exec},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	for _, h := range sortedKeysHit(undeclaredNet) {
		hit := undeclaredNet[h]
		findings = append(findings, Finding{
			Scanner: "S6/undeclared-network", Severity: SevHigh, Confidence: ConfHigh,
			Title:    "Script reaches a host the manifest does not declare: " + h,
			FilePath: hit.file, LineStart: hit.line, LineEnd: hit.line,
			Detail:   map[string]any{"host": h, "declaredHosts": sortedSet(decl.hosts)},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	for _, p := range sortedKeysHit(fsWrite) {
		hit := fsWrite[p]
		findings = append(findings, Finding{
			Scanner: "S6/undeclared-fs-write", Severity: SevHigh, Confidence: ConfMedium,
			Title:    "Script writes to the filesystem but the manifest declares no write access",
			FilePath: hit.file, LineStart: hit.line, LineEnd: hit.line,
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	for _, p := range sortedKeysHit(subprocess) {
		hit := subprocess[p]
		findings = append(findings, Finding{
			Scanner: "S6/undeclared-exec", Severity: SevHigh, Confidence: ConfHigh,
			Title:    "Script starts subprocesses but the manifest declares no exec capability",
			FilePath: hit.file, LineStart: hit.line, LineEnd: hit.line,
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	for _, n := range sortedKeysHit(envReads) {
		hit := envReads[n]
		findings = append(findings, Finding{
			// High, not medium: an undeclared capability reaches a person
			// whatever the auto-publish threshold.
			Scanner: scannerUndeclaredEnv, Severity: SevHigh, Confidence: ConfMedium,
			Title:    "Script reads an environment variable the manifest does not declare as a secret: " + n,
			FilePath: hit.file, LineStart: hit.line, LineEnd: hit.line,
			Detail:   map[string]any{"name": n, "declaredSecrets": sortedSet(decl.secrets)},
			Taxonomy: []string{"LLM06", "ASI04"},
		})
	}
	var unused []string
	for h := range decl.hosts {
		if !referenced[h] {
			unused = append(unused, h)
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		findings = append(findings, Finding{
			Scanner: "S6/declared-unused", Severity: SevLow, Confidence: ConfMedium,
			Title:    "Nothing in the package references these declared egress hosts",
			Detail:   map[string]any{"hosts": unused},
			Taxonomy: []string{"ASI04"},
		})
	}
	sort.Strings(scanned)
	sort.Slice(skipped, func(i, j int) bool { return skipped[i]["path"].(string) < skipped[j]["path"].(string) })
	findings = append(findings, Finding{
		Scanner: "S6/coverage", Severity: SevInfo, Confidence: ConfHigh,
		Title:  fmt.Sprintf("S6 read %d script(s); %d file(s) in languages it does not cover", len(scanned), len(skipped)),
		Detail: map[string]any{"scannedScripts": scanned, "skippedFiles": skipped, "checks": []string{"network calls vs declared egress", "filesystem writes vs filesystem.write", "subprocesses vs exec", "environment reads vs secrets", "remote and obfuscated execution", "declared but unreferenced hosts", "runner tools the instruction calls for vs their grants"}},
	})
	return StageResult{Scanner: "S6", Findings: findings}
}

// hostsOnLine returns the lower-cased hosts a line names: URL hosts and
// bare domain-looking tokens (something.tld), deduplicated in order.
// s6Quoted finds string literals; in Python and JavaScript a bare host is
// only believed inside one, because dotted identifiers (requests.get,
// os.environ) are everywhere else.
var s6Quoted = regexp.MustCompile("[\"'`]([^\"'`]+)[\"'`]")

// s6UserAtHost is an ssh destination written user@host, with scp's and
// rsync's :path after it; the user may be a shell variable ($USER,
// ${SSH_USER}). An e-mail address has the same shape, which is why only
// an ssh-family command's own destination words are read with it.
var s6UserAtHost = regexp.MustCompile(`(?i)^` + s6UserRe + `@(` + s6HostRe + `)\.?(?::.*)?$`)

// s6UserRe is the user of a destination or a git remote: letters, digits and
// . _ -, or a shell variable.
const s6UserRe = `(?:[a-z0-9._-]|\$\{[^}]*\}|\$[a-z0-9_]+)+`

// s6HostRe is a host as an ssh-family command names it: a dotted name, an
// IPv4 address or a bracketed IPv6 one. s6DestHost is an ssh
// destination with no user (ssh 10.1.2.3), s6HostColon an scp, rsync or
// sshfs operand host:path with no user. A user may be a variable, a
// parameter expansion (${USER:-root}, $1) or a command substitution, which
// shellSegments leaves in the word as $_.
const s6HostRe = `(?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\]`

var (
	s6DestHost  = regexp.MustCompile(`(?i)^(` + s6HostRe + `)\.?$`)
	s6HostColon = regexp.MustCompile(`(?i)^(` + s6HostRe + `):`)
	s6IPv4      = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
)

// The options that take an argument (the rest of the word, or the next
// word): ssh's, and sftp's, which differ.
const (
	sshOptsWithArg  = "BbcDEeFIiJLlmOoPpQRSWw"
	sftpOptsWithArg = "BbcDFiJloPRSsX"
)

// s6CmdWrappers run the command that follows them; their own options are
// skipped to find it (sudo -u deploy ssh …, sshpass -p pw scp …).
var s6CmdWrappers = map[string]string{
	// wrapper: its options that take the next word as their argument
	"sudo": "CDghpRrTtUu", "doas": "Cu", "env": "CSu", "exec": "a", "command": "", "builtin": "",
	"nohup": "", "time": "fo", "nice": "n", "timeout": "ks", "stdbuf": "eio", "sshpass": "dfPp",
	// The shell's own words before a command (then ssh …, do ssh …).
	"if": "", "then": "", "else": "", "elif": "", "do": "", "while": "", "until": "", "!": "", "{": "",
}

// sshDestinations reads the hosts a shell line's ssh, scp, sftp and rsync
// reach when written user@host or user@host:path: bare() skips a host
// after "@" so that curl's @file argument is not one, and that also
// skipped the usual way an SSH destination is written. The
// command must be its segment's own (after assignments and wrappers such
// as sudo or sshpass), and nothing after an unquoted '#' is read, so an
// e-mail address in a comment or another command's arguments is never a
// host. ssh's and sftp's words stop at the destination, so the remote
// command's arguments are not read; their jump hosts (-J, ProxyJump) are.
// scp and rsync read every operand. A destination may
// be an address (10.1.2.3, [2001:db8::1]) or a dotted name with no user,
// an operand host:path, and the user dynamic ($(whoami)@h, ${USER:-root}@h);
// autossh, ssh-copy-id and mosh are read like ssh, sshfs like scp, and the
// string an sh -c or eval runs is read as a line (expandSegments).
func sshDestinations(line string) []string {
	var out []string
	for _, seg := range expandSegments(line, 0) {
		cmd, args := segmentCommand(seg)
		switch cmd {
		case "ssh":
			out = append(out, sshArgs(args, sshOptsWithArg)...)
		case "autossh": // ssh's own options, and -M port
			out = append(out, sshArgs(args, sshOptsWithArg+"M")...)
		case "sftp":
			out = append(out, sshArgs(args, sftpOptsWithArg)...)
		case "ssh-copy-id":
			out = append(out, sshArgs(args, "iopFt")...)
		case "mosh":
			out = append(out, sshArgs(withoutLongOptions(args, moshLongWithArg), "p")...)
		case "scp", "rsync", "sshfs":
			for _, a := range args {
				if strings.HasPrefix(a.text, "-") && !a.quoted {
					out = append(out, proxyJump(a.text)...)
					continue
				}
				out = append(out, operandHost(a.text)...)
			}
		}
	}
	return out
}

// mosh's long options that take the next word when not written --opt=value.
var moshLongWithArg = map[string]bool{"--ssh": true, "--port": true, "--server": true, "--client": true, "--predict": true, "--family": true, "--bind-server": true, "--experimental-remote-ip": true}

// withoutLongOptions drops --long options (and the argument of those in
// withArg) so the short-option reader sees the rest.
func withoutLongOptions(words []shellWord, withArg map[string]bool) []shellWord {
	var out []shellWord
	for i := 0; i < len(words); i++ {
		w := words[i]
		// --ssh='ssh -p 2222' is quoted only after its =.
		if strings.HasPrefix(w.text, "--") && len(w.text) > 2 && (!w.quoted || strings.Contains(w.text, "=")) {
			if withArg[w.text] {
				i++
			}
			continue
		}
		out = append(out, w)
	}
	return out
}

// s6Shells are the shells whose -c string is read as a line of its own.
var s6Shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true}

// expandSegments is shellSegments plus the segments of the strings a
// segment hands to a shell to run: sh -c '…' (or a flag cluster holding c,
// sh -ec '…') and eval's words. depth bounds the nesting.
func expandSegments(line string, depth int) [][]shellWord {
	segs := shellSegments(line)
	if depth > 3 {
		return segs
	}
	var more [][]shellWord
	for _, seg := range segs {
		cmd, args := segmentCommand(seg)
		switch {
		case s6Shells[cmd]:
			// The shell's own flags come before its script; -c's string is
			// the next word after the cluster that holds it, and -o and -O
			// take an option name (bash -o pipefail -c '…').
			for i := 0; i < len(args); i++ {
				a := args[i]
				if a.quoted || !strings.HasPrefix(a.text, "-") || a.text == "-" || a.text == "--" {
					break
				}
				if strings.HasPrefix(a.text, "--") {
					continue // --login, --norc
				}
				if strings.ContainsRune(a.text, 'c') {
					if i+1 < len(args) {
						more = append(more, expandSegments(args[i+1].text, depth+1)...)
					}
					break
				}
				if strings.ContainsAny(a.text[1:], "oO") {
					i++
				}
			}
		case cmd == "eval":
			var parts []string
			for _, a := range args {
				parts = append(parts, a.text)
			}
			more = append(more, expandSegments(strings.Join(parts, " "), depth+1)...)
		}
	}
	return append(segs, more...)
}

// segmentCommand is a segment's command word and its arguments, past any
// NAME=value assignments and wrappers (s6CmdWrappers) with their options.
func segmentCommand(seg []shellWord) (string, []shellWord) {
	wrapped := ""
	for i := 0; i < len(seg); i++ {
		w := seg[i]
		if s6Assign.MatchString(w.text) {
			// An assignment before the command, or after a wrapper that
			// passes it on (sudo FOO=1 ssh …), quoted or not (X="a b" cmd).
			continue
		}
		if wrapped != "" && strings.HasPrefix(w.text, "-") {
			if len(w.text) == 2 && strings.IndexByte(s6CmdWrappers[wrapped], w.text[1]) >= 0 {
				i++
			}
			continue
		}
		if wrapped == "timeout" && s6Duration.MatchString(w.text) {
			continue
		}
		if wrapped == "env" && strings.Contains(w.text, "=") {
			continue
		}
		// The word's text is already unquoted, as the shell runs it:
		// "curl", 'ssh' and c"url" are curl, ssh and curl. A quoted word
		// with a space in it is a whole command line held as a string
		// ("cat docs/mv"), never the name of a command that runs.
		if w.quoted && strings.ContainsAny(w.text, " \t\n") {
			return "", nil
		}
		name := w.text[strings.LastIndexByte(w.text, '/')+1:] // /usr/bin/ssh is ssh
		if _, ok := s6CmdWrappers[name]; ok {
			wrapped = name
			continue
		}
		return name, seg[i+1:]
	}
	return "", nil
}

var s6Duration = regexp.MustCompile(`^[0-9.]+[smhd]?$`)

// s6NetCmds and s6WriteCmds are the shell commands S6 reads as a network
// call or a filesystem write when a segment runs them (shellCommands).
var (
	s6NetCmds   = map[string]bool{"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "ssh": true, "scp": true, "sftp": true, "rsync": true, "telnet": true, "ssh-copy-id": true, "autossh": true, "mosh": true, "sshfs": true}
	s6WriteCmds = map[string]bool{"rm": true, "mv": true, "cp": true, "tee": true, "mkdir": true, "chmod": true, "chown": true, "truncate": true, "dd": true}
)

// shellCommands reads what a shell line runs: the command word of each
// segment (shellSegments, segmentCommand), by its base name, so
// /usr/bin/curl, `rm …` and \curl are curl, rm and curl, and a word that
// is an argument (cat docs/mv, test -x /usr/bin/ssh) or sits in a string
// (printf "a\nc") is not a command. The keyword regexes (s6ShellNet,
// s6ShellFSW, s6Eval) are kept beside it, so it only adds.
func shellCommands(line string) (net, write, eval bool) {
	for _, seg := range expandSegments(line, 0) {
		cmd, args := segmentCommand(seg)
		switch {
		case s6NetCmds[cmd]:
			net = true
		case cmd == "openssl" && len(args) > 0 && args[0].text == "s_client":
			net = true
		case s6WriteCmds[cmd]:
			write = true
		case cmd == "eval":
			eval = true
		}
	}
	return net, write, eval
}

// sshArgs reads ssh's or sftp's words up to and including the destination,
// with the jump hosts its options name.
func sshArgs(words []shellWord, optsWithArg string) []string {
	var out []string
	for i := 0; i < len(words); i++ {
		w := words[i]
		if w.text == "--" && !w.quoted {
			if i+1 < len(words) {
				out = append(out, destHost(words[i+1].text)...)
			}
			return out
		}
		if strings.HasPrefix(w.text, "-") && len(w.text) > 1 && !w.quoted {
			// A cluster of flags; the first that takes an argument takes
			// the rest of the word, or the next word.
			for j := 1; j < len(w.text); j++ {
				opt := w.text[j]
				if strings.IndexByte(optsWithArg, opt) < 0 {
					continue
				}
				arg := w.text[j+1:]
				if arg == "" && i+1 < len(words) {
					i++
					arg = words[i].text
				}
				switch opt {
				case 'L', 'R':
					out = append(out, forwardHost(arg)...)
				case 'W':
					out = append(out, forwardHost("0:"+arg)...)
				case 'J':
					out = append(out, jumpHosts(arg)...)
				case 'o':
					out = append(out, proxyJump("-o"+arg)...)
				}
				break
			}
			continue
		}
		return append(out, destHost(w.text)...) // the destination; what follows is the remote command
	}
	return out
}

// forwardHost is the host of an -L or -R forward, [bind:]port:host:hostport,
// which the command reaches through the connection; a dynamic or socket
// forward names none.
func forwardHost(spec string) []string {
	if i := strings.IndexByte(spec, '['); i >= 0 {
		if j := strings.IndexByte(spec[i:], ']'); j > 0 {
			return destHost(spec[i : i+j+1])
		}
	}
	f := strings.Split(spec, ":")
	if len(f) < 3 {
		return nil
	}
	return destHost(f[len(f)-2])
}

// proxyJump reads the hosts of an -oProxyJump=… or -o ProxyJump … option.
func proxyJump(opt string) []string {
	v, ok := strings.CutPrefix(opt, "-o")
	if !ok {
		return nil
	}
	k, val, ok := strings.Cut(strings.TrimSpace(v), "=")
	if !ok {
		k, val, ok = strings.Cut(strings.TrimSpace(v), " ")
	}
	if !ok || !strings.EqualFold(strings.TrimSpace(k), "ProxyJump") {
		return nil
	}
	return jumpHosts(val)
}

func jumpHosts(list string) []string {
	var out []string
	for _, j := range strings.Split(list, ",") {
		out = append(out, destHost(strings.TrimSpace(j))...)
	}
	return out
}

func userAtHost(word string) []string {
	if m := s6UserAtHost.FindStringSubmatch(word); m != nil {
		return []string{m[1]}
	}
	return nil
}

// destHost is an ssh destination: user@host, or a host alone when it is a
// dotted name or an address, bracketed or not for IPv6 (a single label may
// be an ssh_config alias).
func destHost(word string) []string {
	if h := userAtHost(word); h != nil {
		return h
	}
	if m := s6DestHost.FindStringSubmatch(word); m != nil && !s6LooksLikeFile(m[1]) {
		return []string{m[1]}
	}
	// An IPv6 address needs no brackets as ssh's destination, alone or after
	// the user; only scp's and rsync's host:path cannot tell it from the path.
	if i := strings.LastIndexByte(word, '@'); i > 0 && s6User.MatchString(word[:i]) {
		word = word[i+1:]
	}
	if ip := s6IPv6Word(word); ip != "" {
		return []string{ip}
	}
	return nil
}

// s6LooksLikeFile is a dotted name whose last label is a file extension
// (notes.txt, deploy.sh), which a destination written without a user is
// taken not to be; an address never is.
func s6LooksLikeFile(h string) bool {
	if strings.HasPrefix(h, "[") || s6IsIPv4(h) {
		return false
	}
	return s6FileExt[strings.ToLower(h[strings.LastIndex(h, ".")+1:])]
}

// operandHost is an scp, rsync or sshfs operand's host: user@host[:path] or
// host:path. An operand with neither is a local path.
func operandHost(word string) []string {
	if h := userAtHost(word); h != nil {
		return h
	}
	if m := s6HostColon.FindStringSubmatch(word); m != nil && !s6LooksLikeFile(m[1]) {
		return []string{m[1]}
	}
	return nil
}

// s6Assign is a shell assignment word, NAME=value.
var s6Assign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// s6Declarers assign the NAME=value words they are given.
var s6Declarers = map[string]bool{"export": true, "readonly": true, "local": true, "declare": true, "typeset": true}

// s6Assignments collects a shell script's assignments, every value of each
// name (at most eight), so that a destination held in a variable is read
// where a network line uses it. Order is ignored: a value
// assigned anywhere in the file counts.
func s6Assignments(content string) map[string][]string {
	vars := map[string][]string{}
	record := func(word string) {
		name, value, _ := strings.Cut(word, "=")
		for _, v := range vars[name] {
			if v == value {
				return
			}
		}
		if len(vars[name]) < 8 {
			vars[name] = append(vars[name], value)
		}
	}
	for _, line := range strings.Split(content, "\n") {
		if isCommentLineOf(scriptShell, line) {
			continue
		}
		for _, seg := range expandSegments(line, 0) {
			// for NAME in word…: each word is a value of NAME.
			if len(seg) > 3 && seg[0].text == "for" && seg[2].text == "in" && !seg[0].quoted {
				for _, w := range seg[3:] {
					record(seg[1].text + "=" + w.text)
				}
				continue
			}
			for i, w := range seg {
				if s6Assign.MatchString(w.text) {
					record(w.text)
					continue
				}
				if s6Declarers[w.text] && !w.quoted {
					for _, a := range seg[i+1:] {
						if s6Assign.MatchString(a.text) {
							record(a.text)
						}
					}
				}
				break
			}
		}
	}
	return vars
}

// s6Ref is a shell variable reference: $NAME, ${NAME} or ${NAME:-default}
// (and the other operators, whose word counts as a value too).
var s6Ref = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-=+?]([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// s6Substitute returns the line with each variable the script assigns (or
// gives a default) replaced by each of its values, at most 16 variants; the
// line itself when it uses none.
func s6Substitute(line string, vars map[string][]string) []string {
	out := []string{line}
	// Three rounds, so a variable whose value names another (R=root@$H)
	// resolves; each round replaces each distinct reference once, at most 32
	// of them, so a line of thousands of $A stays linear.
	for round := 0; round < 3; round++ {
		changed := false
		var next []string
		for _, l := range out {
			variants := []string{l}
			seen := map[string]bool{}
			for _, m := range s6Ref.FindAllStringSubmatch(l, -1) {
				if seen[m[0]] || len(seen) >= 32 {
					continue
				}
				seen[m[0]] = true
				values := append([]string(nil), vars[m[1]+m[3]]...)
				if m[2] != "" {
					values = append(values, m[2])
				}
				if len(values) == 0 {
					continue
				}
				var vs []string
				for _, v := range variants {
					for _, val := range values {
						if len(vs) < 16 {
							vs = append(vs, strings.ReplaceAll(v, m[0], val))
						}
					}
				}
				variants, changed = vs, true
			}
			for _, v := range variants {
				if len(next) < 16 {
					next = append(next, v)
				}
			}
		}
		out = next
		if !changed {
			break
		}
	}
	return out
}

// shellWord is one word of a shell line, whether any of it was quoted, and
// whether it is the word a redirection (<, >, >>, <>, &>) opens: the file
// the shell opens rather than an argument of the command.
type shellWord struct {
	text   string
	quoted bool
	redir  bool
}

// shellSegments splits a shell line into its commands' words: a new
// segment at an unquoted ;, |, &, (, ) or `, a word break at an unquoted
// space, tab, < or >, and nothing after an unquoted '#' that starts a
// word. It is a reader for the scanner, not a shell: no expansion; a
// backslash escapes the next byte outside quotes and ", \, $ and ` inside
// double quotes, and nothing inside single quotes.
func shellSegments(line string) [][]shellWord { return shellSegmentsAt(line, 0) }

// s6MaxSubst bounds how deep command substitutions are read as their own
// commands; deeper ones are split flat at their parentheses and
// backticks, so a crafted line stays linear.
const s6MaxSubst = 8

func shellSegmentsAt(line string, depth int) [][]shellWord {
	var segs [][]shellWord
	var seg []shellWord
	var cur strings.Builder
	inWord, quoted, redirect := false, false, false
	var quote byte
	flush := func() {
		if inWord {
			seg = append(seg, shellWord{text: cur.String(), quoted: quoted, redir: redirect})
			redirect = false
		}
		cur.Reset()
		inWord, quoted = false, false
	}
	endSeg := func() {
		flush()
		if len(seg) > 0 {
			segs = append(segs, seg)
		}
		seg = nil
	}
	// A command substitution, $(…) or `…`, outside quotes or inside double
	// quotes, is read as commands of its own, and is $_ in the word around it,
	// so ssh $(whoami)@h keeps its destination and out="$(ssh h)" runs ssh.
	substitute := func(i int) int {
		var inner string
		end := len(line)
		if line[i] == '`' {
			if j := strings.IndexByte(line[i+1:], '`'); j >= 0 {
				end = i + 1 + j
			}
			inner = line[i+1 : end]
		} else {
			end = s6CloseParen(line, i+2)
			inner = line[i+2 : min(end, len(line))]
		}
		segs = append(segs, shellSegmentsAt(inner, depth+1)...)
		cur.WriteString("$_")
		inWord = true
		return end
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case depth < s6MaxSubst && quote != '\'' && (c == '`' || (c == '$' && i+1 < len(line) && line[i+1] == '(')):
			i = substitute(i)
		case quote == '"' && c == '\\' && i+1 < len(line) && strings.IndexByte("\"\\$`", line[i+1]) >= 0:
			i++
			cur.WriteByte(line[i])
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
			inWord = true
		case c == '\'' || c == '"':
			quote, quoted, inWord = c, true, true
		case c == '#' && !inWord:
			endSeg()
			return segs
		case c == ' ' || c == '\t' || c == '\r' || c == '<' || c == '>':
			flush()
			if c == '<' || c == '>' {
				// The next word is a file, except after << and <<<, whose
				// next word is a delimiter or a string.
				doubled := (i > 0 && line[i-1] == '<') || (i+1 < len(line) && line[i+1] == '<')
				redirect = c == '>' || !doubled
			}
		case strings.IndexByte(";|&()`", c) >= 0:
			endSeg()
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	endSeg()
	return segs
}

// s6CloseParen is the index of the ) that closes a $( opened before from,
// counting nested parentheses outside quotes; len(line) when none does.
func s6CloseParen(line string, from int) int {
	depth := 1
	var quote byte
	for i := from; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(line)
}

// s6IsLocal is a host a script reaching never leaves the machine for. A
// name that only starts with 127. (127.0.0.1.attacker.example) is not.
func s6IsLocal(h string) bool {
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// s6IsIPv4 is a dotted quad whose octets are at most 255.
func s6IsIPv4(h string) bool {
	if len(s6IPv4.FindString(h)) != len(h) || h == "" {
		return false
	}
	for _, o := range strings.Split(h, ".") {
		if n, err := strconv.Atoi(o); err != nil || n > 255 {
			return false
		}
	}
	return true
}

// s6HostOf normalises a host as read: lower case, no trailing dot, no
// brackets round an IPv6 address; "" for an IPv4-shaped word that is not an
// address (999.1.2.3).
func s6HostOf(h string) string {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if len(s6IPv4.FindString(h)) == len(h) && !s6IsIPv4(h) {
		return ""
	}
	return h
}

// s6AddrWord is a word that is an address and nothing else, with a port
// or a path after it: 10.1.2.3, 10.1.2.3:8080/x, [2001:db8::1]:22.
var s6AddrWord = regexp.MustCompile(`(?i)^(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\])(?::\d+)?(?:/.*)?$`)

// s6AddrCmds read an address given as a word of their own; ssh's family
// is sshDestinations'. s6BindOpts take the local address to bind, which
// is not a host the command reaches.
var (
	s6AddrCmds = map[string]bool{"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "telnet": true, "openssl": true}
	s6BindOpts = map[string]map[string]bool{
		"curl": {"--interface": true, "-o": true, "--output": true, "--retry-delay": true, "-m": true, "--max-time": true, "--connect-timeout": true},
		"wget": {"-O": true, "--output-document": true, "-o": true, "--output-file": true},
		"nc":   {"-s": true}, "ncat": {"-s": true, "--source": true}, "netcat": {"-s": true},
		"telnet": {"-b": true}, "openssl": {"-bind": true},
	}
)

// s6AddrWords are the addresses a shell line's network commands are given
// as words of their own (nc 10.1.2.3 80, curl 10.1.2.3:8080/x), so that a
// version, a header value or another command's argument that only looks
// like an address is not one.
func s6AddrWords(line string) []string {
	var out []string
	for _, seg := range expandSegments(line, 0) {
		cmd, args := segmentCommand(seg)
		if !s6AddrCmds[cmd] || s6Listens(cmd, args) {
			continue
		}
		for i, a := range args {
			if i > 0 && s6BindOpts[cmd][args[i-1].text] {
				continue
			}
			if m := s6AddrWord.FindStringSubmatch(a.text); m != nil {
				out = append(out, m[1])
			} else if ip := s6IPv6Word(a.text); ip != "" {
				out = append(out, ip)
			}
		}
	}
	return out
}

// s6Listens is nc listening (-l, or a flag cluster holding l), whose
// address is the one it binds.
func s6Listens(cmd string, args []shellWord) bool {
	if cmd != "nc" && cmd != "ncat" && cmd != "netcat" {
		return false
	}
	for _, a := range args {
		if !a.quoted && (a.text == "--listen" || (strings.HasPrefix(a.text, "-") && !strings.HasPrefix(a.text, "--") && strings.ContainsRune(a.text, 'l'))) {
			return true
		}
	}
	return false
}

// s6PyJSAddr is an address in Python or JavaScript: a quoted address with a
// port inside the string or as the next argument ("10.0.0.1", 80).
var s6PyJSAddr = regexp.MustCompile(`["'](\d{1,3}(?:\.\d{1,3}){3})(?::\d+["']|["']\s*,\s*\d)`)

// hostsOnLineWith is hostsOnLine over each of the line's variable
// substitutions (s6Substitute); for a shell script only.
func hostsOnLineWith(line string, class scriptClass, vars map[string][]string) []string {
	if class != scriptShell || len(vars) == 0 {
		return hostsOnLine(line, class)
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range s6Substitute(line, vars) {
		for _, h := range hostsOnLine(l, class) {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

func hostsOnLine(line string, class scriptClass) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = s6HostOf(h)
		if h == "" || seen[h] || s6IsLocal(h) {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, m := range s6URLHost.FindAllStringSubmatch(line, -1) {
		add(m[1])
	}
	bare := func(seg string) {
		for _, m := range s6BareHost.FindAllStringSubmatchIndex(seg, -1) {
			h := seg[m[2]:m[3]]
			// A bare token is a host only when it is not a file name (out.txt,
			// listing.csv) and does not continue a path or a curl @file argument.
			if m[2] > 0 && strings.ContainsRune("@/.$", rune(seg[m[2]-1])) {
				continue
			}
			if s6FileExt[strings.ToLower(h[strings.LastIndex(h, ".")+1:])] {
				continue
			}
			add(h)
		}
	}
	if class == scriptShell {
		bare(line)
		for _, h := range s6AddrWords(line) {
			add(h)
		}
		for _, h := range sshDestinations(line) {
			add(h)
		}
	} else {
		for _, m := range s6Quoted.FindAllStringSubmatch(line, -1) {
			bare(m[1])
		}
		for _, m := range s6PyJSAddr.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
	}
	return out
}

// s6FileExt lists the trailing labels that mark a dotted token as a file
// name rather than a host name.
var s6FileExt = map[string]bool{
	"txt": true, "log": true, "csv": true, "tsv": true, "md": true, "json": true, "yaml": true, "yml": true,
	"toml": true, "ini": true, "cfg": true, "conf": true, "env": true, "lock": true, "xml": true, "html": true,
	"htm": true, "css": true, "sh": true, "bash": true, "py": true, "js": true, "mjs": true, "cjs": true,
	"ts": true, "go": true, "rs": true, "rb": true, "java": true, "php": true, "pl": true, "lua": true,
	"c": true, "h": true, "cpp": true, "cs": true, "sql": true, "db": true, "sqlite": true, "png": true,
	"jpg": true, "jpeg": true, "gif": true, "svg": true, "pdf": true, "zip": true, "tar": true, "gz": true,
	"tgz": true, "bz2": true, "xz": true, "exe": true, "dll": true, "so": true, "dylib": true, "bin": true,
	"dat": true, "bak": true, "tmp": true, "out": true, "err": true, "pid": true, "sock": true, "key": true,
	"pem": true, "crt": true, "cer": true, "pub": true, "map": true, "min": true, "test": true, "spec": true,
}

func s6First(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func sortedKeysHit(m map[string]s6Hit) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
