package scan

import (
	"net"
	"regexp"
	"strings"
)

// The network forms of a shell script that name a host without a network
// command's own words: a bash redirection to /dev/tcp or /dev/udp, a socat
// address, a git remote written user@host:path, a container image reference
// whose first component is a registry, and an IPv6 address written without
// brackets. Each is read from the words of a command (shellSegments), so a
// string, an echoed argument or a comment that only mentions one is not a
// host.
//
// Not read, because a static reader cannot know the value: a host that
// reaches the command through a loop variable over an array, a line read
// from a file (while read h; do ssh "$h"; done < hosts.txt) or the output of
// another command (H=$(cat host.txt)).

// netFormHostsWith is netFormHosts over each of the line's variable
// substitutions (s6Substitute), so a host a script keeps in a variable is
// read where the form uses it.
func netFormHostsWith(line string, vars map[string][]string) []string {
	lines := []string{line}
	if len(vars) > 0 {
		lines = s6Substitute(line, vars)
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		for _, h := range netFormHosts(l) {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// netFormHosts are the hosts, lower case and with no brackets, that the
// forms above name on a shell line. Loopback and unspecified addresses are
// not hosts.
func netFormHosts(line string) []string {
	// Cheap test first: most lines name none of these commands or devices.
	low := strings.ToLower(line)
	if !strings.Contains(low, "/dev/") && !strings.Contains(low, "socat") && !strings.Contains(low, "git") &&
		!strings.Contains(low, "docker") && !strings.Contains(low, "podman") {
		return nil
	}
	var raw []string
	for _, seg := range expandSegments(line, 0) {
		for _, w := range seg {
			if w.redir {
				raw = append(raw, devNetHost(w.text)...)
			}
		}
		cmd, args := segmentCommand(seg)
		switch cmd {
		case "socat":
			raw = append(raw, socatHosts(args)...)
		case "git":
			raw = append(raw, gitRemoteHosts(args)...)
		case "docker", "podman":
			raw = append(raw, imageRegistryHosts(args)...)
		}
	}
	var out []string
	for _, h := range raw {
		if h = s6HostOf(h); h != "" && !s6IsLocal(h) {
			out = append(out, h)
		}
	}
	return out
}

// s6WordHost is a word read as a host: a dotted name that is not a file
// name, an IPv4 address, or an IPv6 address with or without brackets.
func s6WordHost(w string) []string {
	if m := s6DestHost.FindStringSubmatch(w); m != nil && !s6LooksLikeFile(m[1]) {
		return []string{m[1]}
	}
	if ip := s6IPv6Word(w); ip != "" {
		return []string{ip}
	}
	return nil
}

// s6IPv6Word is w lower-cased when it is an IPv6 address written without
// brackets and nothing else (2001:db8::1), "" otherwise. A time (12:34:56),
// a hardware address (aa:bb:cc:dd:ee:ff), a zone-qualified address and a
// word with other characters are not one.
func s6IPv6Word(w string) string {
	if strings.Count(w, ":") < 2 || strings.Trim(w, "0123456789abcdefABCDEF:.") != "" || net.ParseIP(w) == nil {
		return ""
	}
	return strings.ToLower(w)
}

// s6User matches the whole of an ssh destination's or a git remote's user.
var s6User = regexp.MustCompile(`(?i)^` + s6UserRe + `$`)

// devNetPath is a /dev/tcp/HOST/PORT or /dev/udp/HOST/PORT file name, which
// bash opens as a connection when a redirection names it.
var devNetPath = regexp.MustCompile(`(?i)^/dev/(?:tcp|udp)/([^/]+)/[^/]+$`)

// devNetHost is the host of a redirection's target word, when it is one of
// bash's network devices.
func devNetHost(word string) []string {
	if m := devNetPath.FindStringSubmatch(word); m != nil {
		return s6WordHost(m[1])
	}
	return nil
}

// socatConnect are socat's address types that open a connection to, or send
// to, the host they name. The listening types (TCP-LISTEN and the like) name
// a local port only.
var socatConnect = map[string]bool{
	"TCP": true, "TCP4": true, "TCP6": true, "TCP-CONNECT": true, "TCP4-CONNECT": true, "TCP6-CONNECT": true,
	"UDP": true, "UDP4": true, "UDP6": true, "UDP-CONNECT": true, "UDP4-CONNECT": true, "UDP6-CONNECT": true,
	"UDP-SENDTO": true, "UDP4-SENDTO": true, "UDP6-SENDTO": true,
	"UDP-DATAGRAM": true, "UDP4-DATAGRAM": true, "UDP6-DATAGRAM": true,
	"OPENSSL": true, "OPENSSL-CONNECT": true,
}

// socatHosts reads each argument written TYPE:host:port[,options] with a
// connecting TYPE (socat keywords are case-insensitive). An IPv6 host is
// written in brackets.
func socatHosts(args []shellWord) []string {
	var out []string
	for _, a := range args {
		kw, rest, ok := strings.Cut(a.text, ":")
		if !ok || !socatConnect[strings.ToUpper(kw)] {
			continue
		}
		var host string
		if strings.HasPrefix(rest, "[") {
			if j := strings.IndexByte(rest, ']'); j > 0 {
				host = rest[:j+1]
			}
		} else {
			host, _, _ = strings.Cut(rest, ":")
			host, _, _ = strings.Cut(host, ",")
		}
		out = append(out, s6WordHost(host)...)
	}
	return out
}

// gitScpRemote is git's scp-like remote, user@host:path, which git reads as
// ssh when no scheme and no slash comes before the colon.
var gitScpRemote = regexp.MustCompile(`(?i)^` + s6UserRe + `@(` + s6HostRe + `):\S*$`)

// gitRemoteCmds are the git subcommands that take a remote, as a name or a
// location. Others (commit, config, log, tag) have words that look like
// user@host:path and are messages or settings.
var gitRemoteCmds = map[string]bool{"clone": true, "fetch": true, "pull": true, "push": true, "ls-remote": true, "remote": true, "submodule": true, "subtree": true}

// gitRemoteHosts reads the scp-like remotes among the words of a git
// subcommand that takes one. git's own options before the subcommand
// (-C path, -c name=value, --git-dir …) are skipped.
func gitRemoteHosts(args []shellWord) []string {
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a.quoted || !strings.HasPrefix(a.text, "-") {
			break
		}
		switch a.text {
		case "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--exec-path", "--config-env":
			i++
		}
	}
	if i >= len(args) || !gitRemoteCmds[args[i].text] {
		return nil
	}
	var out []string
	for _, a := range args[i+1:] {
		if m := gitScpRemote.FindStringSubmatch(a.text); m != nil && !s6LooksLikeFile(m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

// imageRegistryHosts reads the image references of docker's and podman's
// pull and push (also image pull, image push). The first component of a
// reference is a registry when it holds a dot or a port, as it does for the
// container tools themselves, and only when a path follows it:
// registry.example.org:5000/app is a registry and app, example.org:5000 is
// an image named example.org with a tag.
func imageRegistryHosts(args []shellWord) []string {
	i := 0
	for i < len(args) && !args[i].quoted && strings.HasPrefix(args[i].text, "-") {
		i++
	}
	if i < len(args) && (args[i].text == "image" || args[i].text == "container") {
		i++
	}
	if i >= len(args) || (args[i].text != "pull" && args[i].text != "push") {
		return nil
	}
	var out []string
	for _, a := range args[i+1:] {
		if !a.quoted && strings.HasPrefix(a.text, "-") {
			continue
		}
		comp, _, ok := strings.Cut(a.text, "/")
		if !ok || comp == "" || !strings.ContainsAny(comp, ".:") {
			continue
		}
		host := comp
		if strings.HasPrefix(comp, "[") {
			if j := strings.IndexByte(comp, ']'); j > 0 {
				host = comp[:j+1]
			}
		} else if j := strings.LastIndexByte(comp, ':'); j > 0 && strings.Trim(comp[j+1:], "0123456789") == "" {
			host = comp[:j]
		}
		out = append(out, s6WordHost(host)...)
	}
	return out
}
