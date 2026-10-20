package scan

import (
	"slices"
	"testing"
)

const s6QuotedOptionsManifest = `{"capabilities":{"exec":{"commands":["ssh","sftp","scp","autossh","mosh","sh","bash","curl","nc"]}}}`

// s6UndeclaredHosts is every host S6 reports an undeclared network call to
// for one script line.
func s6UndeclaredHosts(t *testing.T, line string) []string {
	t.Helper()
	var hosts []string
	for _, f := range s6RunAll(t, s6QuotedOptionsManifest, map[string]string{"run.sh": "#!/bin/sh\n" + line + "\n"}) {
		if f.Scanner == "S6/undeclared-network" {
			if h, ok := f.Detail["host"].(string); ok {
				hosts = append(hosts, h)
			}
		}
	}
	slices.Sort(hosts)
	return hosts
}

// TestS6ReadsAQuotedOption pins that an option word is recognised by its
// unquoted text, whole or partly quoted, as the shell passes it: each line
// runs exactly like its unquoted form, so S6 reads the same hosts from it.
func TestS6ReadsAQuotedOption(t *testing.T) {
	for _, c := range []struct {
		line string
		want []string
	}{
		// ssh's options, and a quoted -- that ends them.
		{`ssh '-p' 2222 admin@p.example.org`, []string{"p.example.org"}},
		{`ssh "-p2222" admin@p2.example.org`, []string{"p2.example.org"}},
		{`ssh -'p' 2222 admin@partial.example.org`, []string{"partial.example.org"}},
		{`ssh '-o' StrictHostKeyChecking=no admin@o.example.org`, []string{"o.example.org"}},
		{`ssh "-L" 8080:localhost:80 admin@l.example.org`, []string{"l.example.org"}},
		{`ssh "--" admin@dashdash.example.org`, []string{"dashdash.example.org"}},
		// After --, quoted or not, the next word is the destination ssh is
		// given (and refuses, since it starts with -), never an option.
		{`ssh -- -oProxyJump=10.20.30.50`, nil},
		{`ssh "--" -oProxyJump=10.20.30.51`, nil},
		{`ssh '-J' jump.example.net admin@j.example.org`, []string{"j.example.org", "jump.example.net"}},
		{`ssh -"o" ProxyJump=hop.example.net admin@pj.example.org`, []string{"hop.example.net", "pj.example.org"}},
		// The same reader for sftp and autossh.
		{`sftp '-P' 2222 admin@sftp.example.org`, []string{"sftp.example.org"}},
		{`autossh "-M" 0 admin@auto.example.org`, []string{"auto.example.org"}},
		// scp's options: a quoted -o ProxyJump is a jump host, not an operand.
		{`scp '-oProxyJump=10.20.30.40' notes.txt admin@scp.example.org:/tmp/`, []string{"10.20.30.40", "scp.example.org"}},
		// mosh's long options take their argument, quoted or not.
		{`mosh '--port' 60001 admin@mosh.example.org`, []string{"mosh.example.org"}},
		// A shell's -c string is read as commands.
		{`"bash" "-c" 'curl -s https://bashc.example.org/x'`, []string{"bashc.example.org"}},
		{`sh "-c" 'ssh admin@shc.example.org'`, []string{"shc.example.org"}},
		{`bash '-ec' "ssh admin@ec.example.org"`, []string{"ec.example.org"}},
	} {
		if got := s6UndeclaredHosts(t, c.line); !slices.Equal(got, c.want) {
			t.Errorf("%s: undeclared hosts %v, want %v", c.line, got, c.want)
		}
	}
}

// TestS6QuotedListenIsAListen pins that nc told to listen with a quoted -l
// binds the address it is given, as unquoted -l does, rather than reaching
// it.
func TestS6QuotedListenIsAListen(t *testing.T) {
	for _, line := range []string{
		`nc -l 10.9.8.7 4444`,
		`nc '-l' 10.9.8.7 4444`,
		`nc "-lvp" 10.9.8.7 4444`,
		`nc -vl 10.9.8.7 4444`,
		`nc -p 4444 -l 10.9.8.7`,
		`ncat --listen 10.9.8.7 4444`,
	} {
		if got := s6UndeclaredHosts(t, line); len(got) != 0 {
			t.Errorf("%s: undeclared hosts %v, want none", line, got)
		}
	}
}

// TestS6AnLInAnOptionArgumentIsNoListen pins that only nc's flag letters
// make a listen: an l inside the argument of an option that takes one,
// in the same word or the next, quoted or not, leaves nc reaching the
// address.
func TestS6AnLInAnOptionArgumentIsNoListen(t *testing.T) {
	for _, c := range []struct{ line, want string }{
		{`nc -e '-lol' 10.1.2.3 80`, "10.1.2.3"},
		{`nc -e -lol 10.1.2.4 80`, "10.1.2.4"},
		{`nc "-s localhost" 10.1.2.5 80`, "10.1.2.5"},
		{`nc -slocalhost 10.1.2.6 80`, "10.1.2.6"},
		{`nc -w 5 -s lo 10.1.2.7 80`, "10.1.2.7"},
	} {
		if got := s6UndeclaredHosts(t, c.line); !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s: undeclared hosts %v, want [%s]", c.line, got, c.want)
		}
	}
}

// TestS6ScpOperandsAfterDashDash pins that -- ends scp's and rsync's
// options: an operand after it is read as an operand even when it starts
// with -, quoted or not.
func TestS6ScpOperandsAfterDashDash(t *testing.T) {
	for _, line := range []string{
		`scp -- notes.txt -x@dd1.example.org:/tmp/`,
		`rsync -- notes.txt '-x@dd1.example.org:/tmp/'`,
		`scp "--" notes.txt -x@dd1.example.org:/tmp/`,
	} {
		if got := s6UndeclaredHosts(t, line); !slices.Equal(got, []string{"dd1.example.org"}) {
			t.Errorf("%s: undeclared hosts %v, want [dd1.example.org]", line, got)
		}
	}
}
