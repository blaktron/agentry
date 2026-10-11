package manifest

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// Target hosts (plan runtime-hosts.md §4, D2, D10, D13, D17; agentry#1092).
// A target host is a machine the person names when a run starts, such as a
// Linux server to set up or manage, that the runner reaches over SSH from a
// container of its own (the host link) and the agent works through the
// runner's host tools. The release declares that it takes one, never which:
// an intake question of type host, whose id is listed in
// capabilities.targetHosts. The answer, [user@]host[:port], belongs to the
// run, as a source's URL does, and no address, user, port or credential is
// ever in the manifest.
//
// Unlike a source, a target host is inside the contract: the agent acts on
// the machine, so consent shows it, an upgrade that adds one asks again, the
// judge reads it as a declared capability (pkg/judge RunnerGrants), and
// search can filter on it. It grants nothing else: it is not network egress,
// and a script the release ships that runs ssh itself is still the
// release's own network (S6).

// MaxTargetHosts bounds the target hosts one release may declare (D13).
const MaxTargetHosts = 4

// remoteShellClients are the programs that make an SSH or rsync session.
// An exec declaration naming one is pointed at targetHosts (D10).
var remoteShellClients = []string{"ssh", "scp", "sftp", "rsync"}

// RemoteShellCommands returns the commands of c's exec declaration that
// make a remote session themselves (ssh, scp, sftp, rsync), in declaration
// order, compared by program name. V14 warns on them and S1 reports them
// low: such a release would make its own connection, where a declared
// target host has the runner make it.
func RemoteShellCommands(c Capabilities) []string {
	var out []string
	for _, cmd := range c.Exec.Commands {
		if isRemoteShellClient(cmd) {
			out = append(out, cmd)
		}
	}
	return out
}

func isRemoteShellClient(cmd string) bool {
	return slices.Contains(remoteShellClients, strings.ToLower(path.Base(cmd)))
}

// HostQuestions returns the release's intake questions of type host, in
// intake order.
func (m *Manifest) HostQuestions() []IntakeQuestion {
	var out []IntakeQuestion
	for _, q := range m.Intake {
		if q.Type == IntakeHost {
			out = append(out, q)
		}
	}
	return out
}

// validateTargetHosts is V14: capabilities.targetHosts and the host
// questions name each other one to one, at most MaxTargetHosts of them; a
// host question's shape beyond that (an id, a prompt, no choices) is V10's.
// An exec declaration that names an SSH client is warned toward targetHosts.
func validateTargetHosts(s *issues, m *Manifest) {
	c := m.Capabilities
	if m.Major() != 2 {
		if len(c.TargetHosts) > 0 {
			s.errf("V1", "capabilities.targetHosts", "targetHosts is a v2 field; set schemaVersion: 2")
		}
		return
	}
	if len(c.TargetHosts) > MaxTargetHosts {
		s.errf("V14", "capabilities.targetHosts", "%d target hosts; the maximum is %d", len(c.TargetHosts), MaxTargetHosts)
	}
	hostQ := map[string]bool{}
	for _, q := range m.HostQuestions() {
		hostQ[q.ID] = true
	}
	listed := make(map[string]bool, len(c.TargetHosts))
	for i, id := range c.TargetHosts {
		p := fmt.Sprintf("capabilities.targetHosts[%d]", i)
		switch {
		case listed[id]:
			s.errf("V14", p, "duplicate target host %q", id)
		case !hostQ[id]:
			s.errf("V14", p, "%q names no intake question of type host: a target host is the answer to one", id)
		}
		listed[id] = true
	}
	for i, q := range m.Intake {
		if q.Type == IntakeHost && !listed[q.ID] {
			s.errf("V14", fmt.Sprintf("intake[%d].type", i), "host question %q is not listed in capabilities.targetHosts: a target host is part of the contract a person consents to", q.ID)
		}
	}
	for i, cmd := range c.Exec.Commands {
		if !isRemoteShellClient(cmd) {
			continue
		}
		s.warnf("V14", fmt.Sprintf("capabilities.exec.commands[%d]", i),
			"exec names %q: to work a machine the person names at run time, declare a target host instead (an intake question of type host, listed in capabilities.targetHosts), so the runner makes the SSH session and not the agent", cmd)
	}
}
