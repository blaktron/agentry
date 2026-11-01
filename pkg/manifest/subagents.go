package manifest

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Masterminds/semver/v3"
)

// MaxSubagents bounds the subagents one persistent release may declare.
const MaxSubagents = 16

// MaxSubagentWhyChars bounds a dependency's why, the reason consent shows.
const MaxSubagentWhyChars = 200

// Subagents returns the release's subagents: its dependencies.agents when
// it supports the persistent mode, nil otherwise, where the list stays
// informational. The slice is the caller's own.
func (m *Manifest) Subagents() []AgentDependency {
	if !m.IsPersistent() || len(m.Dependencies.Agents) == 0 {
		return nil
	}
	return append([]AgentDependency(nil), m.Dependencies.Agents...)
}

// validateSubagents is V18: in a persistent release, dependencies.agents
// are its subagents, at most MaxSubagents, each once, none the release
// itself, each with a semver constraint and a why. A why is one plain
// line of at most MaxSubagentWhyChars in any release.
func validateSubagents(s *issues, m *Manifest) {
	persistent := m.IsPersistent()
	if persistent && len(m.Dependencies.Agents) > MaxSubagents {
		s.errf("V18", "dependencies.agents", "%d subagents; the maximum is %d", len(m.Dependencies.Agents), MaxSubagents)
	}
	self := m.Namespace + "/" + m.Name
	seen := map[string]bool{}
	for i, dep := range m.Dependencies.Agents {
		p := fmt.Sprintf("dependencies.agents[%d]", i)
		if dep.Why != "" {
			if n := utf8.RuneCountInString(dep.Why); n > MaxSubagentWhyChars {
				s.errf("V18", p+".why", "why is %d characters; the maximum is %d", n, MaxSubagentWhyChars)
			}
			if msg := notPlain("why", dep.Why); msg != "" {
				s.errf("V18", p+".why", "%s", msg)
			}
		}
		if !persistent {
			continue
		}
		if strings.TrimSpace(dep.Version) == "" {
			s.errf("V18", p+".version", "a subagent needs a semver constraint, such as ^1.2.0")
		}
		if strings.TrimSpace(dep.Why) == "" {
			s.errf("V18", p+".why", "a subagent needs a why: one line, shown when the person agrees, saying what the agent uses it for")
		}
		switch {
		case dep.Ref == self:
			s.errf("V18", p+".ref", "a release cannot be its own subagent")
		case seen[dep.Ref]:
			s.errf("V18", p+".ref", "duplicate subagent %q", dep.Ref)
		}
		seen[dep.Ref] = true
	}
}

// SubagentAllows reports whether version satisfies the subagent's
// constraint; false when either does not parse.
func (d AgentDependency) SubagentAllows(version string) bool {
	c, err := semver.NewConstraint(d.Version)
	if err != nil {
		return false
	}
	v, err := semver.StrictNewVersion(version)
	if err != nil {
		return false
	}
	return c.Check(v)
}
