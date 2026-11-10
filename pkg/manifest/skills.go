package manifest

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Shipped skills. A QuickAgent may ship skills: folders of instructions
// for one kind of work, each skills/<name>/SKILL.md in the Agent Skills
// shape, opening with frontmatter that gives the skill's name and a
// description of when to use it. A runner lists each skill to the model by
// its name and description and lets the model read the rest when a step
// matches, so a release can carry procedures without growing its prompt.
//
// capabilities.skills declares it (V20), so the skills are reviewed and
// consented to like every other line of the contract, and the archive's
// skills/ folder is read only with it. A persistent agent declares its
// skills as capabilities.persistent.skills instead (V16), which also gives
// it the skills the person adds; a release never declares both.

// ShippedSkillsWords say what capabilities.skills gives, in the words
// consent and the capability diff use.
const ShippedSkillsWords = "the skills it ships"

// Bounds on a release's shipped skills. Every skill costs the run's
// prompt one line, its name and description, so the count and the
// description are bounded; the name follows the Agent Skills rule.
const (
	// MaxShippedSkills is the most skills one release ships.
	MaxShippedSkills = 16
	// MaxSkillNameBytes bounds a skill's name, and so its folder.
	MaxSkillNameBytes = 64
	// MaxSkillDescriptionBytes bounds a skill's description.
	MaxSkillDescriptionBytes = 1024
)

// skillNameRE is a skill's name: lowercase letters and digits in words
// joined by single hyphens.
var skillNameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ShipsSkills reports whether the release gives its runs the skills in its
// skills/ folder: capabilities.skills, or a persistent agent's
// capabilities.persistent.skills.
func (m *Manifest) ShipsSkills() bool {
	return m.Capabilities.Skills || m.Capabilities.Persistent.Declares("skills")
}

// validateSkills is V20's manifest half: capabilities.skills is a v2
// field, and a persistent agent declares its skills in its own block.
func validateSkills(s *issues, m *Manifest) {
	if !m.Capabilities.Skills {
		return
	}
	if m.Major() != 2 {
		s.errf("V1", "capabilities.skills", "skills is a v2 field; set schemaVersion: 2")
		return
	}
	if !m.IsPersistent() {
		return
	}
	if m.Capabilities.Persistent.Declares("skills") {
		s.errf("V20", "capabilities.skills", "capabilities.skills and capabilities.persistent.skills both declare the release's skills: a persistent agent declares them once, as capabilities.persistent.skills")
		return
	}
	s.errf("V20", "capabilities.skills", "a persistent agent declares its skills as capabilities.persistent.skills: move the key there")
}

// validateShippedSkills is V20's archive half for a release that is not
// persistent (V16 reads a persistent agent's folders). The archive's
// skills/ folder is read only with capabilities.skills: without it, a
// warning, since the runner leaves it unread. With it, the archive ships
// at least one skill and at most MaxShippedSkills, each a folder of its
// own whose name is a skill name, carrying SKILL.md whose frontmatter
// names the skill as its folder does and describes it in one plain line,
// which is what the runner lists.
func validateShippedSkills(s *issues, m *Manifest, ctx Context, resolved []FileInfo) {
	if m.IsPersistent() {
		return
	}
	declared := m.Capabilities.Skills
	var stray []string
	folders := map[string]bool{}
	for _, f := range resolved {
		rest, ok := strings.CutPrefix(f.Path, SkillsDir+"/")
		if !ok {
			continue
		}
		name, inner, nested := strings.Cut(rest, "/")
		if !nested {
			stray = append(stray, f.Path)
			continue
		}
		folders[name] = folders[name] || inner == SkillFile
	}
	if !declared {
		if len(folders) > 0 || len(stray) > 0 {
			s.warnf("V20", "publish.include", "the archive carries %s/, which gives the agent skills only with capabilities.skills; without it the runner does not read it", SkillsDir)
		}
		return
	}
	for _, p := range stray {
		s.errf("V20", "publish.include", "%q is not in a skill's folder: each skill is %s/<name>/ with its %s", p, SkillsDir, SkillFile)
	}
	if len(folders) == 0 {
		s.errf("V20", "capabilities.skills", "capabilities.skills is declared but the archive ships no skill: add %s/<name>/%s, or remove the key", SkillsDir, SkillFile)
		return
	}
	if len(folders) > MaxShippedSkills {
		s.errf("V20", "publish.include", "the archive ships %d skills; the maximum is %d", len(folders), MaxShippedSkills)
	}
	for _, name := range slices.Sorted(maps.Keys(folders)) {
		dir := SkillsDir + "/" + name + "/"
		switch {
		case len(name) > MaxSkillNameBytes || !skillNameRE.MatchString(name):
			s.errf("V20", "publish.include", "the skill folder %s is named %q: a skill's name is at most %d lowercase letters, digits and single hyphens", dir, name, MaxSkillNameBytes)
		case !folders[name]:
			s.errf("V20", "publish.include", "the skill folder %s has no %s", dir, SkillFile)
		default:
			checkSkillFile(s, ctx, name, dir+SkillFile)
		}
	}
}

// checkSkillFile checks one skill's SKILL.md frontmatter: present, read
// as YAML, its name the folder's and its description one plain line of at
// most MaxSkillDescriptionBytes. A context that cannot read files leaves
// it to the archive's own check.
func checkSkillFile(s *issues, ctx Context, name, path string) {
	if ctx.ReadFile == nil {
		return
	}
	content, err := ctx.ReadFile(path)
	if err != nil {
		return // V4 reports a file the include names but the tree lacks
	}
	fm, ok, perr := ParseFrontmatter(content)
	switch {
	case !ok:
		s.errf("V20", "publish.include", "%s has no frontmatter: open it with a --- block giving name: %s and a description of when to use it", path, name)
		return
	case perr != nil:
		s.errf("V20", "publish.include", "%s: frontmatter does not parse as YAML (%v)", path, perr)
		return
	}
	if fm.Name != name {
		s.errf("V20", "publish.include", "%s: frontmatter name %q differs from its folder %q", path, fm.Name, name)
	}
	switch {
	case fm.Description == "":
		s.errf("V20", "publish.include", "%s has no description: the agent chooses a skill by its description", path)
	case len(fm.Description) > MaxSkillDescriptionBytes:
		s.errf("V20", "publish.include", "%s: the description is %d bytes; the maximum is %d", path, len(fm.Description), MaxSkillDescriptionBytes)
	default:
		if msg := notPlain(fmt.Sprintf("%s: the description", path), fm.Description); msg != "" {
			s.errf("V20", "publish.include", "%s", msg)
		}
	}
}
