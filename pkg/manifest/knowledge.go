package manifest

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// A release may ship knowledge packs (plan knowledge.md §4.6, D11, D18;
// agentry#594): the pack is made with the Knowledge Creator and travels in
// the release archive under knowledge/<name>/, in the layout the CLI
// writes (agentry-cli pkg/knowledge: manifest.json, wiki/ with its index
// and log, sources/). The manifest names the packs it ships, so the
// registry scans each one as part of the version's scan and a person is
// asked again when a later release ships one more. What a person may
// attach of their own is text for the run setup: it never reaches the
// agent and never widens the contract (attaching is the grant, as for
// /inputs).

// KnowledgeDir is the archive directory shipped packs live under.
const KnowledgeDir = "knowledge"

// Limits of the knowledge block (V11) and of a shipped pack (V8).
const (
	// MaxShippedPacks caps knowledge.ships.
	MaxShippedPacks = 5
	// MaxKnowledgePackBytes caps one shipped pack: its manifest.json and
	// every file of its tree, as the CLI counts a pack (plan D16).
	MaxKnowledgePackBytes = 10 << 20
	// MaxKnowledgePackFiles caps the files of one shipped pack's tree, as
	// the registry's store does.
	MaxKnowledgePackFiles = 2000
	// MaxKnowledgePromptChars caps knowledge.accepts.prompt.
	MaxKnowledgePromptChars = 300
	// KnowledgePackSchema is a pack's manifest.json schema.
	KnowledgePackSchema = "knowledge/v1"
)

// The files of a pack (agentry-cli pkg/knowledge).
const (
	knowledgeManifestFile = "manifest.json"
	knowledgeWikiDir      = "wiki"
	knowledgeSourcesDir   = "sources"
)

// Knowledge is the manifest's knowledge block (v2, V11).
type Knowledge struct {
	// Ships names the packs the archive carries under knowledge/<name>/.
	Ships []ShippedKnowledge `yaml:"ships,omitempty" json:"ships,omitempty"`
	// Accepts asks the person for a pack of their own: shown in the run
	// setup's Knowledge step, never to the agent.
	Accepts *KnowledgeAccepts `yaml:"accepts,omitempty" json:"accepts,omitempty"`
}

// ShippedKnowledge is one pack a release ships.
type ShippedKnowledge struct {
	// Name is the pack's name and its directory under knowledge/.
	Name string `yaml:"name" json:"name"`
}

// KnowledgeAccepts is what a release asks a person to attach.
type KnowledgeAccepts struct {
	// Prompt is one plain line shown in the run setup.
	Prompt string `yaml:"prompt" json:"prompt"`
	// Required means the setup's Knowledge step cannot be skipped.
	Required bool `yaml:"required,omitempty" json:"required,omitempty"`
}

// ShippedPacks returns the names of the packs the release ships, sorted.
func (m *Manifest) ShippedPacks() []string {
	if m == nil || m.Knowledge == nil {
		return nil
	}
	out := make([]string, 0, len(m.Knowledge.Ships))
	for _, s := range m.Knowledge.Ships {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// Contract is the capability contract a person consents to: the declared
// capabilities, and the names of the packs the release ships, so that a
// later release shipping one more asks again (plan §4.6). It is what the
// registry records for a version and an install, and what a client
// compares with DiffCapabilities.
func (m *Manifest) Contract() Capabilities {
	c := m.Capabilities
	c.Knowledge = m.ShippedPacks()
	return c
}

// ValidKnowledgePackName is the CLI's rule for a pack name (agentry-cli
// pkg/knowledge.ValidName): 1-64 lowercase letters, digits, '.', '-' or
// '_', starting with a letter or a digit.
func ValidKnowledgePackName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '-' || r == '_'):
		default:
			return false
		}
	}
	return true
}

// ShippedPackFile says whether p is a file of a shipped pack's tree — under
// knowledge/<name>/wiki/ or knowledge/<name>/sources/ for a name in ships —
// and which pack. A pack's manifest.json is not part of its tree.
func ShippedPackFile(ships []string, p string) (string, bool) {
	rest, ok := strings.CutPrefix(p, KnowledgeDir+"/")
	if !ok {
		return "", false
	}
	name, inner, ok := strings.Cut(rest, "/")
	if !ok || !slices.Contains(ships, name) {
		return "", false
	}
	if strings.HasPrefix(inner, knowledgeWikiDir+"/") || strings.HasPrefix(inner, knowledgeSourcesDir+"/") {
		return name, true
	}
	return "", false
}

// validateKnowledge is V11's manifest half: the block's shape.
func validateKnowledge(s *issues, m *Manifest) {
	k := m.Knowledge
	if k == nil {
		return
	}
	if m.Major() != 2 {
		s.errf("V1", "knowledge", "knowledge is a schemaVersion 2 field")
		return
	}
	if len(k.Ships) == 0 && k.Accepts == nil {
		s.errf("V11", "knowledge", "knowledge must ship a pack or accept one")
	}
	if len(k.Ships) > MaxShippedPacks {
		s.errf("V11", "knowledge.ships", "%d packs; a release ships at most %d", len(k.Ships), MaxShippedPacks)
	}
	seen := map[string]bool{}
	for i, sh := range k.Ships {
		p := fmt.Sprintf("knowledge.ships[%d].name", i)
		switch {
		case !ValidKnowledgePackName(sh.Name):
			s.errf("V11", p, "%q is not a knowledge pack name (1-64 lowercase letters, digits, '.', '-' or '_', starting with a letter or digit)", sh.Name)
		case seen[sh.Name]:
			s.errf("V11", p, "pack %q is shipped twice", sh.Name)
		}
		seen[sh.Name] = true
	}
	if a := k.Accepts; a != nil {
		knowledgeLine(s, "knowledge.accepts.prompt", a.Prompt)
	}
}

// knowledgeLine checks the one line of text the block carries.
func knowledgeLine(s *issues, p, v string) {
	if strings.TrimSpace(v) == "" {
		s.errf("V11", p, "prompt must not be empty")
		return
	}
	if n := utf8.RuneCountInString(v); n > MaxKnowledgePromptChars {
		s.errf("V11", p, "prompt is %d characters; the maximum is %d", n, MaxKnowledgePromptChars)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f || hiddenRune(r) {
			s.errf("V11", p, "prompt must be plain single-line text (no control or format characters)")
			return
		}
	}
}

// validateShippedPacks is V11's context half and V8's pack quota: every
// shipped pack is in the archive in the CLI's layout, within its caps, and
// — when the files can be read — its manifest.json names it and the tree
// it describes; nothing else lives under knowledge/.
func validateShippedPacks(s *issues, m *Manifest, ctx Context, resolved []FileInfo) {
	ships := m.ShippedPacks()
	// The instruction is the release's own and is judged against its
	// contract; a pack's files are read as data, so it cannot be one.
	for _, cand := range m.InstructionCandidates() {
		if strings.HasPrefix(cand, KnowledgeDir+"/") {
			s.errf("V11", "entrypoints", "the instruction file %q is under %s/, which holds knowledge packs", cand, KnowledgeDir)
		}
	}
	inRepo := map[string]bool{}
	for _, f := range ctx.Files {
		inRepo[f.Path] = true
	}
	byPack := map[string][]FileInfo{}
	for _, f := range resolved {
		rest, ok := strings.CutPrefix(f.Path, KnowledgeDir+"/")
		if !ok {
			continue
		}
		name, inner, _ := strings.Cut(rest, "/")
		if inner == "" || !slices.Contains(ships, name) {
			s.errf("V11", "publish.include", "included file %q is under %s/ but not in a pack knowledge.ships names", f.Path, KnowledgeDir)
			continue
		}
		byPack[name] = append(byPack[name], f)
	}
	for _, name := range ships {
		dir := KnowledgeDir + "/" + name + "/"
		mf := dir + knowledgeManifestFile
		files := byPack[name]
		if len(files) == 0 {
			if inRepo[mf] {
				s.errf("V11", "knowledge.ships", "pack %q (%s) is not matched by publish.include", name, dir)
			} else {
				s.errf("V11", "knowledge.ships", "pack %q is not in the repo: %s is missing", name, mf)
			}
			continue
		}
		var bytes int64
		tree := 0
		has := map[string]bool{}
		for _, f := range files {
			inner := strings.TrimPrefix(f.Path, dir)
			has[inner] = true
			bytes += f.Size
			switch {
			case inner == knowledgeManifestFile:
			case strings.HasPrefix(inner, knowledgeWikiDir+"/"), strings.HasPrefix(inner, knowledgeSourcesDir+"/"):
				tree++
			default:
				s.errf("V11", "knowledge.ships", "pack %q: %s does not belong in a knowledge pack (only %s, %s/ and %s/)", name, f.Path, knowledgeManifestFile, knowledgeWikiDir, knowledgeSourcesDir)
			}
		}
		for _, want := range []string{knowledgeManifestFile, knowledgeWikiDir + "/index.md", knowledgeWikiDir + "/log.md"} {
			if !has[want] {
				s.errf("V11", "knowledge.ships", "pack %q: %s%s is missing", name, dir, want)
			}
		}
		if bytes > MaxKnowledgePackBytes {
			s.errf("V8", "knowledge.ships", "pack %q is %d bytes; a pack is at most %d", name, bytes, MaxKnowledgePackBytes)
		}
		if tree > MaxKnowledgePackFiles {
			s.errf("V8", "knowledge.ships", "pack %q holds %d files; a pack holds at most %d", name, tree, MaxKnowledgePackFiles)
		}
		if ctx.ReadFile != nil && has[knowledgeManifestFile] && bytes <= MaxKnowledgePackBytes && tree <= MaxKnowledgePackFiles {
			checkPackManifest(s, name, dir, files, ctx.ReadFile)
		}
	}
}

// checkPackManifest reads a shipped pack's manifest.json and checks it is
// the pack's own: its schema, its name, and the digest, bytes and pages of
// the tree beside it — what the CLI's pkg/knowledge.Load checks before it
// mounts the pack, so a release the runner would refuse is refused here.
func checkPackManifest(s *issues, name, dir string, files []FileInfo, read func(string) ([]byte, error)) {
	raw, err := read(dir + knowledgeManifestFile)
	if err != nil {
		s.errf("V11", "knowledge.ships", "pack %q: %s could not be read: %v", name, dir+knowledgeManifestFile, err)
		return
	}
	var pm struct {
		Schema string `json:"schema"`
		Name   string `json:"name"`
		Pages  int    `json:"pages"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &pm); err != nil {
		s.errf("V11", "knowledge.ships", "pack %q: %s does not parse: %v", name, dir+knowledgeManifestFile, err)
		return
	}
	if pm.Schema != KnowledgePackSchema {
		s.errf("V11", "knowledge.ships", "pack %q: schema %q is not %q", name, pm.Schema, KnowledgePackSchema)
	}
	if pm.Name != name {
		s.errf("V11", "knowledge.ships", "pack %q: its manifest.json names %q; a shipped pack's directory is its name", name, pm.Name)
	}
	tree := map[string][]byte{}
	for _, f := range files {
		inner := strings.TrimPrefix(f.Path, dir)
		if inner == knowledgeManifestFile {
			continue
		}
		b, err := read(f.Path)
		if err != nil {
			s.errf("V11", "knowledge.ships", "pack %q: %s could not be read: %v", name, f.Path, err)
			return
		}
		tree[inner] = b
	}
	digest, bytes, pages, err := KnowledgeTreeDigest(tree)
	if err != nil {
		s.errf("V11", "knowledge.ships", "pack %q: %v", name, err)
		return
	}
	if digest != pm.SHA256 {
		s.errf("V11", "knowledge.ships", "pack %q: its files do not match the digest in its manifest.json (manifest %s, files %s)", name, pm.SHA256, digest)
	}
	if pm.Bytes != bytes || pm.Pages != pages {
		s.errf("V11", "knowledge.ships", "pack %q: manifest.json says %d pages and %d bytes, the files are %d pages and %d bytes", name, pm.Pages, pm.Bytes, pages, bytes)
	}
}

// KnowledgeTreeDigest is a pack's tree digest, "sha256:<hex>", with its
// bytes and pages, over files keyed by their slash path in the pack
// ("wiki/index.md", "sources/a.txt"): the SHA-256 of the canonical tar
// agentry-cli's pkg/knowledge.TreeDigest writes and the registry's store
// reads (every file in byte order of its path, mode 0644, uid and gid 0,
// mtime 0, a PAX header only when a name needs one, two zero blocks).
func KnowledgeTreeDigest(files map[string][]byte) (digest string, bytes int64, pages int, err error) {
	h := sha256.New()
	tw := tar.NewWriter(h)
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: p, Mode: 0o644, Size: int64(len(files[p])),
			ModTime: time.Unix(0, 0), Format: tar.FormatPAX,
		}); err != nil {
			return "", 0, 0, err
		}
		if _, err := tw.Write(files[p]); err != nil {
			return "", 0, 0, err
		}
		bytes += int64(len(files[p]))
		if strings.HasPrefix(p, knowledgeWikiDir+"/") && strings.HasSuffix(p, ".md") &&
			path.Base(p) != "index.md" && p != knowledgeWikiDir+"/log.md" {
			pages++
		}
	}
	if err := tw.Close(); err != nil {
		return "", 0, 0, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), bytes, pages, nil
}
