package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// scannerS4 is the pipeline stage id for signature-engine findings.
const scannerS4 = "S4"

// Manifest is the bundle.yaml document at the root of a rule bundle. It gives
// the bundle a semantic version that is recorded on every scan_run (§8.3) and
// pinned in the CLI release (D-12).
type Manifest struct {
	// Version is the bundle's semantic version, e.g. "0.1.0".
	Version string `yaml:"version"`
	// Notes is free-form release notes for the bundle.
	Notes string `yaml:"notes"`
	// NotPatterns are suppressions applied to EVERY rule in the bundle, in
	// addition to each rule's own. They exist for cross-cutting precision
	// concerns — most importantly descriptive framing: prose that catalogues
	// an attack ("prompts to echo secrets", "look for exfiltration
	// directives") rather than issuing it. §17.3 requires that an agent
	// *about* prompt-injection defense remain publishable, and repeating the
	// same alternation in every rule file guarantees it drifts.
	//
	// Like per-rule notPatterns these are scoped to the matched line, so a
	// single descriptive phrase cannot whitelist a whole file.
	NotPatterns []string `yaml:"notPatterns"`
}

// Fixtures are the required per-rule test strings (§8.3: "every rule ships
// with match + non-match fixtures"). The fixture-runner test asserts that
// every Match string produces the rule's finding and every NonMatch string
// does not.
type Fixtures struct {
	// Match holds strings that MUST trigger the rule (recall).
	Match []string `yaml:"match"`
	// NonMatch holds benign look-alike strings that MUST NOT trigger the rule
	// (precision — §17.3 benign lookalikes).
	NonMatch []string `yaml:"nonMatch"`
}

// Rule is one signature as authored in a YAML family file.
type Rule struct {
	// ID is the rule identifier, "family-nnn" (e.g. "instruction-override-001").
	// Findings use "S4/<ID>".
	ID string `yaml:"id"`
	// Family groups related rules (one of the six §8.3 S4 families).
	Family string `yaml:"family"`
	// Title is a short human-readable summary.
	Title string `yaml:"title"`
	// Severity is the finding severity (info|low|medium|high|critical).
	Severity Severity `yaml:"severity"`
	// Confidence is the finding confidence (low|medium|high).
	Confidence Confidence `yaml:"confidence"`
	// Description explains what the rule detects and why.
	Description string `yaml:"description"`
	// References are external citations (OWASP ids, advisories, docs).
	References []string `yaml:"references"`
	// Patterns are Go regular expressions; a line/text matching any of them is
	// a candidate hit. Case-insensitive by default (see compileRule).
	Patterns []string `yaml:"patterns"`
	// NotPatterns suppress a candidate hit when any of them matches the same
	// line(s) — used to exempt benign discussion of an attack.
	NotPatterns []string `yaml:"notPatterns"`
	// Fixtures are the mandatory match/non-match test strings.
	Fixtures Fixtures `yaml:"fixtures"`
}

// ruleFile is the on-disk shape of a family YAML file: a list of rules.
type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// compiledRule is a Rule with its expressions compiled, ready to evaluate.
type compiledRule struct {
	Rule
	patterns    []*regexp.Regexp
	notPatterns []*regexp.Regexp
	// bundleNotPatterns are the bundle-level suppressions (descriptive
	// framing). They evaluate over the containing PARAGRAPH rather than the
	// matched line, because prose wraps mid-sentence: "Prompts to echo
	// secrets, / paste tokens into output" is one sentence on two lines, and
	// the marker only appears on the first.
	bundleNotPatterns []*regexp.Regexp
}

// Bundle is a loaded, compiled, versioned rule set (the S4 engine input). It
// is the ruleset_releases artifact of §8.3, shared byte-for-byte between the
// server pipeline and the CLI.
type Bundle struct {
	manifest Manifest
	rules    []*compiledRule
	digest   string
}

// Version returns the bundle's semantic version from bundle.yaml.
func (b *Bundle) Version() string { return b.manifest.Version }

// Notes returns the bundle's release notes.
func (b *Bundle) Notes() string { return b.manifest.Notes }

// Digest returns the bundle's content digest: the hex-encoded SHA-256 over the
// sorted, byte-exact rule files (including bundle.yaml). Two loads of the same
// files always yield the same digest, so it is a stable bundle identity for
// recording on a scan_run and for cache keys.
func (b *Bundle) Digest() string { return b.digest }

// Rules returns the authored (uncompiled) rules in load order. The returned
// slice is a copy; callers may not mutate the bundle.
func (b *Bundle) Rules() []Rule {
	out := make([]Rule, len(b.rules))
	for i, cr := range b.rules {
		out[i] = cr.Rule
	}
	return out
}

// severitySet and confidenceSet gate rule validation to the closed vocab.
var (
	validSeverity = map[Severity]bool{
		SeverityInfo: true, SeverityLow: true, SeverityMedium: true,
		SeverityHigh: true, SeverityCritical: true,
	}
	validConfidence = map[Confidence]bool{
		ConfidenceLow: true, ConfidenceMedium: true, ConfidenceHigh: true,
	}
	ruleIDRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]{3}$`)
)

// LoadBundle loads and compiles a rule bundle from dir within fsys. dir must
// contain a bundle.yaml manifest and one or more family YAML files, each a
// document with a top-level `rules:` list. LoadBundle validates every rule
// (id shape, closed severity/confidence vocab, compilable patterns, id
// uniqueness, and the presence of the mandatory fixtures) and computes the
// reproducible digest. It performs no rule evaluation and executes nothing.
func LoadBundle(fsys fs.FS, dir string) (*Bundle, error) {
	manifestBytes, err := fs.ReadFile(fsys, path.Join(dir, "bundle.yaml"))
	if err != nil {
		return nil, fmt.Errorf("rules: reading bundle.yaml: %w", err)
	}
	var man Manifest
	if err := strictYAML(manifestBytes, &man); err != nil {
		return nil, fmt.Errorf("rules: parsing bundle.yaml: %w", err)
	}
	if man.Version == "" {
		return nil, fmt.Errorf("rules: bundle.yaml missing version")
	}

	bundleNot := make([]*regexp.Regexp, 0, len(man.NotPatterns))
	for _, p := range man.NotPatterns {
		re, err := compilePattern(p)
		if err != nil {
			return nil, fmt.Errorf("rules: bundle.yaml notPattern %q: %w", p, err)
		}
		bundleNot = append(bundleNot, re)
	}

	files, err := ruleFilePaths(fsys, dir)
	if err != nil {
		return nil, err
	}

	b := &Bundle{manifest: man}
	seen := map[string]bool{}
	hasher := sha256.New()
	// bundle.yaml participates in the digest so a manifest change is a new
	// bundle identity.
	digestFile(hasher, path.Join(dir, "bundle.yaml"), manifestBytes)

	for _, fp := range files {
		raw, err := fs.ReadFile(fsys, fp)
		if err != nil {
			return nil, fmt.Errorf("rules: reading %s: %w", fp, err)
		}
		digestFile(hasher, fp, raw)

		var rf ruleFile
		if err := strictYAML(raw, &rf); err != nil {
			return nil, fmt.Errorf("rules: parsing %s: %w", fp, err)
		}
		if len(rf.Rules) == 0 {
			return nil, fmt.Errorf("rules: %s contains no rules", fp)
		}
		for i := range rf.Rules {
			cr, err := compileRule(rf.Rules[i], fp, bundleNot)
			if err != nil {
				return nil, err
			}
			if seen[cr.ID] {
				return nil, fmt.Errorf("rules: duplicate rule id %q (in %s)", cr.ID, fp)
			}
			seen[cr.ID] = true
			b.rules = append(b.rules, cr)
		}
	}
	if len(b.rules) == 0 {
		return nil, fmt.Errorf("rules: bundle %s has no rules", dir)
	}
	// Stable rule order (by id) for deterministic evaluation and output.
	sort.Slice(b.rules, func(i, j int) bool { return b.rules[i].ID < b.rules[j].ID })
	b.digest = hex.EncodeToString(hasher.Sum(nil))
	return b, nil
}

// ruleFilePaths returns the sorted list of family YAML files in dir (every
// *.yaml/*.yml except bundle.yaml). Sorting makes the digest reproducible.
func ruleFilePaths(fsys fs.FS, dir string) ([]string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("rules: reading dir %s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "bundle.yaml" {
			continue
		}
		ext := strings.ToLower(path.Ext(name))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path.Join(dir, name))
		}
	}
	sort.Strings(files)
	return files, nil
}

// digestFile mixes one file's path and content into the hasher with length
// framing so that neither path nor content boundaries can be ambiguous.
func digestFile(h io.Writer, p string, content []byte) {
	// Writes to a hash.Hash never fail; errors are ignored by contract.
	_, _ = fmt.Fprintf(h, "%d:%s\n%d:", len(p), p, len(content))
	_, _ = h.Write(content)
	_, _ = h.Write([]byte("\n"))
}

// strictYAML decodes YAML with unknown fields rejected, matching the repo's
// closed-schema convention (see internal/config, pkg/manifest).
func strictYAML(b []byte, dst any) error {
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

// compileRule validates and compiles one rule. Patterns are made
// case-insensitive by prefixing "(?i)" unless the pattern already opens with a
// flag group.
func compileRule(r Rule, fp string, bundleNot []*regexp.Regexp) (*compiledRule, error) {
	if !ruleIDRe.MatchString(r.ID) {
		return nil, fmt.Errorf("rules: %s: invalid rule id %q (want family-nnn)", fp, r.ID)
	}
	if r.Family == "" {
		return nil, fmt.Errorf("rules: %s: rule %s missing family", fp, r.ID)
	}
	if !strings.HasPrefix(r.ID, r.Family+"-") {
		return nil, fmt.Errorf("rules: %s: rule %s id must be prefixed by family %q", fp, r.ID, r.Family)
	}
	if r.Title == "" {
		return nil, fmt.Errorf("rules: %s: rule %s missing title", fp, r.ID)
	}
	if !validSeverity[r.Severity] {
		return nil, fmt.Errorf("rules: %s: rule %s invalid severity %q", fp, r.ID, r.Severity)
	}
	if !validConfidence[r.Confidence] {
		return nil, fmt.Errorf("rules: %s: rule %s invalid confidence %q", fp, r.ID, r.Confidence)
	}
	if len(r.Patterns) == 0 {
		return nil, fmt.Errorf("rules: %s: rule %s has no patterns", fp, r.ID)
	}
	if len(r.Fixtures.Match) < 2 {
		return nil, fmt.Errorf("rules: %s: rule %s needs >=2 match fixtures", fp, r.ID)
	}
	if len(r.Fixtures.NonMatch) < 2 {
		return nil, fmt.Errorf("rules: %s: rule %s needs >=2 nonMatch fixtures", fp, r.ID)
	}

	cr := &compiledRule{Rule: r}
	for _, p := range r.Patterns {
		re, err := compilePattern(p)
		if err != nil {
			return nil, fmt.Errorf("rules: %s: rule %s pattern %q: %w", fp, r.ID, p, err)
		}
		cr.patterns = append(cr.patterns, re)
	}
	for _, p := range r.NotPatterns {
		re, err := compilePattern(p)
		if err != nil {
			return nil, fmt.Errorf("rules: %s: rule %s notPattern %q: %w", fp, r.ID, p, err)
		}
		cr.notPatterns = append(cr.notPatterns, re)
	}
	cr.bundleNotPatterns = bundleNot
	return cr, nil
}

// flagGroupRe detects a leading regexp flag group like "(?i)" or "(?is)" so we
// do not double-apply the case-insensitive default.
var flagGroupRe = regexp.MustCompile(`^\(\?[a-zA-Z]+\)`)

// compilePattern compiles a rule pattern, applying case-insensitivity and
// multiline anchoring by default (§8.3: "case-insensitive by default"). The
// multiline flag makes ^ and $ match at line boundaries so rules can anchor to
// a line (e.g. a fake "System:" role turn) while the engine still scans whole
// content in one pass. "." does not cross newlines unless the author opts in
// with an explicit (?s) flag group.
func compilePattern(p string) (*regexp.Regexp, error) {
	if !flagGroupRe.MatchString(p) {
		p = "(?im)" + p
	}
	return regexp.Compile(p)
}
