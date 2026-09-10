package scan

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/blaktron/agentry/pkg/rules"
)

// S8 — Metadata, namespace & publisher abuse (§8.3). Name similarity vs
// popular agents (normalized edit distance + UTS #39 confusable-skeleton
// compare), URL reputation in readme/manifest, keyword-stuffing heuristics,
// and publisher-behaviour signals (young account + publish velocity — the
// ClawHavoc pattern).
type S8Metadata struct {
	// PopularAgentNames seeds the anti-typosquat compare (T-10); the
	// orchestrator injects the live top-N.
	PopularAgentNames []string
	// AgentName is this agent's name (for self-exclusion).
	AgentName string
}

func (S8Metadata) ID() string { return "S8" }

func (s S8Metadata) Run(sc stageContext, in *Input) StageResult {
	var findings []Finding

	findings = append(findings, s8NameSimilarity(s.AgentName, s.PopularAgentNames)...)

	// URL reputation in prose (punycode/homograph, shorteners).
	for _, f := range in.Files {
		if !f.IsText || f.Content == nil {
			continue
		}
		for i, line := range strings.Split(string(f.Content), "\n") {
			for _, m := range urlRe.FindAllString(line, -1) {
				if reason := suspiciousURL(m); reason != "" {
					findings = append(findings, Finding{
						Scanner: "S8/url-reputation", Severity: SevMedium, Confidence: ConfMedium,
						Title: "Suspicious URL: " + reason, FilePath: f.Path,
						LineStart: i + 1, LineEnd: i + 1, Excerpt: truncateStr(m, 100),
						Detail:   map[string]any{"reason": reason},
						Taxonomy: []string{"LLM01"},
					})
				}
			}
		}
	}

	findings = append(findings, s8Spam(in)...)

	// Publisher anomaly (§8.3, §19 ramp): young account + high velocity.
	if in.AccountAgeDays >= 0 && in.AccountAgeDays < 7 && in.RecentPublishCount >= 5 {
		findings = append(findings, Finding{
			Scanner: "S8/publisher-velocity", Severity: SevMedium, Confidence: ConfMedium,
			Title:    "New account with high publish velocity",
			Detail:   map[string]any{"accountAgeDays": in.AccountAgeDays, "recentPublishes": in.RecentPublishCount},
			Taxonomy: []string{"LLM03"},
		})
	}
	// The cluster axis (§8.3, agentry#27): several accounts publishing
	// from one address in a day is the ClawHavoc shape (12 accounts, one
	// operator) that per-account velocity cannot see. Routes to platform
	// review like the other publisher signals; the hash is keyed and
	// month-rotated, so the finding names counts, never an address.
	if in.IPClusterAccounts >= ipClusterMinAccounts && in.IPClusterVersions >= ipClusterMinVersions {
		findings = append(findings, Finding{
			Scanner: "S8/ip-cluster", Severity: SevMedium, Confidence: ConfMedium,
			Title:    "Several accounts publishing from one address",
			Detail:   map[string]any{"accounts24h": in.IPClusterAccounts, "versions24h": in.IPClusterVersions},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	return StageResult{Scanner: "S8", Findings: findings}
}

// ClawHavoc-shaped thresholds for S8/ip-cluster: distinct accounts and
// versions sharing one submitting-address hash within 24 hours. A shared
// office or CI runner publishing a few versions from two accounts stays
// clear; a burst from a handful of fresh accounts does not.
const (
	ipClusterMinAccounts = 3
	ipClusterMinVersions = 10
)

// s8NameSimilarity implements both halves of §8.3's anti-typosquat compare:
// the UTS #39 confusable skeleton (catches Cyrillic-а for Latin-a, which is
// edit distance 1 but visually distance 0) and normalized edit distance
// (catches "githib-mcp" for "github-mcp", which no skeleton collapses).
//
// The confusable half is the higher-confidence signal — two names with the
// same skeleton are indistinguishable to a reader — so it scores higher.
func s8NameSimilarity(name string, popular []string) []Finding {
	if name == "" {
		return nil
	}
	var findings []Finding
	skel := confusableSkeleton(name)
	reported := map[string]bool{}
	for _, pop := range popular {
		if pop == "" || pop == name || reported[pop] {
			continue
		}
		if confusableSkeleton(pop) == skel {
			reported[pop] = true
			findings = append(findings, Finding{
				Scanner: "S8/name-confusable", Severity: SevMedium, Confidence: ConfMedium,
				Title:    "Name confusable with a popular BriefAgent: " + pop,
				Detail:   map[string]any{"resembles": pop, "skeleton": skel},
				Taxonomy: []string{"LLM03"},
			})
			continue
		}
		d, norm, ok := nameDistance(name, pop)
		if !ok {
			continue
		}
		reported[pop] = true
		findings = append(findings, Finding{
			Scanner: "S8/name-similar", Severity: SevMedium, Confidence: ConfLow,
			Title: "Name is one small edit from a popular BriefAgent: " + pop,
			Detail: map[string]any{
				"resembles": pop, "editDistance": d,
				"normalizedDistance": fmt.Sprintf("%.3f", norm),
			},
			Taxonomy: []string{"LLM03"},
		})
	}
	return findings
}

// nameDistance reports whether two names are close enough to be a typosquat
// candidate: at most two edits, and at most a quarter of the longer name.
// Short names need the ratio guard — "ai" and "ui" are one edit apart and
// nothing alike.
func nameDistance(a, b string) (dist int, normalized float64, ok bool) {
	longest := len(a)
	if len(b) > longest {
		longest = len(b)
	}
	if longest < 5 {
		return 0, 0, false
	}
	d := editDistance(a, b, 3)
	if d == 0 || d > 2 {
		return 0, 0, false
	}
	norm := float64(d) / float64(longest)
	if norm > 0.25 {
		return 0, 0, false
	}
	return d, norm, true
}

// s8Spam is the keyword-stuffing heuristic (§8.3 S8: "spam/keyword-stuffing
// heuristics"). It reads the agent summary and the README — the two fields
// that feed search ranking — and flags text whose vocabulary has collapsed
// onto one repeated token or degenerated into a keyword list.
//
// Low severity by design: stuffing is a ranking-abuse and ClawHavoc-profile
// signal, not a compromise of the consumer, and legitimate reference docs
// repeat their subject noun a great deal.
func s8Spam(in *Input) []Finding {
	var findings []Finding
	type source struct {
		label   string
		path    string
		content string
	}
	sources := []source{}
	if strings.TrimSpace(in.Summary) != "" {
		sources = append(sources, source{label: "summary", content: in.Summary})
	}
	for _, f := range in.Files {
		if !f.IsText || f.Content == nil {
			continue
		}
		if base := strings.ToLower(path.Base(f.Path)); base == "readme.md" || base == "readme" {
			sources = append(sources, source{label: "readme", path: f.Path, content: string(f.Content)})
		}
	}
	for _, src := range sources {
		token, count, total := topTokenDensity(src.content)
		switch {
		case total >= 40 && count >= 8 && float64(count)/float64(total) >= 0.08:
			findings = append(findings, Finding{
				Scanner: "S8/keyword-stuffing", Severity: SevLow, Confidence: ConfMedium,
				Title:    "Keyword stuffing in " + src.label,
				FilePath: src.path,
				Detail: map[string]any{
					"token": token, "occurrences": count, "words": total,
					"density": fmt.Sprintf("%.2f", float64(count)/float64(total)),
				},
				Taxonomy: []string{"LLM03"},
			})
		case keywordListRatio(src.content) >= 0.5 && total >= 30:
			findings = append(findings, Finding{
				Scanner: "S8/keyword-stuffing", Severity: SevLow, Confidence: ConfLow,
				Title:    "Keyword-list text in " + src.label,
				FilePath: src.path,
				Detail: map[string]any{
					"reason": "most of the text is comma-separated keywords rather than prose",
					"words":  total,
				},
				Taxonomy: []string{"LLM03"},
			})
		}
	}
	return findings
}

// S9 — Release-diff risk (§8.3). Diffs this version against the previous
// published version — manifest AND content — for new egress hosts/URLs,
// capability additions, newly added install scripts or dependencies, the first
// appearance of obfuscation markers, and large instruction rewrites shipped as
// a patch bump. Escalates findings that arrive VIA the diff (the postmark-mcp
// rug-pull pattern). First-ever publishes skip S9.
type S9ReleaseDiff struct {
	// CurrentFindings are this run's other stages' findings, so S9 can
	// escalate rather than re-detect. The orchestrator injects the set.
	CurrentFindings []Finding
}

func (S9ReleaseDiff) ID() string { return "S9" }

// proseRewriteRatio is the share of the previous version's instruction lines
// that must change before a patch bump counts as a rewrite.
const proseRewriteRatio = 0.30

func (s S9ReleaseDiff) Run(sc stageContext, in *Input) StageResult {
	if in.PrevManifestJSON == nil && in.PrevArchiveDir == "" {
		return StageResult{Scanner: "S9"} // first publish
	}
	var findings []Finding
	bump := bumpSize(in.PrevVersion, in.Version)
	prevFiles := inventoryDir(in.PrevArchiveDir)

	findings = append(findings, s9ManifestDiff(in)...)
	findings = append(findings, s9ContentDiff(in, prevFiles, bump)...)
	findings = append(findings, s9Escalate(sc, in, prevFiles, s.CurrentFindings, bump)...)
	return StageResult{Scanner: "S9", Findings: findings}
}

// s9ManifestDiff covers the declared surface: egress hosts and capabilities
// the previous manifest did not have.
func s9ManifestDiff(in *Input) []Finding {
	var findings []Finding
	prevEgress := egressSet(in.PrevManifestJSON)
	for _, host := range sortedSet(egressSet(in.ManifestJSON)) {
		if !prevEgress[host] && host != "none" {
			findings = append(findings, Finding{
				Scanner: "S9/new-egress", Severity: SevMedium, Confidence: ConfHigh,
				Title:    "New network egress host in this release: " + host,
				Detail:   map[string]any{"host": host, "pattern": "new destination after clean releases (postmark-mcp)"},
				Taxonomy: []string{"LLM03", "ASI04"},
			})
		}
	}
	prevCaps := declaredCaps(in.PrevManifestJSON)
	for _, c := range sortedSet(declaredCaps(in.ManifestJSON)) {
		if !prevCaps[c] {
			findings = append(findings, Finding{
				Scanner: "S9/capability-widened", Severity: SevMedium, Confidence: ConfHigh,
				Title:    "Capability newly declared this release: " + c,
				Detail:   map[string]any{"capability": c},
				Taxonomy: []string{"ASI04"},
			})
		}
	}
	return findings
}

// s9ContentDiff is the postmark-mcp defense. The incident that defines this
// stage changed no manifest field: it added one line of code that BCC'd every
// message to an address the previous fifteen releases had never mentioned.
// Only a diff of the CONTENT sees that.
func s9ContentDiff(in *Input, prevFiles []FileEntry, bump string) []Finding {
	if len(prevFiles) == 0 {
		return nil // no baseline archive to compare against
	}
	var findings []Finding

	// (a) Destinations that appear in this release and did not exist in the
	// previous one, anywhere in prose or code.
	prevTargets := extractEgressTargets(prevFiles)
	curTargets := extractEgressTargets(in.Files)
	declared := egressSet(in.ManifestJSON)
	for _, target := range sortedTargets(curTargets) {
		if _, existed := prevTargets[target]; existed {
			continue
		}
		t := curTargets[target]
		// A patch release that introduces a destination is the exact documented
		// rug-pull shape; a major rewrite that adds one is ordinary.
		sev := SevMedium
		if bump == "patch" {
			sev = SevHigh
		}
		findings = append(findings, Finding{
			Scanner: "S9/new-egress-content", Severity: sev, Confidence: ConfHigh,
			Title:     "New egress destination in package content: " + target,
			FilePath:  t.File,
			LineStart: t.Line, LineEnd: t.Line,
			Excerpt: t.Excerpt,
			Detail: map[string]any{
				"target": target, "kind": t.Kind, "bump": bump,
				"declaredInManifest": declared[target],
				"pattern":            "new destination after clean releases (postmark-mcp: 15 clean versions, then one BCC line)",
			},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}

	// (b) Obfuscation markers appearing for the first time. An S3 class the
	// previous release did not contain is a change in kind, not degree.
	prevClasses := map[string]bool{}
	for _, rf := range rules.Scan(nil, toRuleFiles(prevFiles)) {
		prevClasses[rf.RuleID] = true
	}
	curClasses := map[string]struct {
		file string
		line int
	}{}
	for _, rf := range rules.Scan(nil, toRuleFiles(in.Files)) {
		if _, ok := curClasses[rf.RuleID]; !ok {
			curClasses[rf.RuleID] = struct {
				file string
				line int
			}{rf.FilePath, rf.LineStart}
		}
	}
	for _, class := range sortedSetFromStructMap(curClasses) {
		if prevClasses[class] {
			continue
		}
		loc := curClasses[class]
		findings = append(findings, Finding{
			Scanner: "S9/new-obfuscation", Severity: SevHigh, Confidence: ConfHigh,
			Title:     "Obfuscation marker appears for the first time in this release: " + class,
			FilePath:  loc.file,
			LineStart: loc.line, LineEnd: loc.line,
			Detail: map[string]any{
				"class": class, "bump": bump,
				"reason": "hidden-content techniques absent from every previous release arrived with this one",
			},
			Taxonomy: []string{"LLM01", "ASI06"},
		})
	}

	// (c) Large instruction rewrites shipped as a patch bump. A patch claims
	// "no behaviour change"; rewriting the instructions IS the behaviour.
	if bump == "patch" {
		if ratio, changed, base := proseDelta(prevFiles, in.Files); ratio >= proseRewriteRatio && changed >= 5 {
			findings = append(findings, Finding{
				Scanner: "S9/instruction-rewrite", Severity: SevMedium, Confidence: ConfMedium,
				Title: "Large instruction rewrite in a patch-level release",
				Detail: map[string]any{
					"changedLines": changed, "previousLines": base,
					"ratio": fmt.Sprintf("%.2f", ratio), "bump": bump,
					"from": in.PrevVersion, "to": in.Version,
				},
				Taxonomy: []string{"LLM01", "ASI04"},
			})
		}
	}

	return findings
}

// s9Escalate raises the severity of findings that arrive VIA the diff (§8.3
// S9). The scoping matters: escalation used to apply to every current
// S3/S4/install-script medium whenever any previous version existed, so a
// package with one long-standing postinstall hook was escalated on every
// release forever — an alarm that fires identically whether or not anything
// changed carries no information. Only findings absent from the previous
// version's own content escalate now.
func s9Escalate(sc stageContext, in *Input, prevFiles []FileEntry, current []Finding, bump string) []Finding {
	if len(prevFiles) == 0 && in.PrevArchiveDir != "" {
		return nil
	}
	baseline := baselineFindings(sc.bundle, prevFiles)
	// Without a baseline archive the previous version's content is unknown.
	// Escalating everything would restore the bug; escalating nothing would
	// drop the signal. The middle course: escalate only when the manifest diff
	// already shows this release widened its reach.
	manifestWidened := len(s9ManifestDiff(in)) > 0
	haveBaseline := len(prevFiles) > 0

	var findings []Finding
	for _, cf := range current {
		if !isDiffEscalatable(cf) || severityRank(cf.Severity) != severityRank(SevMedium) {
			continue
		}
		if haveBaseline {
			if baseline[findingKey(cf)] {
				continue // present before this release: not a diff signal
			}
		} else if !manifestWidened {
			continue
		}
		findings = append(findings, Finding{
			Scanner: "S9/escalated", Severity: SevHigh, Confidence: cf.Confidence,
			Title:    cf.Title + " — severity raised by the release diff",
			FilePath: cf.FilePath, LineStart: cf.LineStart, LineEnd: cf.LineEnd,
			Detail: map[string]any{
				"escalatedFrom": cf.Scanner, "bump": bump,
				"reason": "newly introduced relative to the previous published version",
			},
			Taxonomy: cf.Taxonomy,
		})
	}
	return findings
}

func isDiffEscalatable(f Finding) bool {
	return strings.HasPrefix(f.Scanner, "S3/") ||
		strings.HasPrefix(f.Scanner, "S4/")
}

func egressSet(manifestJSON []byte) map[string]bool {
	out := map[string]bool{}
	var m struct {
		Capabilities struct {
			Network struct {
				Egress []string `json:"egress"`
			} `json:"network"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return out
	}
	for _, h := range m.Capabilities.Network.Egress {
		out[strings.ToLower(h)] = true
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Deterministic iteration helpers: findings must be reproducible because the
// canonical report is hashed and signed (§8.8).

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedTargets(m map[string]egressTarget) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSetFromStructMap(m map[string]struct {
	file string
	line int
}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
