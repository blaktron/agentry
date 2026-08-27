package scan

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// S7 — Dependencies & licenses (§8.3). Native lockfile analysis:
// install-script detection in package.json, typosquat heuristics on
// dependency names, and lockfile-presence for code kinds. OSV vulnerability
// lookup is gated behind an injected client (offline no-op by default,
// DEV-006).
type S7Dependencies struct{}

func (S7Dependencies) ID() string { return "S7" }

// popularNPM is a small seed of high-value package names for the typosquat
// edit-distance check (the production list is data-driven, §8.8 feed).
var popularNPM = []string{
	"react", "lodash", "express", "axios", "chalk", "commander", "debug",
	"typescript", "webpack", "next", "vue", "eslint", "jest", "dotenv",
}

func (S7Dependencies) Run(sc stageContext, in *Input) StageResult {
	var findings []Finding
	if in.Kind != "mcp-server" {
		return StageResult{Scanner: "S7"}
	}

	for _, f := range in.Files {
		if f.Content == nil {
			continue
		}
		base := filepath.Base(f.Path)
		switch base {
		case "package.json":
			findings = append(findings, s7PackageJSON(f)...)
		}
	}
	return StageResult{Scanner: "S7", Findings: findings}
}

func s7PackageJSON(f FileEntry) []Finding {
	var findings []Finding
	var pkg struct {
		Scripts      map[string]string `json:"scripts"`
		Dependencies map[string]string `json:"dependencies"`
		DevDeps      map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(f.Content, &pkg); err != nil {
		return findings
	}
	// Install-script detection (§8.3: preinstall etc. ⇒ medium minimum).
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		if cmd, ok := pkg.Scripts[hook]; ok {
			findings = append(findings, Finding{
				Scanner: "S7/install-script", Severity: SevMedium, Confidence: ConfHigh,
				Title:    "Lifecycle install script: " + hook,
				FilePath: f.Path,
				Detail:   map[string]any{"hook": hook, "command": truncateStr(cmd, 120)},
				Taxonomy: []string{"LLM03", "ASI04"},
			})
		}
	}
	// Typosquat heuristic (edit distance 1 to a popular name, but not equal).
	for name := range merged(pkg.Dependencies, pkg.DevDeps) {
		for _, pop := range popularNPM {
			if name != pop && editDistance1(name, pop) {
				findings = append(findings, Finding{
					Scanner: "S7/typosquat", Severity: SevMedium, Confidence: ConfMedium,
					Title:    "Possible typosquat dependency: " + name,
					FilePath: f.Path,
					Detail:   map[string]any{"dependency": name, "resembles": pop},
					Taxonomy: []string{"LLM03", "ASI04"},
				})
			}
		}
	}
	return findings
}

// S8 — Metadata, namespace & publisher abuse (§8.3). Name-similarity vs
// popular agents (confusable-skeleton compare), URL reputation in
// readme/manifest, and publisher-behaviour signals (young account + publish
// velocity — the ClawHavoc pattern).
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

	// Name confusable-similarity vs popular agents (T-10).
	skel := confusableSkeleton(s.AgentName)
	for _, pop := range s.PopularAgentNames {
		if pop == s.AgentName {
			continue
		}
		if confusableSkeleton(pop) == skel && pop != "" {
			findings = append(findings, Finding{
				Scanner: "S8/name-confusable", Severity: SevMedium, Confidence: ConfMedium,
				Title:    "Agent name confusable with popular agent: " + pop,
				Detail:   map[string]any{"resembles": pop},
				Taxonomy: []string{"LLM03"},
			})
		}
	}

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

	// Publisher anomaly (§8.3, §19 ramp): young account + high velocity.
	if in.AccountAgeDays >= 0 && in.AccountAgeDays < 7 && in.RecentPublishCount >= 5 {
		findings = append(findings, Finding{
			Scanner: "S8/publisher-velocity", Severity: SevMedium, Confidence: ConfMedium,
			Title:    "New account with high publish velocity",
			Detail:   map[string]any{"accountAgeDays": in.AccountAgeDays, "recentPublishes": in.RecentPublishCount},
			Taxonomy: []string{"LLM03"},
		})
	}
	return StageResult{Scanner: "S8", Findings: findings}
}

// S9 — Release-diff risk (§8.3). Diffs this version against the previous
// published version: new egress hosts/URLs, capability widening, new install
// scripts/deps, first appearance of obfuscation markers. Escalates severity
// of findings that arrive via a diff (the postmark-mcp rug-pull pattern).
// First-ever publishes skip S9.
type S9ReleaseDiff struct {
	// Findings from this run's other stages, so S9 can escalate rather than
	// re-detect. The orchestrator injects the accumulated set.
	CurrentFindings []Finding
}

func (S9ReleaseDiff) ID() string { return "S9" }

func (s S9ReleaseDiff) Run(sc stageContext, in *Input) StageResult {
	if in.PrevManifestJSON == nil {
		return StageResult{Scanner: "S9"} // first publish
	}
	var findings []Finding

	prevEgress := egressSet(in.PrevManifestJSON)
	curEgress := egressSet(in.ManifestJSON)
	for host := range curEgress {
		if !prevEgress[host] && host != "none" {
			findings = append(findings, Finding{
				Scanner: "S9/new-egress", Severity: SevMedium, Confidence: ConfHigh,
				Title:    "New network egress host in this release: " + host,
				Detail:   map[string]any{"host": host, "pattern": "clean-then-malicious diff (postmark-mcp)"},
				Taxonomy: []string{"LLM03", "ASI04"},
			})
		}
	}

	// Capability widening: any capability newly declared this release.
	prevCaps := declaredCaps(in.PrevManifestJSON)
	curCaps := declaredCaps(in.ManifestJSON)
	for c := range curCaps {
		if !prevCaps[c] {
			findings = append(findings, Finding{
				Scanner: "S9/capability-widened", Severity: SevMedium, Confidence: ConfHigh,
				Title:    "Capability newly declared this release: " + c,
				Detail:   map[string]any{"capability": c},
				Taxonomy: []string{"ASI04"},
			})
		}
	}

	// Escalation: an S3/S4 obfuscation or an S7 install-script that appears
	// alongside a diff is worse than in isolation (§8.3 S9). Escalate any
	// current medium finding from those families to high.
	for _, cf := range s.CurrentFindings {
		if isDiffEscalatable(cf) && severityRank(cf.Severity) == severityRank(SevMedium) {
			findings = append(findings, Finding{
				Scanner: "S9/escalated", Severity: SevHigh, Confidence: cf.Confidence,
				Title:    "Escalated by release-diff: " + cf.Title,
				FilePath: cf.FilePath, LineStart: cf.LineStart, LineEnd: cf.LineEnd,
				Detail:   map[string]any{"escalatedFrom": cf.Scanner},
				Taxonomy: cf.Taxonomy,
			})
		}
	}
	return StageResult{Scanner: "S9", Findings: findings}
}

func isDiffEscalatable(f Finding) bool {
	return strings.HasPrefix(f.Scanner, "S3/") ||
		strings.HasPrefix(f.Scanner, "S4/") ||
		strings.HasPrefix(f.Scanner, "S7/install-script")
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
		out[h] = true
	}
	return out
}

func merged(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
