package scan

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/blaktron/agentry/pkg/rules"
)

// S2 — Secrets (§8.3). Native high-signal secret detection over the archive
// (git-history scanning is the git-tag add-on, deferred per DEV-006). The
// mandatory `agy_` PAT rule (D-22) is included. A gitleaks/trufflehog
// external adapter can replace this behind the same Stage interface.
type S2Secrets struct{}

func (S2Secrets) ID() string { return "S2" }

type secretRule struct {
	id       string
	re       *regexp.Regexp
	severity Severity
	// entropyMin, when > 0, additionally requires the captured group's
	// Shannon entropy to exceed it (cuts placeholder/example matches).
	entropyMin float64
	group      int
}

var secretRules = []secretRule{
	{id: "agentry-pat", re: regexp.MustCompile(`\bagy_[a-z2-7]{40,}\b`), severity: SevHigh},
	{id: "aws-access-key", re: regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), severity: SevHigh},
	{id: "aws-secret-key", re: regexp.MustCompile(`(?i)aws.{0,20}?['"]([0-9a-zA-Z/+]{40})['"]`), severity: SevHigh, entropyMin: 4.0, group: 1},
	{id: "github-pat", re: regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b`), severity: SevHigh},
	{id: "github-fine-grained", re: regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{50,}\b`), severity: SevHigh},
	{id: "slack-token", re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`), severity: SevHigh},
	{id: "private-key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), severity: SevCritical},
	{id: "google-api-key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), severity: SevHigh},
	{id: "stripe-secret", re: regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}\b`), severity: SevCritical},
	{id: "generic-assignment", re: regexp.MustCompile(`(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['"]([^'"\s]{16,})['"]`), severity: SevMedium, entropyMin: 3.6, group: 1},
}

func (S2Secrets) Run(sc stageContext, in *Input) StageResult {
	var findings []Finding
	seen := map[string]bool{}
	for _, f := range in.Files {
		if !f.IsText || f.Content == nil {
			continue
		}
		lines := strings.Split(string(f.Content), "\n")
		for i, line := range lines {
			for _, rule := range secretRules {
				loc := rule.re.FindStringSubmatch(line)
				if loc == nil {
					continue
				}
				if rule.entropyMin > 0 {
					cand := loc[0]
					if rule.group > 0 && rule.group < len(loc) {
						cand = loc[rule.group]
					}
					if rules.ShannonEntropy([]byte(cand)) < rule.entropyMin {
						continue
					}
				}
				key := f.Path + "|" + rule.id + "|" + strconv.Itoa(i)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, Finding{
					Scanner: "S2/" + rule.id, Severity: rule.severity, Confidence: ConfHigh,
					Title: "Possible secret: " + rule.id, FilePath: f.Path,
					LineStart: i + 1, LineEnd: i + 1,
					Excerpt:  redact(line),
					Detail:   map[string]any{"rule": rule.id},
					Taxonomy: []string{"LLM03"},
				})
			}
		}
	}
	return StageResult{Scanner: "S2", Findings: findings}
}

// redact keeps a secret out of the report body: show only the match's shape.
func redact(line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 80 {
		line = line[:80]
	}
	// Mask long alphanumeric runs.
	return maskRuns.ReplaceAllStringFunc(line, func(m string) string {
		if len(m) <= 6 {
			return m
		}
		return m[:3] + strings.Repeat("*", 6)
	})
}

var maskRuns = regexp.MustCompile(`[0-9A-Za-z/+_\-]{8,}`)
