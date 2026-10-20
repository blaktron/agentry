package scan

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/blaktron/agentry/pkg/rules"
)

// S2 — Secrets. Native high-signal secret detection over the archive
// (git-history scanning is the git-tag add-on). The
// mandatory `agy_` PAT rule is included, and the manifest's declared
// env values are read as values (stages_s2_manifest.go). A
// gitleaks/trufflehog external adapter can replace this behind the same
// Stage interface.
type S2Secrets struct {
	// Gitleaks, when set, execs the real tool after the native ruleset and
	// folds its report in.
	Gitleaks *ExecTool
}

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

func (s S2Secrets) Run(sc stageContext, in *Input) StageResult {
	var findings []Finding
	lineSeen := map[string]bool{}
	for _, f := range in.Files {
		if !f.IsText || f.Content == nil {
			continue
		}
		lines := strings.Split(string(f.Content), "\n")
		for i, line := range lines {
			for _, rule := range secretRules {
				// Every match on the line: two keys of one rule on one line
				// are two secrets to rotate, told apart by their column.
				for _, loc := range rule.re.FindAllStringSubmatchIndex(line, -1) {
					start, end := loc[0], loc[1]
					if g := rule.group; g > 0 && 2*g+1 < len(loc) && loc[2*g] >= 0 {
						start, end = loc[2*g], loc[2*g+1]
					}
					if rule.entropyMin > 0 && rules.ShannonEntropy([]byte(line[start:end])) < rule.entropyMin {
						continue
					}
					lineSeen[f.Path+"|"+strconv.Itoa(i+1)] = true
					findings = append(findings, Finding{
						Scanner: "S2/" + rule.id, Severity: rule.severity, Confidence: ConfHigh,
						Title: "Possible secret: " + rule.id, FilePath: f.Path,
						LineStart: i + 1, LineEnd: i + 1,
						Excerpt:  redact(line),
						Detail:   map[string]any{"rule": rule.id, "column": start + 1},
						Taxonomy: []string{"LLM03"},
					})
				}
			}
		}
	}
	findings = append(findings, s2ManifestEnv(in, lineSeen)...)
	if s.Gitleaks != nil && in.Dir != "" {
		findings = append(findings, runGitleaks(sc.Context(), s.Gitleaks, in.Dir, lineSeen)...)
	}
	hist, ran := s2History(sc.Context(), in)
	findings = append(findings, hist...)
	return StageResult{Scanner: "S2", Findings: findings, NoCache: ran}
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
