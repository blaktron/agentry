// Package scan is the security pipeline (§8): orchestrator, scanner stages
// S1–S10, the LLM judge interface, the gate, and provenance signing. It
// operates on the exact archive bytes that will ship (§6.5), never the repo.
package scan

import (
	"github.com/PLACEHOLDER_ORG/agentry/pkg/rules"
)

// Severity is a finding severity (§8, ordered).
type Severity string

// Severities, ascending.
const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// SeverityAtLeast reports whether severity a is at least b (by name).
func SeverityAtLeast(a, b string) bool {
	return severityRank(Severity(a)) >= severityRank(Severity(b))
}

// severityRank orders severities for the gate.
func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// Confidence is a finding confidence.
type Confidence string

// Confidences.
const (
	ConfLow    Confidence = "low"
	ConfMedium Confidence = "medium"
	ConfHigh   Confidence = "high"
)

// Finding is one pipeline result (mirrors the findings table, §4.2). It is
// the common currency across stages; rules.Finding (S3/S4) converts in.
type Finding struct {
	Scanner    string // "S1".."S10", optionally with a rule id: "S4/inj-override-001"
	Severity   Severity
	Confidence Confidence
	Title      string
	FilePath   string
	LineStart  int
	LineEnd    int
	Excerpt    string
	Detail     map[string]any
	Taxonomy   []string // OWASP ids (§8.10)
}

// fromRules converts a pkg/rules finding (S3/S4) into a pipeline finding.
func fromRules(rf rules.Finding) Finding {
	detail := map[string]any{"ruleId": rf.RuleID}
	for k, v := range rf.Detail {
		detail[k] = v
	}
	return Finding{
		Scanner:    rf.RuleID, // already "S3/..." or "S4/..."
		Severity:   Severity(rf.Severity),
		Confidence: Confidence(rf.Confidence),
		Title:      rf.Title,
		FilePath:   rf.FilePath,
		LineStart:  rf.LineStart,
		LineEnd:    rf.LineEnd,
		Excerpt:    rf.Excerpt,
		Detail:     detail,
		Taxonomy:   rf.Taxonomy,
	}
}

// StageResult is one scanner stage's output.
type StageResult struct {
	Scanner  string
	Findings []Finding
	// Err is set when the stage could not complete; the orchestrator treats
	// a stage error as fail-closed (§7 timeout rule, §8.2).
	Err error
	// Skipped marks a stage whose result was already known — a completed
	// stage of an interrupted run, or a §8.7 results-cache hit. Skipped
	// stages are not re-persisted and not re-cached.
	Skipped bool
	// PromptHash is set by S5: the hash of the rubric/prompt version the
	// judge adjudicated with (§8.4.4, recorded on the scan run).
	PromptHash string
}

// Input is the unpacked archive plus context a stage may need.
type Input struct {
	// Dir is the extracted archive root (read-only to stages).
	Dir string
	// Files is the S1 inventory (populated before S2–S9 run).
	Files []FileEntry
	// Manifest is the parsed, validated manifest (capabilities drive S6).
	ManifestJSON []byte
	// Kind is the agent kind (skill|prompt-agent|mcp-server).
	Kind string
	// Version is this version's semver string; S9 classifies the bump size
	// against PrevVersion (a patch bump that changes behaviour is the
	// rug-pull shape).
	Version string
	// Summary is the agent's one-line summary, one of the two ranked fields
	// S8's keyword-stuffing heuristic reads.
	Summary string
	// PrevArchiveDir is the previous published version's extracted archive
	// for S9 release-diff; empty on first publish.
	PrevArchiveDir string
	// PrevManifestJSON is the previous version's manifest for S9.
	PrevManifestJSON []byte
	// PrevVersion is the previous published version's semver string.
	PrevVersion string
	// AccountAgeDays and RecentPublishCount feed S8 publisher signals.
	AccountAgeDays     int
	RecentPublishCount int
}

// FileEntry is one inventoried file (S1 output).
type FileEntry struct {
	Path    string
	Size    int64
	IsText  bool
	IsImage bool
	Content []byte // populated for text files under the scan cap
}

// Stage is one scanner (S1–S9). S10 assembly is not a Stage.
type Stage interface {
	// ID is the stage id ("S1".."S9").
	ID() string
	// Run executes the stage against the (already-inventoried) input.
	Run(ctx stageContext, in *Input) StageResult
}
