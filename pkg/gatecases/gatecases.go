// Package gatecases publishes the registry gate's behaviour as data: a table
// of cases, each a set of findings, the flags the gate reads, a policy, and
// the outcome the gate reaches (published, needs_review, rejected).
//
// The gate itself (internal/scan's Evaluate) stays internal. The core's gate
// test runs every case in this table against it, and fails when the gate has
// a branch no case reaches, so the table is always what the gate does. A
// client that restates the gate's rule (the CLI's Examiner, which names the
// outcome a submission would be expected to reach) runs the same table in its
// own test; a core pin bump that changes the gate then fails that test until
// the restatement follows (plan desktop-review-key-and-run-cards.md §6.2,
// D31; agentry#776).
//
// The table carries no code of the pipeline. Its baseline is the platform
// baseline compiled into the registry; an operator may store another one,
// which GET /api/v1/platform/policy answers.
package gatecases

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
)

//go:embed cases.json
var raw []byte

// The gate's outcomes, as the registry names them.
const (
	OutcomePublished   = "published"
	OutcomeNeedsReview = "needs_review"
	OutcomeRejected    = "rejected"
)

// The review queues a needs_review outcome lands on.
const (
	QueuePlatform = "platform"
	QueueOrg      = "org"
)

// Table is the published table of the gate's cases.
type Table struct {
	// Baseline is the platform baseline policy. A case with no policy of its
	// own is decided under it.
	Baseline Policy `json:"baseline"`
	// Cases are the gate's cases, each with the outcome it reaches.
	Cases []Case `json:"cases"`
}

// Policy is the part of the publication policy the gate reads, in the
// policy document's own shape. The other knobs (blockedCapabilities,
// allowedLicenses, blockedMcpServers, requireEvals) refuse at submission,
// before the gate.
type Policy struct {
	// RequireHumanReview is "never", "always" or {"whenCapabilities": [...]};
	// absent means "never".
	RequireHumanReview json.RawMessage `json:"requireHumanReview,omitempty"`
	// MaxAutoPublishSeverity is the worst severity that publishes; absent
	// means the gate's fallback, the registry's baseline (medium since
	// ruleset 0.3.0, agentry#773).
	MaxAutoPublishSeverity string `json:"maxAutoPublishSeverity,omitempty"`
	// WildcardEgress is "review" or "reject"; absent means "review".
	WildcardEgress string `json:"wildcardEgress,omitempty"`
}

// Finding is an open finding as the gate weighs it.
type Finding struct {
	// Scanner is the finding's scanner id ("S4/inj-override-001"). The gate
	// reads it only to know a finding that says content went unread.
	Scanner string `json:"scanner"`
	// Severity is info, low, medium, high or critical.
	Severity string `json:"severity"`
	// Confidence is low, medium or high; a low-confidence finding never
	// gates alone.
	Confidence string `json:"confidence"`
}

// Case is one input to the gate and the outcome it reaches.
type Case struct {
	// Name says what the case shows; names are unique in the table.
	Name string `json:"name"`
	// Branch names the rule of the gate that decides the case.
	Branch   string    `json:"branch"`
	Findings []Finding `json:"findings,omitempty"`
	// Policy is the effective policy; nil means the table's Baseline.
	Policy *Policy `json:"policy,omitempty"`
	// WildcardEgress: the manifest declares "*" egress.
	WildcardEgress bool `json:"wildcardEgress,omitempty"`
	// JudgeForcesReview: the AI Review provider requires a person whatever
	// its scores, or a stage failed closed.
	JudgeForcesReview bool `json:"judgeForcesReview,omitempty"`
	// DeclaredCapabilities are the manifest's declared capability tokens.
	DeclaredCapabilities []string `json:"declaredCapabilities,omitempty"`
	// Public: the agent is public.
	Public bool `json:"public,omitempty"`
	// NamespaceIsOrg: the agent is in an organization's namespace.
	NamespaceIsOrg bool `json:"namespaceIsOrg,omitempty"`
	// Want is the outcome the gate reaches.
	Want Want `json:"want"`
}

// Want is a gate outcome.
type Want struct {
	// Outcome is published, needs_review or rejected.
	Outcome string `json:"outcome"`
	// Queue is QueuePlatform or QueueOrg when the outcome is needs_review, and
	// empty otherwise.
	Queue string `json:"queue,omitempty"`
}

// PolicyOf is the effective policy a case is decided under.
func (t Table) PolicyOf(c Case) Policy {
	if c.Policy != nil {
		return *c.Policy
	}
	return t.Baseline
}

// Load decodes and checks the embedded table.
func Load() (Table, error) {
	return parse(raw)
}

var (
	severities  = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	confidences = map[string]bool{"low": true, "medium": true, "high": true}
)

func parse(doc []byte) (Table, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var t Table
	if err := dec.Decode(&t); err != nil {
		return Table{}, fmt.Errorf("gatecases: %w", err)
	}
	if err := checkPolicy(t.Baseline); err != nil {
		return Table{}, fmt.Errorf("gatecases: baseline: %w", err)
	}
	if len(t.Cases) == 0 {
		return Table{}, errors.New("gatecases: the table has no cases")
	}
	seen := map[string]bool{}
	for i, c := range t.Cases {
		if c.Name == "" || seen[c.Name] {
			return Table{}, fmt.Errorf("gatecases: case %d: missing or repeated name %q", i, c.Name)
		}
		seen[c.Name] = true
		if err := checkCase(c); err != nil {
			return Table{}, fmt.Errorf("gatecases: case %q: %w", c.Name, err)
		}
	}
	return t, nil
}

func checkCase(c Case) error {
	if c.Branch == "" {
		return errors.New("the case names no branch")
	}
	if c.Policy != nil {
		if err := checkPolicy(*c.Policy); err != nil {
			return err
		}
	}
	for i, f := range c.Findings {
		switch {
		case f.Scanner == "":
			return fmt.Errorf("finding %d names no scanner", i)
		case !severities[f.Severity]:
			return fmt.Errorf("finding %d: bad severity %q", i, f.Severity)
		case !confidences[f.Confidence]:
			return fmt.Errorf("finding %d: bad confidence %q", i, f.Confidence)
		}
	}
	switch c.Want.Outcome {
	case OutcomeNeedsReview:
		if c.Want.Queue != QueuePlatform && c.Want.Queue != QueueOrg {
			return fmt.Errorf("needs_review on queue %q: want %s or %s", c.Want.Queue, QueuePlatform, QueueOrg)
		}
	case OutcomePublished, OutcomeRejected:
		if c.Want.Queue != "" {
			return fmt.Errorf("a queue on a %s outcome", c.Want.Outcome)
		}
	default:
		return fmt.Errorf("bad outcome %q", c.Want.Outcome)
	}
	return nil
}

func checkPolicy(p Policy) error {
	if p.MaxAutoPublishSeverity != "" && !severities[p.MaxAutoPublishSeverity] {
		return fmt.Errorf("bad maxAutoPublishSeverity %q", p.MaxAutoPublishSeverity)
	}
	switch p.WildcardEgress {
	case "", "review", "reject":
	default:
		return fmt.Errorf("bad wildcardEgress %q", p.WildcardEgress)
	}
	return checkReviewMode(p.RequireHumanReview)
}

// checkReviewMode accepts requireHumanReview as "never", "always" or a
// whenCapabilities list naming at least one capability. That is stricter
// than the registry, which reads an empty list or an unknown key as "never";
// the table writes "never" for those, so a client's restatement has one form
// to read for each meaning.
func checkReviewMode(raw json.RawMessage) error {
	const forms = `"never", "always" or {"whenCapabilities": [...]}`
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s != "never" && s != "always" {
			return fmt.Errorf("bad requireHumanReview %q: want %s", s, forms)
		}
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var obj struct {
		WhenCapabilities []string `json:"whenCapabilities"`
	}
	if err := dec.Decode(&obj); err != nil {
		return fmt.Errorf("bad requireHumanReview %s: want %s: %w", raw, forms, err)
	}
	if len(obj.WhenCapabilities) == 0 {
		return fmt.Errorf("bad requireHumanReview %s: whenCapabilities names no capability", raw)
	}
	return nil
}
