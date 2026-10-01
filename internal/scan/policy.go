package scan

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/blaktron/agentry/pkg/ruleset"
)

// Policy is the §8.6 policy document. The platform baseline is the floor;
// org policies may only tighten (Evaluate enforces this).
type Policy struct {
	// RequireHumanReview: "never" | "always" | {"whenCapabilities": [...]}.
	RequireHumanReview json.RawMessage `json:"requireHumanReview,omitempty"`
	// BlockedCapabilities: submissions declaring these are rejected at
	// V-validation (registry enforces; listed here for completeness).
	BlockedCapabilities []string `json:"blockedCapabilities,omitempty"`
	// AllowedLicenses: public publishes outside this list are rejected.
	AllowedLicenses []string `json:"allowedLicenses,omitempty"`
	// BlockedMcpServers: submissions whose manifest declares one of these
	// MCP servers are rejected at submission (RUNNER-PLAN-3 §P1 org
	// blocklist, agentry#52). Entries are "npm:<package>" / "pypi:<package>";
	// path.Match globs are allowed ("npm:@evil/*", "pypi:*-fetch"). Unions
	// toward strict like blockedCapabilities.
	BlockedMcpServers []string `json:"blockedMcpServers,omitempty"`
	// MaxAutoPublishSeverity tightens the §8.5 table: worst auto-publishable
	// severity. "" means the baseline default, which the ruleset carries
	// (medium since ruleset 0.3.0, agentry#773).
	MaxAutoPublishSeverity string `json:"maxAutoPublishSeverity,omitempty"`
	// RequireEvals: evals/ dir must exist and be non-empty.
	RequireEvals bool `json:"requireEvals,omitempty"`
	// WildcardEgress: "review" | "reject" for "*" egress.
	WildcardEgress string `json:"wildcardEgress,omitempty"`
}

// DefaultBaseline is the platform baseline policy (§8.5 defaults). Its
// threshold is the embedded ruleset's: released with the bundle version, so
// "which ruleset published this" names the threshold too (agentry#773).
func DefaultBaseline() Policy {
	return Policy{
		RequireHumanReview:     json.RawMessage(`"never"`),
		MaxAutoPublishSeverity: baselineMaxAuto(),
		WildcardEgress:         "review",
	}
}

// baselineMaxAuto is the default auto-publish threshold: what a baseline
// that names none, or a policy that names none, publishes up to.
func baselineMaxAuto() string { return ruleset.BaselineMaxAutoPublishSeverity() }

// ParsePolicy decodes and validates a policy document.
func ParsePolicy(doc []byte) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(doc, &p); err != nil {
		return Policy{}, fmt.Errorf("scan: policy parse: %w", err)
	}
	if p.MaxAutoPublishSeverity != "" {
		if _, ok := severityByName(p.MaxAutoPublishSeverity); !ok {
			return Policy{}, fmt.Errorf("scan: policy: bad maxAutoPublishSeverity %q", p.MaxAutoPublishSeverity)
		}
	}
	switch p.WildcardEgress {
	case "", "review", "reject":
	default:
		return Policy{}, fmt.Errorf("scan: policy: bad wildcardEgress %q", p.WildcardEgress)
	}
	// requireHumanReview must be "never"|"always"|{whenCapabilities:[...]}.
	if len(p.RequireHumanReview) > 0 {
		if _, err := parseReviewMode(p.RequireHumanReview); err != nil {
			return Policy{}, err
		}
	}
	for _, b := range p.BlockedMcpServers {
		b = strings.TrimSpace(b)
		if !strings.HasPrefix(b, "npm:") && !strings.HasPrefix(b, "pypi:") {
			return Policy{}, fmt.Errorf("scan: policy: blockedMcpServers entry %q must be prefixed with npm or pypi", b)
		}
		if _, err := path.Match(b, ""); err != nil {
			return Policy{}, fmt.Errorf("scan: policy: blockedMcpServers entry %q: %w", b, err)
		}
	}
	return p, nil
}

func severityByName(s string) (Severity, bool) {
	switch Severity(s) {
	case SevInfo, SevLow, SevMedium, SevHigh, SevCritical:
		return Severity(s), true
	}
	return "", false
}

type reviewMode struct {
	always           bool
	never            bool
	whenCapabilities []string
}

func parseReviewMode(raw json.RawMessage) (reviewMode, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch s {
		case "never":
			return reviewMode{never: true}, nil
		case "always":
			return reviewMode{always: true}, nil
		default:
			return reviewMode{}, fmt.Errorf("scan: policy: bad requireHumanReview %q", s)
		}
	}
	var obj struct {
		WhenCapabilities []string `json:"whenCapabilities"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return reviewMode{}, fmt.Errorf("scan: policy: bad requireHumanReview object: %w", err)
	}
	return reviewMode{whenCapabilities: obj.WhenCapabilities}, nil
}

// Merge tightens baseline with an org overlay (§8.6: org may only tighten).
// The stricter of each knob wins; org can never loosen the baseline.
func Merge(baseline, org Policy) Policy {
	out := baseline

	// requireHumanReview: escalate only (never < whenCapabilities < always).
	bm, _ := parseReviewMode(orNever(baseline.RequireHumanReview))
	om, err := parseReviewMode(orNever(org.RequireHumanReview))
	if err == nil {
		out.RequireHumanReview = tightenReview(bm, om)
	}

	// maxAutoPublishSeverity: the LOWER threshold (stricter) wins.
	bSev, _ := severityByName(orDefault(baseline.MaxAutoPublishSeverity, baselineMaxAuto()))
	if org.MaxAutoPublishSeverity != "" {
		if oSev, ok := severityByName(org.MaxAutoPublishSeverity); ok && severityRank(oSev) < severityRank(bSev) {
			out.MaxAutoPublishSeverity = org.MaxAutoPublishSeverity
		}
	}

	// blockedCapabilities / allowedLicenses: union / intersection toward strict.
	out.BlockedCapabilities = union(baseline.BlockedCapabilities, org.BlockedCapabilities)
	out.BlockedMcpServers = union(baseline.BlockedMcpServers, org.BlockedMcpServers)
	if len(org.AllowedLicenses) > 0 {
		if len(baseline.AllowedLicenses) == 0 {
			out.AllowedLicenses = org.AllowedLicenses
		} else {
			out.AllowedLicenses = intersect(baseline.AllowedLicenses, org.AllowedLicenses)
		}
	}
	out.RequireEvals = baseline.RequireEvals || org.RequireEvals
	if org.WildcardEgress == "reject" || baseline.WildcardEgress == "reject" {
		out.WildcardEgress = "reject"
	}
	return out
}

func tightenReview(a, b reviewMode) json.RawMessage {
	rank := func(m reviewMode) int {
		switch {
		case m.always:
			return 2
		case len(m.whenCapabilities) > 0:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		if b.always {
			return json.RawMessage(`"always"`)
		}
		out, _ := json.Marshal(map[string][]string{"whenCapabilities": b.whenCapabilities})
		return out
	}
	if a.always {
		return json.RawMessage(`"always"`)
	}
	if len(a.whenCapabilities) > 0 {
		out, _ := json.Marshal(map[string][]string{"whenCapabilities": a.whenCapabilities})
		return out
	}
	return json.RawMessage(`"never"`)
}

// orNever returns raw, or the "never" default when empty (the only default
// requireHumanReview ever needs).
func orNever(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`"never"`)
	}
	return raw
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	var out []string
	for _, s := range b {
		if set[s] {
			out = append(out, s)
		}
	}
	return out
}

// LoosensBaseline reports whether org would loosen baseline on any knob the
// API rejects outright (§8.6). Merge already clamps silently; this gives the
// author a clear error for the most confusing case — a looser
// maxAutoPublishSeverity or downgrading wildcardEgress from reject.
func LoosensBaseline(baseline, org Policy) bool {
	if org.MaxAutoPublishSeverity != "" {
		bSev, _ := severityByName(orDefault(baseline.MaxAutoPublishSeverity, baselineMaxAuto()))
		if oSev, ok := severityByName(org.MaxAutoPublishSeverity); ok && severityRank(oSev) > severityRank(bSev) {
			return true
		}
	}
	if baseline.WildcardEgress == "reject" && org.WildcardEgress == "review" {
		return true
	}
	// requireHumanReview: org cannot go below baseline.
	bm, _ := parseReviewMode(orNever(baseline.RequireHumanReview))
	om, err := parseReviewMode(orNever(org.RequireHumanReview))
	if err == nil && len(org.RequireHumanReview) > 0 {
		rank := func(m reviewMode) int {
			switch {
			case m.always:
				return 2
			case len(m.whenCapabilities) > 0:
				return 1
			default:
				return 0
			}
		}
		if rank(om) < rank(bm) {
			return true
		}
	}
	return false
}
