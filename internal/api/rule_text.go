package api

import (
	"strings"
	"sync"

	"github.com/blaktron/agentry/pkg/rules"
	"github.com/blaktron/agentry/pkg/ruleset"
)

// bundleRules indexes the rules of the bundle this registry scans with (the
// embedded one, which the pipeline registers at start) by id, for the
// description, references and remediation a report shows beside a finding.
var bundleRules = sync.OnceValue(func() map[string]rules.Rule {
	out := map[string]rules.Rule{}
	b, err := ruleset.Load()
	if err != nil {
		return out
	}
	for _, r := range b.Rules() {
		out[r.ID] = r
	}
	return out
})

// bundleRuleOf is the bundle rule a finding's scanner names ("S4/<rule id>",
// "S3/<rule id>"), when the bundle holds it. A stage's own findings ("S1",
// "S2/gitleaks", AI Review) name no bundle rule.
func bundleRuleOf(scanner string) (rules.Rule, bool) {
	_, id, ok := strings.Cut(scanner, "/")
	if !ok || id == "" {
		return rules.Rule{}, false
	}
	r, ok := bundleRules()[id]
	return r, ok
}
