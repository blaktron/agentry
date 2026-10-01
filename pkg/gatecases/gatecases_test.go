package gatecases

import (
	"strings"
	"testing"
)

func TestTheEmbeddedTableLoads(t *testing.T) {
	table, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Cases) == 0 || table.Baseline.MaxAutoPublishSeverity == "" {
		t.Fatalf("loaded an empty table: %+v", table)
	}
	var withPolicy, onBaseline Case
	for _, c := range table.Cases {
		if c.Policy != nil {
			withPolicy = c
		} else {
			onBaseline = c
		}
	}
	if got := table.PolicyOf(onBaseline); got.MaxAutoPublishSeverity != table.Baseline.MaxAutoPublishSeverity {
		t.Fatalf("a case with no policy is decided under %+v, not the baseline", got)
	}
	if got := table.PolicyOf(withPolicy); got.MaxAutoPublishSeverity != withPolicy.Policy.MaxAutoPublishSeverity {
		t.Fatalf("a case's own policy was not used: %+v", got)
	}
}

func TestATableThatCannotBeReadIsRefused(t *testing.T) {
	const base = `"baseline":{"maxAutoPublishSeverity":"low"}`
	for name, doc := range map[string]string{
		"unknown field":    `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}}],"extra":1}`,
		"no cases":         `{` + base + `,"cases":[]}`,
		"repeated name":    `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}},{"name":"a","branch":"b","want":{"outcome":"published"}}]}`,
		"no branch":        `{` + base + `,"cases":[{"name":"a","want":{"outcome":"published"}}]}`,
		"bad severity":     `{` + base + `,"cases":[{"name":"a","branch":"b","findings":[{"scanner":"S4/x","severity":"severe","confidence":"high"}],"want":{"outcome":"published"}}]}`,
		"bad outcome":      `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"held"}}]}`,
		"review, no queue": `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"needs_review"}}]}`,
		"queue on publish": `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published","queue":"org"}}]}`,
		"bad threshold":    `{"baseline":{"maxAutoPublishSeverity":"severe"},"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}}]}`,
		"bad review mode":  `{` + base + `,"cases":[{"name":"a","branch":"b","policy":{"requireHumanReview":"sometimes"},"want":{"outcome":"published"}}]}`,
		"empty capability": `{` + base + `,"cases":[{"name":"a","branch":"b","policy":{"requireHumanReview":{"whenCapabilities":[]}},"want":{"outcome":"published"}}]}`,
		"bad review field": `{` + base + `,"cases":[{"name":"a","branch":"b","policy":{"requireHumanReview":{"whenCaps":["network"]}},"want":{"outcome":"published"}}]}`,
		"bad egress":       `{` + base + `,"cases":[{"name":"a","branch":"b","policy":{"wildcardEgress":"allow"},"want":{"outcome":"published"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte(doc)); err == nil || !strings.HasPrefix(err.Error(), "gatecases: ") {
				t.Fatalf("parse accepted it (err %v)", err)
			}
		})
	}
}
