package gatecases

import (
	"slices"
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
		"unknown field":             `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}}],"extra":1}`,
		"no cases":                  `{` + base + `,"cases":[]}`,
		"repeated name":             `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}},{"name":"a","branch":"b","want":{"outcome":"published"}}]}`,
		"no branch":                 `{` + base + `,"cases":[{"name":"a","want":{"outcome":"published"}}]}`,
		"bad severity":              `{` + base + `,"cases":[{"name":"a","branch":"b","findings":[{"scanner":"S4/x","severity":"severe","confidence":"high"}],"want":{"outcome":"published"}}]}`,
		"bad outcome":               `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"held"}}]}`,
		"review, no queue":          `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"needs_review"}}]}`,
		"queue on publish":          `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published","queue":"org"}}]}`,
		"bad threshold":             `{"baseline":{"maxAutoPublishSeverity":"severe"},"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}}]}`,
		"bad review mode":           `{` + base + `,"cases":[{"name":"a","branch":"b","policy":{"requireHumanReview":"sometimes"},"want":{"outcome":"published"}}]}`,
		"empty capability":          `{` + base + `,"cases":[{"name":"a","branch":"b","policy":{"requireHumanReview":{"whenCapabilities":[]}},"want":{"outcome":"published"}}]}`,
		"bad review field":          `{` + base + `,"cases":[{"name":"a","branch":"b","policy":{"requireHumanReview":{"whenCaps":["network"]}},"want":{"outcome":"published"}}]}`,
		"bad egress":                `{` + base + `,"cases":[{"name":"a","branch":"b","policy":{"wildcardEgress":"allow"},"want":{"outcome":"published"}}]}`,
		"repeated derivation":       `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}}],"derivations":[{"name":"d","manifest":{},"want":{"declaredCapabilities":[],"unrestrictedNetwork":false}},{"name":"d","manifest":{},"want":{"declaredCapabilities":[],"unrestrictedNetwork":false}}]}`,
		"unnamed derivation":        `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}}],"derivations":[{"manifest":{},"want":{"declaredCapabilities":[],"unrestrictedNetwork":false}}]}`,
		"derivation, no manifest":   `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}}],"derivations":[{"name":"d","want":{"declaredCapabilities":[],"unrestrictedNetwork":false}}]}`,
		"derivation, null manifest": `{` + base + `,"cases":[{"name":"a","branch":"b","want":{"outcome":"published"}}],"derivations":[{"name":"d","manifest":null,"want":{"declaredCapabilities":[],"unrestrictedNetwork":false}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte(doc)); err == nil || !strings.HasPrefix(err.Error(), "gatecases: ") {
				t.Fatalf("parse accepted it (err %v)", err)
			}
		})
	}
}

// TestTheDerivationsAnswerTheTable: every derivation case in the table is
// what DeclaredCapabilities and UnrestrictedNetwork answer, so the table a
// client reads and the code the registry runs say the same thing.
func TestTheDerivationsAnswerTheTable(t *testing.T) {
	table, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Derivations) == 0 {
		t.Fatal("the table has no derivation cases")
	}
	for _, d := range table.Derivations {
		t.Run(d.Name, func(t *testing.T) {
			got := DeclaredCapabilities(d.Manifest)
			if !slices.Equal(got, d.Want.DeclaredCapabilities) {
				t.Errorf("DeclaredCapabilities = %v, the table says %v", got, d.Want.DeclaredCapabilities)
			}
			if got := UnrestrictedNetwork(d.Manifest); got != d.Want.UnrestrictedNetwork {
				t.Errorf("UnrestrictedNetwork = %v, the table says %v", got, d.Want.UnrestrictedNetwork)
			}
		})
	}
}

// TestTheDerivationsCoverEveryToken: some derivation case declares each
// token DeclaredCapabilities can name, and both answers of
// UnrestrictedNetwork are reached.
func TestTheDerivationsCoverEveryToken(t *testing.T) {
	table, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	unrestricted := map[bool]bool{}
	for _, d := range table.Derivations {
		for _, c := range d.Want.DeclaredCapabilities {
			seen[c] = true
		}
		unrestricted[d.Want.UnrestrictedNetwork] = true
	}
	for _, c := range []string{CapNetwork, CapFSRead, CapFSWrite, CapExec, CapEnv, CapTargetHosts, CapBrowser} {
		if !seen[c] {
			t.Errorf("no derivation case declares %q", c)
		}
	}
	if !unrestricted[true] || !unrestricted[false] {
		t.Errorf("the derivation cases reach only %v of UnrestrictedNetwork", unrestricted)
	}
}

// TestAnUnreadableManifestDeclaresNothing: bytes that are not a manifest's
// JSON declare no capability and ask for no network.
func TestAnUnreadableManifestDeclaresNothing(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("not json"), []byte(`{"capabilities": 3}`)} {
		if got := DeclaredCapabilities(b); len(got) != 0 {
			t.Errorf("DeclaredCapabilities(%q) = %v", b, got)
		}
		if UnrestrictedNetwork(b) {
			t.Errorf("UnrestrictedNetwork(%q) is true", b)
		}
	}
}
