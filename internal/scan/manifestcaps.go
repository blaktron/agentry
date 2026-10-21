package scan

import (
	"github.com/blaktron/agentry/pkg/gatecases"
	"github.com/blaktron/agentry/pkg/rules"
)

// unrestrictedNetwork is the gate's WildcardEgress: "*" egress, or a
// browser on any public site. pkg/gatecases publishes the derivation, so a
// client restating the gate reads these two inputs exactly as this scanner
// does.
func unrestrictedNetwork(manifestJSON []byte) bool {
	return gatecases.UnrestrictedNetwork(manifestJSON)
}

// declaredCaps is the manifest's declared capability tokens as a set, from
// the derivation pkg/gatecases publishes.
func declaredCaps(manifestJSON []byte) map[string]bool {
	out := map[string]bool{}
	for _, c := range gatecases.DeclaredCapabilities(manifestJSON) {
		out[c] = true
	}
	return out
}

// declarationOf is what the manifest declares, as S4's rating by
// declaration reads it: gatecases.Declaration, which a client that restates
// the gate's rating reads too.
func declarationOf(manifestJSON []byte) rules.Declared {
	return gatecases.Declaration(manifestJSON)
}
