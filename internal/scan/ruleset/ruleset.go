// Package ruleset embeds the versioned S3/S4 rule bundle (rules/) into the
// server binary so the pipeline ships a self-contained ruleset (§8.3). The
// same YAML files are the ruleset_releases artifact; the CLI embeds them too
// (D-12) for offline `agentry validate` parity.
package ruleset

import (
	"embed"
	"io/fs"

	"github.com/PLACEHOLDER_ORG/agentry/pkg/rules"
)

//go:embed rules/*.yaml
var embedded embed.FS

// Load compiles the embedded rule bundle.
func Load() (*rules.Bundle, error) {
	sub, err := fs.Sub(embedded, "rules")
	if err != nil {
		return nil, err
	}
	return rules.LoadBundle(sub, ".")
}
