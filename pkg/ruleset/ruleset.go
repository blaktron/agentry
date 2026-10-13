// Package ruleset embeds the versioned S3/S4 rule bundle (rules/) into the
// server binary so the pipeline ships a self-contained ruleset (§8.3). The
// same YAML files are the ruleset_releases artifact; the CLI embeds them too
// (D-12) for offline `agentry validate` parity.
package ruleset

import (
	"embed"
	"io/fs"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/pkg/rules"
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

// baselineThresholds is the platform baseline's auto-publish threshold
// (maxAutoPublishSeverity, §8.5) for every bundle version that has reached a
// registry. The threshold judges the findings the bundle and the Go stages
// of its day produce, so it is released with them: a version names one
// threshold, and a change of threshold is a new version (plan
// scan-and-run-tweaks §4.1, agentry#773). Entries are only ever added.
//
// It is kept here, beside the version, and not as a key in bundle.yaml:
// installed CLIs strict-parse the manifest when `agentry validate
// --rules-update` fetches a registry's bundle, and a key they do not know
// would make every one of them refuse every bundle from then on.
var baselineThresholds = map[string]string{
	"0.2.0": "low",
	"0.2.1": "low",
	"0.2.2": "low",
	"0.2.3": "low",
	"0.3.0": "medium",
	"0.3.1": "medium",
	"0.3.2": "medium",
	"0.3.3": "medium",
	"0.3.4": "medium",
	"0.4.0": "medium",
	"0.4.1": "medium",
	"0.4.2": "medium",
	"0.4.3": "medium",
	"0.4.4": "medium",
	"0.4.5": "medium",
	"0.4.6": "medium",
	"0.4.7": "medium",
	"0.4.8": "medium",
}

var embeddedVersion = sync.OnceValue(func() string {
	raw, err := embedded.ReadFile("rules/bundle.yaml")
	if err != nil {
		return ""
	}
	var man struct {
		Version string `yaml:"version"`
	}
	if yaml.Unmarshal(raw, &man) != nil {
		return ""
	}
	return man.Version
})

// BaselineMaxAutoPublishSeverity is the platform baseline's auto-publish
// threshold under the embedded bundle's version. A version with no entry
// answers "low", the strictest threshold any version has had: an unknown
// threshold fails toward review (TestEveryReleasedVersionNamesItsThreshold
// keeps the embedded version listed).
func BaselineMaxAutoPublishSeverity() string {
	return BaselineMaxAutoPublishSeverityFor(embeddedVersion())
}

// BaselineMaxAutoPublishSeverityFor is the baseline threshold a bundle
// version was released with, or "low" for a version with no entry.
func BaselineMaxAutoPublishSeverityFor(version string) string {
	if t, ok := baselineThresholds[version]; ok {
		return t
	}
	return "low"
}
