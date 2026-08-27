package scan

import "github.com/PLACEHOLDER_ORG/agentry/pkg/rules"

// rulesScan runs the S3/S4 engine (pkg/rules) over the inventoried text
// files with the loaded bundle. Isolated so S3S4Content and tests share it.
func rulesScan(sc stageContext, in *Input) []rules.Finding {
	return rules.Scan(sc.bundle, toRuleFiles(in.Files))
}
