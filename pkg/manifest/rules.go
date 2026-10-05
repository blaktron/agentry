package manifest

// Rule is one §5.3 validation rule: the id an Issue carries and what the
// rule checks, in a phrase.
type Rule struct {
	// ID is the rule id an Issue reports, such as "V1".
	ID string
	// Title says what the rule checks.
	Title string
}

// rules is every rule this package can report, in order. V6 was withdrawn
// with the code-carrying kind and reports nothing, so it is not here.
// TestRulesMatchReportedIDs fails when an Issue names an id this list
// lacks, or the list names one no Issue reports.
var rules = []Rule{
	{ID: "V1", Title: "YAML and the closed schema"},
	{ID: "V2", Title: "namespace and name match the target repository"},
	{ID: "V3", Title: "strict semver, tag match, monotonic per channel"},
	{ID: "V4", Title: "publish.include resolves and carries the entrypoints"},
	{ID: "V5", Title: "the capability vocabulary"},
	{ID: "V7", Title: "public publish: licence, LICENSE and README.md"},
	{ID: "V8", Title: "size and count quotas"},
	{ID: "V9", Title: "skill frontmatter agrees with the manifest"},
	{ID: "V10", Title: "intake, interactive hints and the guide"},
	{ID: "V11", Title: "the knowledge block and its shipped packs"},
}

// Rules returns the rules Validate and ValidateInContext can report, in
// order, so a client can say which rules it ran without hard-coding the
// range. The slice is the caller's own.
func Rules() []Rule {
	return append([]Rule(nil), rules...)
}
