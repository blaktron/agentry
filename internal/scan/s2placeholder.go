package scan

import (
	"regexp"

	"github.com/blaktron/agentry/pkg/rules"
)

// placeholderRe matches what documentation puts where a secret would go: a
// name reserved for examples (RFC 2606 and RFC 6761: example.com/.net/.org,
// .example, .invalid, .test, localhost), a template marker (<name>,
// ${NAME}, {{name}}, %NAME%, $NAME, [name]), or a word that says it is not
// real. A security QuickAgent's proof-of-concept command (`sqlmap -u
// "https://app.example.com/search?q=test"`, `curl -u <user>:<pass>`)
// carries one.
var placeholderRe = regexp.MustCompile(`(?i)` +
	`(?:[a-z0-9-]+\.)*example\.(?:com|net|org)\b|(?:[a-z0-9-]+\.)*[a-z0-9-]+\.(?:example|invalid|test|localhost)\b|\blocalhost\b|` +
	`<[^<>\s]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|(?-i:%[A-Z_]+%|\$[A-Z][A-Z_]{2,}\b)|\[[^\]]+\]|` +
	`\b(?:your|my)[_-]?(?:api[_-]?)?(?:key|token|secret|pass(?:word)?|user(?:name)?)\b|` +
	`\bexample\b|\bplaceholder\b|\bchangeme\b|\bredacted\b|\bdummy\b|x{4,}|\*{3,}`)

// secretRunRe is a run of letters and digits long enough to be a
// credential once the placeholders are taken out.
var secretRunRe = regexp.MustCompile(`[A-Za-z0-9]{8,}`)

// documentedPlaceholder reports whether a gitleaks hit's captured value
// (its Secret, else its Match) is a documented placeholder rather than a
// credential: it carries a placeholder, and what is left once every
// placeholder is taken out holds no run of eight or more letters and
// digits with the entropy of a secret. So `your_username:<password>` is a
// placeholder, and `your_username:Zq8vR2mT9pL4xW7c` or a real key beside an
// example host is not.
func documentedPlaceholder(value string) bool {
	if value == "" || !placeholderRe.MatchString(value) {
		return false
	}
	rest := placeholderRe.ReplaceAllString(value, " ")
	for _, run := range secretRunRe.FindAllString(rest, -1) {
		if rules.ShannonEntropy([]byte(run)) >= 2.5 {
			return false
		}
	}
	return true
}
