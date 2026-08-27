package rules

import "unicode"

// scriptName classifies a letter rune into one of the confusable-prone
// scripts we care about for mixed-script detection. It returns "" for
// non-letters and for letters outside the tracked scripts. Only scripts that
// contain Latin look-alikes are tracked, because a token mixing, say, Latin
// and Cyrillic is the classic homograph attack (раypal). We deliberately use
// the standard library's Unicode range tables (unicode.Latin, etc.) rather
// than an external confusables table: no data files, fully deterministic.
func scriptName(r rune) string {
	if !unicode.IsLetter(r) {
		return ""
	}
	switch {
	case unicode.Is(unicode.Latin, r):
		return "Latin"
	case unicode.Is(unicode.Cyrillic, r):
		return "Cyrillic"
	case unicode.Is(unicode.Greek, r):
		return "Greek"
	case unicode.Is(unicode.Armenian, r):
		return "Armenian"
	default:
		return "other"
	}
}

// isWordRune reports whether r can be part of a single token for the purpose
// of mixed-script analysis: letters and combining marks. Digits, spaces, and
// punctuation split tokens.
func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.Is(unicode.Mark, r)
}

// mixedScriptToken reports whether the word token contains letters from two
// or more distinct tracked scripts (Latin/Cyrillic/Greek/Armenian). Tokens
// that are wholly one script — or that mix a tracked script only with the
// "other" bucket — are not flagged, keeping legitimate multilingual prose
// (a Greek word next to a Latin one is two tokens, not one) clean. The
// returned slice lists the distinct script names that co-occurred.
func mixedScriptToken(token string) (bool, []string) {
	seen := map[string]bool{}
	for _, r := range token {
		if name := scriptName(r); name != "" && name != "other" {
			seen[name] = true
		}
	}
	if len(seen) < 2 {
		return false, nil
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	// Deterministic order for stable excerpts/detail.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return true, names
}
