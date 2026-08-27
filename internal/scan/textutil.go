package scan

import (
	"regexp"
	"strings"
)

// editDistance1 reports whether a and b differ by a single insertion,
// deletion, or substitution (Levenshtein distance exactly 1) — the typosquat
// heuristic for S7.
func editDistance1(a, b string) bool {
	la, lb := len(a), len(b)
	if la == lb {
		diff := 0
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				diff++
				if diff > 1 {
					return false
				}
			}
		}
		return diff == 1
	}
	if la > lb {
		a, b = b, a
		la, lb = lb, la
	}
	if lb-la != 1 {
		return false
	}
	// b is one longer: check it is a with one insertion.
	i, j, skipped := 0, 0, false
	for i < la && j < lb {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		if skipped {
			return false
		}
		skipped = true
		j++ // skip the extra char in b
	}
	return true
}

// confusableSkeleton normalizes a name for the anti-typosquat compare (T-10,
// UTS #39 spirit): lowercase, map common confusable digits/letters, and
// strip separators. A cheap skeleton that collapses obvious look-alikes.
func confusableSkeleton(s string) string {
	s = strings.ToLower(s)
	repl := strings.NewReplacer(
		"0", "o", "1", "l", "3", "e", "4", "a", "5", "s", "7", "t",
		"-", "", "_", "", ".", "", " ", "",
		// Cyrillic/Greek look-alikes → Latin.
		"а", "a", "е", "e", "о", "o", "с", "c", "р", "p", "х", "x",
		"ѕ", "s", "і", "i", "ο", "o", "α", "a",
	)
	return repl.Replace(s)
}

var urlRe = regexp.MustCompile(`https?://[^\s)>\]"']+`)

// shortenerHosts are URL-shortener domains that hide the true destination.
var shortenerHosts = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "goo.gl": true, "t.co": true,
	"ow.ly": true, "buff.ly": true, "is.gd": true, "cutt.ly": true,
	"rebrand.ly": true, "shorturl.at": true,
}

// suspiciousURL returns a non-empty reason when a URL looks hostile:
// punycode/homograph host or a known shortener.
func suspiciousURL(u string) string {
	rest := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	host := rest
	if i := strings.IndexAny(rest, "/:?#"); i >= 0 {
		host = rest[:i]
	}
	host = strings.ToLower(host)
	if strings.Contains(host, "xn--") {
		return "punycode/homograph domain"
	}
	if shortenerHosts[host] {
		return "URL shortener hides destination"
	}
	// Mixed-script host (Latin + non-ASCII letters) is a homograph signal.
	hasASCII, hasNonASCII := false, false
	for _, r := range host {
		switch {
		case r < 0x80 && (r >= 'a' && r <= 'z'):
			hasASCII = true
		case r >= 0x80:
			hasNonASCII = true
		}
	}
	if hasASCII && hasNonASCII {
		return "mixed-script (homograph) domain"
	}
	return ""
}
