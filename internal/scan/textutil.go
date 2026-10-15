package scan

import (
	"regexp"
	"strings"
)

// editDistance is Levenshtein distance over runes with an early exit: once
// every cell of a row exceeds cap the answer can only grow, so the function
// returns cap. S8 only ever asks "are these two names within two edits", and
// the cap keeps a pathological name pair from costing more than the question
// is worth.
func editDistance(a, b string, cap int) int {
	ra, rb := []rune(a), []rune(b)
	if len(ra) < len(rb) {
		ra, rb = rb, ra
	}
	if len(ra)-len(rb) >= cap {
		return cap
	}
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		best := cur[0]
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
			if cur[j] < best {
				best = cur[j]
			}
		}
		if best >= cap {
			return cap
		}
		prev, cur = cur, prev
	}
	if prev[len(rb)] > cap {
		return cap
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// wordRe splits text into comparable word tokens for the spam heuristics.
var wordRe = regexp.MustCompile(`[\p{L}\p{N}][\p{L}\p{N}'\-]*`)

// spamStopWords are the tokens whose repetition means nothing. Without them
// the densest token in any English README is "the".
var spamStopWords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "or": true, "of": true,
	"to": true, "in": true, "is": true, "it": true, "for": true, "on": true,
	"with": true, "this": true, "that": true, "you": true, "your": true,
	"be": true, "are": true, "as": true, "at": true, "by": true, "from": true,
	"if": true, "not": true, "can": true, "will": true, "use": true, "using": true,
}

// topTokenDensity returns the most-repeated non-stop-word token in text, how
// often it occurs, and the total token count.
func topTokenDensity(text string) (token string, count, total int) {
	freq := map[string]int{}
	for _, w := range wordRe.FindAllString(strings.ToLower(text), -1) {
		total++
		if spamStopWords[w] || len(w) < 3 {
			continue
		}
		freq[w]++
	}
	for w, n := range freq {
		if n > count || (n == count && w < token) {
			token, count = w, n
		}
	}
	return token, count, total
}

// keywordListRatio estimates how much of the text is a keyword list rather
// than prose: the share of non-blank lines that are comma-separated runs of
// short phrases with no sentence punctuation.
func keywordListRatio(text string) float64 {
	lines, listy := 0, 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines++
		parts := strings.Split(line, ",")
		if len(parts) < 4 || strings.ContainsAny(line, ".!?") {
			continue
		}
		short := 0
		for _, p := range parts {
			if n := len(strings.Fields(p)); n >= 1 && n <= 4 {
				short++
			}
		}
		if short == len(parts) {
			listy++
		}
	}
	if lines == 0 {
		return 0
	}
	return float64(listy) / float64(lines)
}

// confusableSkeleton normalizes a name for the anti-typosquat compare (UTS #39
// spirit): lowercase, map common confusable digits/letters, and
// strip separators. A cheap skeleton that collapses obvious look-alikes.
func confusableSkeleton(s string) string {
	s = strings.ToLower(s)
	repl := strings.NewReplacer(
		"0", "o", "1", "l", "3", "e", "4", "a", "5", "s", "7", "t",
		"-", "", "_", "", ".", "", " ", "",
		// Dash look-alikes: an en-dash in a package name is invisible next to
		// a hyphen at any reading speed.
		"‐", "", "‑", "", "‒", "", "–", "", "—", "", "−", "",
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
