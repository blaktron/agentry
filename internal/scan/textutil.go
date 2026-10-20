package scan

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
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

// urlRe finds an http(s) URL in text. A browser takes the scheme in any
// case, so HTTPS:// and Http:// are found too.
var urlRe = regexp.MustCompile(`(?i)https?://[^\s)>\]"']+`)

// shortenerHosts are URL-shortener domains that hide the true destination.
var shortenerHosts = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "goo.gl": true, "t.co": true,
	"ow.ly": true, "buff.ly": true, "is.gd": true, "cutt.ly": true,
	"rebrand.ly": true, "shorturl.at": true,
}

// urlHost is the host a browser reads from an http(s) URL, lowercased:
// the authority ends at the first "/", "\", "?" or "#" (a browser reads a
// backslash as "/" in an http(s) URL, so https://bit.ly\@example.com opens
// bit.ly), the host follows its last "@" (user:password@ is userinfo, not
// host), a port is cut off, and the name is the one a browser looks up
// (browserHostName).
func urlHost(u string) string { return urlHostEndingAt(u, "/\\?#") }

// urlHosts are the hosts an http(s) URL can reach: the one a browser reads,
// and, when its authority holds a backslash, the one a parser that keeps the
// backslash reads (Python's urlsplit does, and reads
// https://example.com\@bit.ly as bit.ly). A tool that fetches the link
// need not be a browser, so either reading counts.
func urlHosts(u string) []string {
	browser, kept := urlHost(u), urlHostEndingAt(u, "/?#")
	if kept == browser {
		return []string{browser}
	}
	return []string{browser, kept}
}

// urlHostEndingAt reads the host of an http(s) URL whose authority ends at
// the first of the bytes in ends.
func urlHostEndingAt(u, ends string) string {
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, ends); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	if strings.HasPrefix(rest, "[") { // an IPv6 literal keeps its colons
		if i := strings.IndexByte(rest, ']'); i >= 0 {
			rest = rest[:i+1]
		}
		return strings.ToLower(rest)
	}
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	return browserHostName(rest)
}

// browserHostName is the name a browser looks up for a host as written. It
// first applies the mapping a browser applies to a host name (UTS #46):
// compatibility forms fold to their plain ones, so full-width letters,
// digits and hyphens are ASCII; the full-width and ideographic full stops
// are "."; and case is lowered, so a shortener written in full-width
// letters, or with an ideographic full stop, opens the shortener. Punycode labels are kept as written. Then it trims what no host
// name holds from either end, as text around a link leaves there (a comma
// in https://bit.ly,/x), and a trailing dot, which names the same host.
func browserHostName(host string) string {
	host = strings.Map(func(r rune) rune {
		switch r {
		case '\u3002', '\uFF0E', '\uFF61': // ideographic, full-width and half-width ideographic full stops
			return '.'
		}
		return r
	}, norm.NFKC.String(host))
	host = strings.TrimLeftFunc(host, notHostNameRune)
	host = strings.TrimRightFunc(host, func(r rune) bool { return r == '.' || notHostNameRune(r) })
	return strings.ToLower(host)
}

// notHostNameRune is true for a character no host name holds: anything but
// a letter (an internationalized name's included), a digit, "." and "-".
func notHostNameRune(r rune) bool {
	return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-'
}

// suspiciousURL returns a non-empty reason when a URL looks hostile:
// punycode/homograph host or a known shortener, in any of the hosts the URL
// can reach (urlHosts).
func suspiciousURL(u string) string {
	for _, host := range urlHosts(u) {
		if reason := suspiciousHost(host); reason != "" {
			return reason
		}
	}
	return ""
}

// suspiciousHost is suspiciousURL's reason for one host.
func suspiciousHost(host string) string {
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
