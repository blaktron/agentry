package manifest

import (
	"bufio"
	"embed"
	"fmt"
	"strings"
)

// The full SPDX license and exception lists, embedded (agentry#28; DEV-042
// recorded the earlier 60-id allowlist). Refreshed with
// scripts/dev/spdx-sync.sh from spdx/license-list-data (CC0). V7 accepts
// exactly these identifiers, combined as SPDX expressions — `MIT`,
// `MIT OR Apache-2.0`, `(MIT AND CC0-1.0)`, `GPL-2.0-or-later WITH
// Classpath-exception-2.0`, `GPL-2.0+` — and nothing else: no LicenseRef-
// custom identifiers on a public publish, because the point of V7 is a
// license a consumer can look up.
//
//go:embed spdx/licenses.txt spdx/exceptions.txt
var spdxFS embed.FS

// spdxIDs / spdxExceptions map lowercase id → canonical spelling. Lookup is
// case-insensitive: SPDX ids are case-sensitive by spec, but refusing a
// publish over "apache-2.0" would be a validator failing on punctuation.
// Deprecated identifiers (marked "!" in the file) stay accepted — they are
// still identifiers someone may honestly have declared — with the
// canonical spelling returned so the record reads the same everywhere.
var spdxIDs, spdxExceptions = func() (map[string]string, map[string]string) {
	load := func(name string) map[string]string {
		f, err := spdxFS.Open(name)
		if err != nil {
			panic("manifest: embedded " + name + ": " + err.Error())
		}
		defer func() { _ = f.Close() }()
		m := map[string]string{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			id := strings.TrimSuffix(line, "!")
			m[strings.ToLower(id)] = id
		}
		return m
	}
	return load("spdx/licenses.txt"), load("spdx/exceptions.txt")
}()

// KnownSPDXID reports whether id is an SPDX license identifier, matching
// case-insensitively, and returns the canonical spelling.
func KnownSPDXID(id string) (canonical string, ok bool) {
	canonical, ok = spdxIDs[strings.ToLower(strings.TrimSpace(id))]
	return canonical, ok
}

// KnownSPDXException is KnownSPDXID for exception identifiers.
func KnownSPDXException(id string) (canonical string, ok bool) {
	canonical, ok = spdxExceptions[strings.ToLower(strings.TrimSpace(id))]
	return canonical, ok
}

// ParseSPDXExpression validates an SPDX license expression (SPDX 2.3
// Annex D, the subset without LicenseRef): identifiers, an optional "+",
// WITH <exception>, AND / OR, and parentheses. It returns the expression
// with canonical spellings and the distinct license ids it names, in order
// of first appearance — what policy gates compare against.
func ParseSPDXExpression(expr string) (canonical string, ids []string, err error) {
	p := &spdxParser{toks: spdxTokens(expr)}
	if len(p.toks) == 0 {
		return "", nil, fmt.Errorf("empty license expression")
	}
	out, err := p.parseOr()
	if err != nil {
		return "", nil, err
	}
	if p.pos != len(p.toks) {
		return "", nil, fmt.Errorf("unexpected %q", p.toks[p.pos])
	}
	return out, p.ids, nil
}

type spdxParser struct {
	toks []string
	pos  int
	ids  []string
}

func spdxTokens(s string) []string {
	var toks []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case '(', ')':
			flush()
			toks = append(toks, string(r))
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

func (p *spdxParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *spdxParser) parseOr() (string, error) {
	left, err := p.parseAnd()
	if err != nil {
		return "", err
	}
	for strings.EqualFold(p.peek(), "OR") {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return "", err
		}
		left = left + " OR " + right
	}
	return left, nil
}

func (p *spdxParser) parseAnd() (string, error) {
	left, err := p.parseTerm()
	if err != nil {
		return "", err
	}
	for strings.EqualFold(p.peek(), "AND") {
		p.pos++
		right, err := p.parseTerm()
		if err != nil {
			return "", err
		}
		left = left + " AND " + right
	}
	return left, nil
}

func (p *spdxParser) parseTerm() (string, error) {
	tok := p.peek()
	switch {
	case tok == "":
		return "", fmt.Errorf("expression ends where a license id was expected")
	case tok == "(":
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return "", err
		}
		if p.peek() != ")" {
			return "", fmt.Errorf("missing closing parenthesis")
		}
		p.pos++
		return "(" + inner + ")", nil
	case tok == ")" || strings.EqualFold(tok, "AND") || strings.EqualFold(tok, "OR") || strings.EqualFold(tok, "WITH"):
		return "", fmt.Errorf("unexpected %q", tok)
	}
	p.pos++
	plus := strings.HasSuffix(tok, "+")
	id := strings.TrimSuffix(tok, "+")
	if strings.HasPrefix(strings.ToLower(id), "licenseref-") {
		return "", fmt.Errorf("%q: custom LicenseRef identifiers are not accepted for a public publish", tok)
	}
	canon, ok := KnownSPDXID(id)
	if !ok {
		return "", fmt.Errorf("%q is not an SPDX license identifier", tok)
	}
	p.ids = appendUnique(p.ids, canon)
	out := canon
	if plus {
		out += "+"
	}
	if strings.EqualFold(p.peek(), "WITH") {
		p.pos++
		exc := p.peek()
		if exc == "" || exc == "(" || exc == ")" {
			return "", fmt.Errorf("WITH must be followed by an exception identifier")
		}
		p.pos++
		ecanon, ok := KnownSPDXException(exc)
		if !ok {
			return "", fmt.Errorf("%q is not an SPDX license exception identifier", exc)
		}
		out += " WITH " + ecanon
	}
	return out, nil
}

func appendUnique(ids []string, id string) []string {
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}
