package manifest

import (
	"bytes"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Frontmatter is the YAML block a skill file may open with. Consuming
// runtimes (the claude-skill export, §5.6) read `name` and `description`
// from it, and the exporter keeps an existing block verbatim (DEV-044), so
// whatever it says is what the consumer sees. V9 and S1 compare it against
// the signed manifest (agentry#47).
type Frontmatter struct {
	Name        string
	Description string
	// Keys lists every top-level key present, for the report.
	Keys []string
}

// ParseFrontmatter extracts the leading `---` YAML block of a skill file.
// ok is false when the file has no frontmatter; a block that is not valid
// YAML returns ok=true with an error so the caller can flag it.
func ParseFrontmatter(content []byte) (fm Frontmatter, ok bool, err error) {
	content = bytes.TrimPrefix(content, []byte("\xef\xbb\xbf"))
	if !bytes.HasPrefix(content, []byte("---\n")) && !bytes.HasPrefix(content, []byte("---\r\n")) {
		return fm, false, nil
	}
	rest := content[3:]
	rest = bytes.TrimLeft(rest, "\r\n")
	// The block ends at the next line that is exactly "---" (or "...").
	var block []byte
	end := -1
	for off := 0; off <= len(rest); {
		nl := bytes.IndexByte(rest[off:], '\n')
		var line []byte
		if nl < 0 {
			line = rest[off:]
		} else {
			line = rest[off : off+nl]
		}
		t := strings.TrimRight(string(line), "\r")
		if t == "---" || t == "..." {
			end = off
			break
		}
		if nl < 0 {
			break
		}
		off += nl + 1
	}
	if end < 0 {
		return fm, true, errFrontmatterUnterminated
	}
	block = rest[:end]
	var raw map[string]any
	if err := yaml.Unmarshal(block, &raw); err != nil {
		return fm, true, err
	}
	for k, v := range raw {
		fm.Keys = append(fm.Keys, k)
		switch strings.ToLower(k) {
		case "name":
			fm.Name = strings.TrimSpace(stringValue(v))
		case "description":
			fm.Description = strings.TrimSpace(stringValue(v))
		}
	}
	sort.Strings(fm.Keys)
	return fm, true, nil
}

var errFrontmatterUnterminated = &Issue{Rule: "V9", Path: "entrypoints.skill", Message: "frontmatter block is not terminated by a --- line"}

func stringValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		b, _ := yaml.Marshal(t)
		return strings.TrimSpace(string(b))
	}
}

// NormalizeProse folds whitespace and case so a description that differs
// only in wrapping or punctuation spacing is not a contradiction.
func NormalizeProse(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
