package manifest

import (
	"bytes"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Rename returns raw, an agent.yaml, with its top-level namespace and
// name set to the given ones: the one change a fork's first commit
// makes to the manifest it copies, since a manifest must name the agent
// it is submitted to. Everything else stays as written, comments
// included, though the YAML is re-emitted with two-space indentation. A
// key that is absent is added after the last of schemaVersion,
// namespace and name that is present, so the file still reads in the
// usual order. It refuses a document that is not a single mapping.
func Rename(raw []byte, namespace, name string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("manifest: rename: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("manifest: rename: agent.yaml is not a single mapping")
	}
	m := doc.Content[0]
	setScalar(m, "namespace", namespace, "schemaVersion")
	setScalar(m, "name", name, "namespace")

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("manifest: rename: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("manifest: rename: %w", err)
	}
	return out.Bytes(), nil
}

// setScalar sets key's value in the mapping m to a plain string scalar, or
// inserts the pair after the key named after (at the start when that is
// absent too).
func setScalar(m *yaml.Node, key, value, after string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v := m.Content[i+1]
			v.Kind, v.Tag, v.Value, v.Style = yaml.ScalarNode, "!!str", value, 0
			v.Content = nil
			return
		}
	}
	at := 0
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == after {
			at = i + 2
		}
	}
	pair := []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	}
	m.Content = append(m.Content[:at], append(pair, m.Content[at:]...)...)
}

// RenameFrontmatter returns content, an instruction file, with the name in
// its leading `---` frontmatter set to name, and whether it changed
// anything. V9 refuses an instruction whose frontmatter name differs from
// the manifest's, so a fork that takes another name renames both. Only the
// top-level name line is rewritten; every other byte stays as written. A
// file with no frontmatter, or whose frontmatter names no agent or names
// this one already, is returned unchanged. It refuses a name written in a
// form it cannot rewrite in place (a block scalar, a key spread over
// lines), since the result would still contradict the manifest.
func RenameFrontmatter(content []byte, name string) ([]byte, bool, error) {
	fm, ok, err := ParseFrontmatter(content)
	if !ok || err != nil || fm.Name == "" || fm.Name == name {
		return content, false, nil
	}
	lines := bytes.SplitAfter(content, []byte("\n"))
	if len(lines) == 0 {
		return content, false, nil
	}
	// The first line is the opening ---, after a byte order mark; the
	// block ends at the next --- or ... line.
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		body := bytes.TrimRight(line, "\r\n")
		if t := string(body); t == "---" || t == "..." {
			break
		}
		key, _, found := bytes.Cut(body, []byte(":"))
		if !found || !bytes.EqualFold(bytes.TrimRight(key, " \t"), []byte("name")) || len(key) == 0 || key[0] == ' ' || key[0] == '\t' {
			continue
		}
		ending := line[len(body):]
		lines[i] = append(append([]byte(string(bytes.TrimRight(key, " \t"))+": "), name...), ending...)
		out := bytes.Join(lines, nil)
		if got, _, err := ParseFrontmatter(out); err != nil || got.Name != name {
			return content, false, fmt.Errorf("manifest: rename: the frontmatter's name could not be rewritten in place")
		}
		return out, true, nil
	}
	return content, false, errors.New("manifest: rename: the frontmatter's name could not be found to rewrite")
}
