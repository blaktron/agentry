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
