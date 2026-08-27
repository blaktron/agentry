package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
)

// CanonicalJSON encodes m as deterministic JSON: object keys sorted
// lexicographically at every level, and null values, empty objects, and
// empty arrays pruned so that undeclared optional fields never appear.
// Two structurally identical manifests always produce byte-identical
// output; this form is stored as agent_versions.manifest (§4.2).
//
// The manifest carries no numeric fields, so no floating-point
// canonicalization concerns apply.
func CanonicalJSON(m *Manifest) ([]byte, error) {
	if m == nil {
		return nil, errors.New("manifest: CanonicalJSON: nil manifest")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("manifest: CanonicalJSON: encoding: %w", err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("manifest: CanonicalJSON: re-decoding: %w", err)
	}
	out, err := json.Marshal(pruneEmpty(v))
	if err != nil {
		return nil, fmt.Errorf("manifest: CanonicalJSON: re-encoding: %w", err)
	}
	return out, nil
}

// pruneEmpty removes nulls, empty objects, and empty arrays from object
// values, recursively. Array elements are kept as-is (manifest arrays hold
// strings and objects with required fields only).
func pruneEmpty(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			pv := pruneEmpty(val)
			if pv == nil {
				continue
			}
			if m, ok := pv.(map[string]any); ok && len(m) == 0 {
				continue
			}
			if a, ok := pv.([]any); ok && len(a) == 0 {
				continue
			}
			out[k] = pv
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = pruneEmpty(val)
		}
		return out
	default:
		return v
	}
}
