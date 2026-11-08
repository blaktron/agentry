package manifest

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// The YAML decoder reports a field it does not know, or a value of the wrong
// shape, in Go's terms ("field licence not found in type manifest.Manifest",
// "cannot unmarshal !!str into []manifest.Mode"). parseError says the same in
// the manifest's: the block, the field, the shape expected and what was found,
// and the nearest field name when the key looks like a misspelling. A type
// name never reaches the author.

var (
	unknownFieldRE = regexp.MustCompile(`^line (\d+): field (\S+) not found in type (\S+)$`)
	wrongShapeRE   = regexp.MustCompile("^line (\\d+): cannot unmarshal !!(\\w+)(?: `(.*)`)? into (\\S+)$")
)

// parseError rewrites a decode error of agent.yaml.
func parseError(err error) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return fmt.Errorf("manifest: agent.yaml is not valid YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	msgs := make([]string, 0, len(te.Errors))
	for _, e := range te.Errors {
		msgs = append(msgs, typeErrorMessage(e))
	}
	return fmt.Errorf("manifest: agent.yaml: %s", strings.Join(msgs, "; "))
}

// typeErrorMessage rewrites one of the decoder's type errors.
func typeErrorMessage(e string) string {
	if m := unknownFieldRE.FindStringSubmatch(e); m != nil {
		line, key, typ := m[1], m[2], m[3]
		block, fields := blockOf(typ)
		msg := fmt.Sprintf("line %s: %s has no field %q", line, block, key)
		if s := nearest(key, fields); s != "" {
			msg += fmt.Sprintf(" (did you mean %q?)", s)
		}
		return msg
	}
	if m := wrongShapeRE.FindStringSubmatch(e); m != nil {
		line, kind, val, typ := m[1], m[2], m[3], m[4]
		found := map[string]string{
			"str": "text", "seq": "a list", "map": "a mapping", "int": "a number",
			"float": "a number", "bool": "true or false", "null": "nothing",
		}[kind]
		if found == "" {
			found = "a value of another kind"
		}
		if val != "" && kind != "seq" && kind != "map" {
			found += fmt.Sprintf(" (%q)", val)
		}
		return fmt.Sprintf("line %s: expected %s, found %s", line, shapeOf(typ), found)
	}
	// A message the decoder words some other way: keep its line, never a
	// Go type name.
	return goTypeRE.ReplaceAllString(e, "a value of another shape")
}

var goTypeRE = regexp.MustCompile(`(\[\])*\*?manifest\.[A-Z]\w*|map\[\w+\]\S+|\[\]\w+|!![a-z]+`)

// shapeOf says what a Go type the decoder named takes, in YAML's terms.
func shapeOf(typ string) string {
	switch {
	case strings.HasPrefix(typ, "[]"):
		return "a list (one \"- item\" per line, or [a, b])"
	case strings.HasPrefix(typ, "map["):
		return "a mapping (\"key: value\" lines)"
	case typ == "string":
		return "text"
	case typ == "bool":
		return "true or false"
	case strings.HasPrefix(typ, "int"), strings.HasPrefix(typ, "uint"):
		return "a whole number"
	case strings.HasPrefix(typ, "float"):
		return "a number"
	}
	if t, ok := manifestTypes()[strings.TrimPrefix(typ, "manifest.")]; ok {
		switch t.Kind() {
		case reflect.Struct, reflect.Map:
			return "a mapping (\"key: value\" lines)"
		case reflect.Slice:
			return "a list (one \"- item\" per line, or [a, b])"
		case reflect.String:
			return "text"
		case reflect.Bool:
			return "true or false"
		case reflect.Int, reflect.Int64, reflect.Int32:
			return "a whole number"
		}
	}
	return "a value of another shape"
}

// blockOf names the block a manifest type is decoded from ("the manifest",
// "capabilities.network") and the fields it takes.
func blockOf(typ string) (string, []string) {
	name := strings.TrimPrefix(typ, "manifest.")
	t, ok := manifestTypes()[name]
	if !ok || t.Kind() != reflect.Struct {
		return "this block", nil
	}
	path := strings.ReplaceAll(blockPaths()[name], "[]", "[n]")
	if path == "" {
		path = "the manifest"
	}
	return path, yamlFields(t)
}

var (
	typesOnce sync.Once
	types     map[string]reflect.Type
	paths     map[string]string
)

// manifestTypes maps each struct type reachable from Manifest to its type,
// and blockPaths to the first YAML path it is decoded at.
func manifestTypes() map[string]reflect.Type { typesOnce.Do(walkTypes); return types }
func blockPaths() map[string]string          { typesOnce.Do(walkTypes); return paths }

func walkTypes() {
	types, paths = map[string]reflect.Type{}, map[string]string{}
	var walk func(t reflect.Type, path string)
	walk = func(t reflect.Type, path string) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			if t.Kind() == reflect.Slice && path != "" {
				path += "[]"
			}
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || t.PkgPath() != reflect.TypeOf(Manifest{}).PkgPath() {
			if t.Name() != "" && t.PkgPath() == reflect.TypeOf(Manifest{}).PkgPath() {
				types[t.Name()] = t
			}
			return
		}
		if _, seen := types[t.Name()]; seen {
			return
		}
		types[t.Name()] = t
		paths[t.Name()] = path
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag, inline := yamlName(f)
			if tag == "-" {
				continue
			}
			child := path
			if !inline {
				if child != "" {
					child += "."
				}
				child += tag
			}
			walk(f.Type, child)
		}
	}
	walk(reflect.TypeOf(Manifest{}), "")
}

// yamlName is a field's YAML key, and whether it is inlined.
func yamlName(f reflect.StructField) (string, bool) {
	tag := f.Tag.Get("yaml")
	name, opts, _ := strings.Cut(tag, ",")
	if strings.Contains(opts, "inline") {
		return "", true
	}
	if name == "" {
		name = strings.ToLower(f.Name)
	}
	return name, false
}

// yamlFields lists the YAML keys a struct type takes, sorted.
func yamlFields(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, inline := yamlName(f)
		switch {
		case name == "-":
		case inline:
			inner := f.Type
			for inner.Kind() == reflect.Pointer {
				inner = inner.Elem()
			}
			if inner.Kind() == reflect.Struct {
				out = append(out, yamlFields(inner)...)
			}
		default:
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// nearest is the field closest to key by edit distance, when it is close
// enough to be a misspelling of it (at most two edits, and fewer than half
// the key's length), or "".
func nearest(key string, fields []string) string {
	best, bestD := "", 3
	for _, f := range fields {
		if d := editDistance(strings.ToLower(key), strings.ToLower(f)); d < bestD && d*2 < len(key) {
			best, bestD = f, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
