package managedsettings

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestSchemaMatchesCatalogue holds the published JSON Schema to the Go
// type and the catalogue: the same top-level fields, every row under
// settings with the same values, and nothing else.
func TestSchemaMatchesCatalogue(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/managed-settings-1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string `json:"required"`
		Properties struct {
			Schema struct {
				Const string `json:"const"`
			} `json:"schema"`
			Settings struct {
				Properties map[string]struct {
					Description string `json:"description"`
					Properties  struct {
						Value struct {
							Enum             []string `json:"enum"`
							Type             string   `json:"type"`
							Ref              string   `json:"$ref"`
							Pattern          string   `json:"pattern"`
							MaxLength        *int     `json:"maxLength"`
							ExclusiveMinimum *float64 `json:"exclusiveMinimum"`
							Maximum          *float64 `json:"maximum"`
							MinItems         *int     `json:"minItems"`
							Items            struct {
								Enum []string `json:"enum"`
							} `json:"items"`
							Properties map[string]struct {
								Enum []string `json:"enum"`
								Ref  string   `json:"$ref"`
							} `json:"properties"`
						} `json:"value"`
						Locked *struct {
							Const *bool `json:"const"`
						} `json:"locked"`
					} `json:"properties"`
				} `json:"properties"`
			} `json:"settings"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Properties.Schema.Const != Schema {
		t.Errorf("schema const %q, want %q", schema.Properties.Schema.Const, Schema)
	}

	var fields []string
	typ := reflect.TypeOf(Document{})
	for i := range typ.NumField() {
		fields = append(fields, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
	}
	sort.Strings(fields)
	required := slices.Clone(schema.Required)
	sort.Strings(required)
	if !slices.Equal(fields, required) {
		t.Errorf("schema requires %v, Document has %v", required, fields)
	}

	rows := Catalogue()
	if len(rows) != len(schema.Properties.Settings.Properties) {
		t.Errorf("schema has %d rows, catalogue %d", len(schema.Properties.Settings.Properties), len(rows))
	}
	for _, r := range rows {
		p, ok := schema.Properties.Settings.Properties[r.ID]
		if !ok {
			t.Errorf("%s: not in the schema", r.ID)
			continue
		}
		if p.Description == "" {
			t.Errorf("%s: no description", r.ID)
		}
		v := p.Properties.Value
		switch r.Kind {
		case KindChoice:
			if !slices.Equal(v.Enum, r.Values) {
				t.Errorf("%s: schema values %v, catalogue %v", r.ID, v.Enum, r.Values)
			}
		case KindSet:
			if v.Type != "array" || !slices.Equal(v.Items.Enum, r.Values) {
				t.Errorf("%s: schema set %s of %v, catalogue %v", r.ID, v.Type, v.Items.Enum, r.Values)
			}
			if least := 1; r.AllowEmpty && (v.MinItems == nil || *v.MinItems != 0) || !r.AllowEmpty && (v.MinItems == nil || *v.MinItems != least) {
				t.Errorf("%s: schema minItems %v, catalogue allows empty %v", r.ID, v.MinItems, r.AllowEmpty)
			}
		case KindModel:
			if v.Type != "object" || !slices.Equal(v.Properties["provider"].Enum, r.Values) {
				t.Errorf("%s: schema model providers %v, catalogue %v", r.ID, v.Properties["provider"].Enum, r.Values)
			}
		case KindSource:
			_, provider := v.Properties["provider"]
			if v.Type != "object" || !slices.Equal(v.Properties["source"].Enum, r.Values) ||
				!slices.Equal(v.Properties["provider"].Enum, r.Providers) || provider != (len(r.Providers) > 0) {
				t.Errorf("%s: schema source %v / providers %v, catalogue %v / %v", r.ID, v.Properties["source"].Enum, v.Properties["provider"].Enum, r.Values, r.Providers)
			}
			// A row that delivers keys describes the reference; Check also
			// refuses one on a row that does not.
			if _, key := v.Properties["key"]; r.Delivers && !key {
				t.Errorf("%s: the schema does not describe the key reference the row delivers", r.ID)
			}
		case KindCap:
			want := "number"
			if r.Integer {
				want = "integer"
			}
			if v.Type != want || v.ExclusiveMinimum == nil || *v.ExclusiveMinimum != 0 || v.Maximum == nil || *v.Maximum != r.Max {
				t.Errorf("%s: schema cap %s (0, %v], catalogue %s (0, %v]", r.ID, v.Type, v.Maximum, want, r.Max)
			}
		case KindSources:
			if v.Ref != "#/$defs/sources" {
				t.Errorf("%s: schema value %q, want the sources definition", r.ID, v.Ref)
			}
		case KindQuickAgents:
			if v.Ref != "#/$defs/quickagents" {
				t.Errorf("%s: schema value %q, want the quickagents definition", r.ID, v.Ref)
			}
		case KindText:
			if v.Type != "string" || v.MaxLength == nil || *v.MaxLength != r.MaxLength {
				t.Errorf("%s: schema text %s of %v, catalogue %d", r.ID, v.Type, v.MaxLength, r.MaxLength)
			}
		case KindToggle:
			if v.Type != "boolean" {
				t.Errorf("%s: schema type %q, want boolean", r.ID, v.Type)
			}
		case KindServers, KindPacks, KindToolModels:
			if want := "#/$defs/" + string(r.Kind); v.Ref != want {
				t.Errorf("%s: schema value %q, want %q", r.ID, v.Ref, want)
			}
		case KindMinimumVersion:
			if v.Type != "string" || v.Pattern != versionPattern.String() {
				t.Errorf("%s: schema pattern %q, catalogue %q", r.ID, v.Pattern, versionPattern.String())
			}
		default:
			t.Errorf("%s: kind %q", r.ID, r.Kind)
		}
		lockOnly := p.Properties.Locked != nil && p.Properties.Locked.Const != nil && *p.Properties.Locked.Const
		if lockOnly != r.LockOnly {
			t.Errorf("%s: schema lock-only %v, catalogue %v", r.ID, lockOnly, r.LockOnly)
		}
	}
}
