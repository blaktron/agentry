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
					Properties struct {
						Value struct {
							Enum []string `json:"enum"`
						} `json:"value"`
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
		if !slices.Equal(p.Properties.Value.Enum, r.Values) {
			t.Errorf("%s: schema values %v, catalogue %v", r.ID, p.Properties.Value.Enum, r.Values)
		}
	}
}
