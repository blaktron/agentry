module github.com/blaktron/agentry/tools/oapi-codegen

go 1.27.3

tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen

require (
	// oapi-codegen v2.8.1 reads and writes YAML nodes of gopkg.in/yaml.v3.
	// speakeasy-api/openapi v1.26 and later, speakeasy-api/jsonpath v0.7 and
	// later and go-yit builds after May 2025 use go.yaml.in/yaml nodes, which
	// that code cannot take, so these three stay on the newest releases that
	// still use yaml.v3.
	github.com/dprotaso/go-yit v0.0.0-20250513224043-18a80f8f6df4 // indirect
	github.com/getkin/kin-openapi v0.152.0 // indirect
	github.com/go-openapi/jsonpointer v1.0.2 // indirect
	github.com/oapi-codegen/oapi-codegen/v2 v2.8.1 // indirect
	github.com/oasdiff/yaml v0.1.3 // indirect
	github.com/oasdiff/yaml3 v0.0.16 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3 // indirect
	github.com/sergi/go-diff v1.3.1 // indirect
	github.com/speakeasy-api/jsonpath v0.6.3 // indirect
	github.com/speakeasy-api/openapi v1.25.6 // indirect
	github.com/vmware-labs/yaml-jsonpath v0.3.2 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
