package manifest

import "testing"

// FuzzParse is a crash-safety fuzz target: Parse and the downstream
// Validate / ValidateInContext / CanonicalJSON paths must never panic
// on arbitrary input.
func FuzzParse(f *testing.F) {
	seeds := [][]byte{
		[]byte(normativeYAML),
		[]byte("schemaVersion: \"1\"\nname: a\nnamespace: b\nkind: prompt-agent\nversion: 0.1.0\nsummary: s\npublish:\n  include: [agent.yaml]\n"),
		[]byte("schemaVersion: \"1\"\nkind: mcp-server\nentrypoints:\n  mcp:\n    command: node\n    args: [src/server.js]\n    transport: stdio\n"),
		[]byte("capabilities:\n  network:\n    egress: none\n  filesystem:\n    read:\n      paths: [a, b]\n  exec:\n    commands: [git]\n"),
		[]byte("schemaVersion: \"2\"\n"),
		[]byte("unknown: key\n"),
		[]byte("publish:\n  include: [\"**\", \"docs/[a-\", \"../x\"]\n"),
		[]byte("---\na: 1\n---\nb: 2\n"),
		[]byte("{{{"),
		[]byte("\x00\xff\xfe"),
		[]byte("summary: \"\\u0001\"\ntags: [UPPER, dup, dup]\n"),
		[]byte("version: v1.2.3\nname: -bad-\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	ctx := Context{
		Namespace:        "acme",
		Name:             "incident-summarizer",
		TagVersion:       "v1.4.2",
		ExistingVersions: map[Channel][]string{ChannelStable: {"1.0.0"}, ChannelBeta: {"1.1.0-beta.1"}},
		Public:           true,
		Files: []FileInfo{
			{Path: "agent.yaml", Size: 100},
			{Path: "README.md", Size: 100},
			{Path: "SKILL.md", Size: 100},
			{Path: "prompts/system.md", Size: 100},
			{Path: "LICENSE", Size: 100},
			{Path: "link", Size: 1, Symlink: true},
		},
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			return
		}
		if m == nil {
			t.Fatal("Parse returned nil manifest without error")
		}
		_ = Validate(m)
		_ = ValidateInContext(m, ctx)
		if _, err := CanonicalJSON(m); err != nil {
			t.Fatalf("CanonicalJSON on parsed manifest: %v", err)
		}
	})
}
