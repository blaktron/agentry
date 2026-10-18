package manifest

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// execCommandCases are command names with the verdict the program-name
// grammar gives them. Every non-ASCII or control character is written as an
// escape so the source carries no invisible character.
var execCommandCases = []struct {
	name string
	cmd  string
	ok   bool
}{
	// the names the shipped QuickAgents, the template and the examples declare
	{"cat", "cat", true},
	{"git", "git", true},
	{"jq", "jq", true},
	{"openssl", "openssl", true},
	{"python3", "python3", true},
	{"sha256sum", "sha256sum", true},
	{"wc", "wc", true},
	// names of published releases
	{"leading digit", "7z", true},
	{"mixed case", "analyzeHeadless", true},
	// shapes a binary's name takes
	{"dot and digit", "python3.12", true},
	{"plus", "g++", true},
	{"hyphen", "ssh-keygen", true},
	{"underscore", "pg_dump", true},
	{"64 characters", strings.Repeat("a", 64), true},

	{"65 characters", strings.Repeat("a", 65), false},
	{"right-to-left override", "git\u202ecod", false},
	{"left-to-right isolate", "\u2066git", false},
	{"zero-width joiner", "g\u200dit", false},
	{"zero-width space", "g\u200bit", false},
	{"word joiner", "git\u2060", false},
	{"byte order mark", "\ufeffgit", false},
	{"soft hyphen", "g\u00adit", false},
	{"tag character", "git\U000e0041", false},
	{"newline", "git\n", false},
	{"nul", "git\x00", false},
	{"delete", "git\x7f", false},
	{"C1 control", "git\u0085", false},
	{"space", "go test", false},
	{"tab", "go\ttest", false},
	{"no-break space", "go\u00a0test", false},
	{"path separator", "/usr/bin/git", false},
	{"relative path", "./run.sh", false},
	{"backslash", "dir\\git", false},
	{"leading hyphen", "-rf", false},
	{"leading dot", ".git", false},
	{"leading plus", "+x", false},
	{"shell metacharacter", "git;rm", false},
	{"substitution", "$(id)", false},
	{"non-ASCII letter", "g\u0131t", false},
	{"fullwidth letter", "\uff47it", false},
	{"empty", "", false},
}

func TestValidExecCommand(t *testing.T) {
	for _, tc := range execCommandCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidExecCommand(tc.cmd); got != tc.ok {
				t.Fatalf("ValidExecCommand(%+q) = %v, want %v", tc.cmd, got, tc.ok)
			}
		})
	}
}

// TestV5ExecCommandGrammar: V5 names the command that is outside the
// grammar, by its index, and accepts the rest.
func TestV5ExecCommandGrammar(t *testing.T) {
	for _, tc := range execCommandCases {
		t.Run(tc.name, func(t *testing.T) {
			m := validSkillManifest()
			m.Capabilities.Exec = ExecCapability{Commands: []string{"jq", tc.cmd}}
			errs := Validate(m)
			if tc.ok {
				wantClean(t, errs)
				return
			}
			wantIssue(t, errs, "V5", SeverityError, "capabilities.exec.commands[1]")
			if len(Blocking(errs)) == 0 {
				t.Fatal("a command outside the grammar must block publish")
			}
			for _, err := range errs {
				if i, ok := AsIssue(err); ok && strings.ContainsFunc(i.Message, func(r rune) bool {
					return r > 0x7e || (r < 0x20 && r != '\t')
				}) {
					t.Fatalf("message carries a raw non-ASCII or control character: %+q", i.Message)
				}
			}
		})
	}
}

// TestV5ExecCommandLengthNamesTheCap: a name over the cap is refused for its
// length, without echoing it.
func TestV5ExecCommandLengthNamesTheCap(t *testing.T) {
	m := validSkillManifest()
	m.Capabilities.Exec = ExecCapability{Commands: []string{strings.Repeat("a", 65)}}
	var msg string
	for _, err := range Validate(m) {
		if i, ok := AsIssue(err); ok && i.Rule == "V5" && strings.Contains(i.Path, "exec.commands[0]") {
			msg = i.Message
		}
	}
	if !strings.Contains(msg, "64") || strings.Contains(msg, strings.Repeat("a", 65)) {
		t.Fatalf("message = %q; want the cap named and the command not echoed", msg)
	}
}

// TestV2SchemaExecCommandPattern pins both schema versions beside the Go
// rule: the pattern of an exec command is the grammar V5 enforces.
func TestV2SchemaExecCommandPattern(t *testing.T) {
	for _, file := range []string{"agent-manifest-1.schema.json", "agent-manifest-2.schema.json"} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile("../../schemas/" + file)
			if err != nil {
				t.Fatal(err)
			}
			var schema struct {
				Defs struct {
					Exec struct {
						Description string `json:"description"`
						OneOf       []struct {
							Properties struct {
								Commands struct {
									Items struct {
										Pattern   string `json:"pattern"`
										MaxLength int    `json:"maxLength"`
									} `json:"items"`
								} `json:"commands"`
							} `json:"properties"`
						} `json:"oneOf"`
					} `json:"exec"`
				} `json:"$defs"`
			}
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			items := schema.Defs.Exec.OneOf[1].Properties.Commands.Items
			if items.Pattern != execCommandRE.String() {
				t.Fatalf("pattern %q != %s", items.Pattern, execCommandRE)
			}
			if !strings.Contains(schema.Defs.Exec.Description, "program name") {
				t.Fatalf("the exec description does not say what the grammar is")
			}
		})
	}
}
