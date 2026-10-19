package draftproof

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// pairsChanged are the pairs whose Builder rendering changes what the
// version declares, so the proof must not hold, each with what changed.
// Every other pair under testdata/pairs must prove as its draft. The pairs
// were made by running each draft through the hosted site's own Publish
// this version path (revision import, build submit, a headless browser's
// form post): draft/ is the Drafter's package/, builder/ is what the
// registry received. The site keeps a choice as written and reads every
// field with LF, and each builder/ is each draft through the revision
// import of the same QuickAgent and licence, with Publish this version's
// entries posted with CRLF as a browser does. What is left below is what
// the Builder still changes: a name the registry does not know (a mode, a
// data category, a question type), and a value with a space its one-word
// fields cannot hold. The registry would refuse each of those but a path
// with a space, which it accepts.
var pairsChanged = map[string]string{
	"data-access-unknown-dupes-order": "an unknown data category is dropped",
	"egress-host-with-space":          "a host holding a space is dropped",
	"fs-paths-and-exec-commands":      "a path and a command holding a space are dropped",
	"intake-every-type":               "an unknown question type is dropped",
	"interactive-modes-opening":       "an unknown mode is dropped",
	"tags-licence-kept-name-changed":  "a tag holding a space is dropped",
}

// TestTheBuilderRenderingOfADraftProvesAsTheDraft: the proof the sandbox
// host computes over a draft's package/ and the one the registry computes
// over what Publish this version submits agree whenever the Builder only
// writes the draft differently (its own name, namespace, version and
// licence, its layout and order, CRLF from the browser, defaults, the
// fields it cannot hold), and disagree when it changes what is declared.
func TestTheBuilderRenderingOfADraftProvesAsTheDraft(t *testing.T) {
	dirs, err := os.ReadDir(filepath.Join("testdata", "pairs"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	same := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		name := d.Name()
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			draft, _, err := OfDir(filepath.Join("testdata", "pairs", name, "draft"))
			if err != nil {
				t.Fatalf("draft: %v", err)
			}
			built, path, err := OfDir(filepath.Join("testdata", "pairs", name, "builder"))
			if err != nil {
				t.Fatalf("builder: %v", err)
			}
			if path != "AGENT.md" {
				t.Errorf("the Builder's instruction file is %q", path)
			}
			if draft.Instruction != built.Instruction {
				t.Errorf("the instruction text does not prove as the draft's")
			}
			why, changed := pairsChanged[name]
			switch {
			case changed && draft.Manifest == built.Manifest:
				t.Errorf("the Builder changed what is declared (%s) and the proof still holds", why)
			case !changed && draft.Manifest != built.Manifest:
				t.Errorf("the Builder only wrote the manifest differently and the proof does not hold")
			case !changed:
				same++
			}
		})
	}
	for name := range pairsChanged {
		if !seen[name] {
			t.Errorf("pairsChanged names %s, which is not under testdata/pairs", name)
		}
	}
	if same < 20 {
		t.Errorf("only %d pairs prove as their draft: the corpus has lost its point", same)
	}
}

const base = `schemaVersion: "2"
name: weekly-summary
namespace: alice
version: 1.2.0
summary: Summarizes the week's closed issues
license: MIT
homepage: https://example.org
authors: [{name: Alice}]
tags: [github, weekly]
modes: [autonomous, interactive]
entrypoints:
  instruction: AGENT.md
intake:
  - id: repo
    prompt: Which repository?
    required: true
  - id: depth
    prompt: How deep?
    type: choice
    choices: [short, long]
interactive:
  opening: Hello.
  idleTimeoutSeconds: 600
guide:
  overview: Reads the issues.
  prepare: [a token]
knowledge:
  accepts:
    prompt: Attach your notes.
capabilities:
  network:
    egress: [api.github.com]
  filesystem:
    read: workspace
    write: none
  exec: none
  secrets: [GITHUB_TOKEN]
  dataAccess: [code, tickets]
publish:
  include: [agent.yaml, AGENT.md, README.md, LICENSE]
  channel: stable
`

func proofOf(t *testing.T, manifestYAML, instruction string) Proof {
	t.Helper()
	p, err := Of([]byte(manifestYAML), []byte(instruction))
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	return p
}

// TestTheProofSeesEveryChangeOfMeaning: any change to what the Builder
// keeps changes the proof; the fields it sets or cannot hold do not.
func TestTheProofSeesEveryChangeOfMeaning(t *testing.T) {
	const text = "Summarize the issues.\n"
	want := proofOf(t, base, text)
	for _, tc := range []struct{ old, new string }{
		{"egress: [api.github.com]", "egress: [api.github.com, evil.example]"},
		{"egress: [api.github.com]", "egress: \"*\""},
		{"read: workspace", "read: none"},
		{"write: none", "write: workspace"},
		{"exec: none", "exec: {commands: [curl]}"},
		{"secrets: [GITHUB_TOKEN]", "secrets: [GITHUB_TOKEN, AWS_KEY]"},
		{"dataAccess: [code, tickets]", "dataAccess: [code, tickets, financial]"},
		{"modes: [autonomous, interactive]", "modes: [autonomous]"},
		{"summary: Summarizes the week's closed issues", "summary: Summarizes the week's open issues"},
		{"tags: [github, weekly]", "tags: [github]"},
		{"prompt: Which repository?", "prompt: Which repositories?"},
		{"required: true", "required: false"},
		{"choices: [short, long]", "choices: [short, long, full]"},
		{"opening: Hello.", "opening: Hi."},
		{"overview: Reads the issues.", "overview: Reads every issue."},
		{"prepare: [a token]", "prepare: [a token, a list]"},
		{"prompt: Attach your notes.", "prompt: Attach your keys."},
	} {
		changed := strings.Replace(base, tc.old, tc.new, 1)
		if changed == base {
			t.Fatalf("the edit %q did not apply", tc.old)
		}
		if p := proofOf(t, changed, text); p.Manifest == want.Manifest {
			t.Errorf("%q → %q did not change the proof", tc.old, tc.new)
		}
	}
	if proofOf(t, base, "Summarize the issue.\n").Instruction == want.Instruction {
		t.Error("a changed instruction text did not change the proof")
	}
	for _, tc := range []struct{ old, new string }{
		{"name: weekly-summary", "name: weekly-summary-draft"},
		{"namespace: alice", "namespace: draft"},
		{"version: 1.2.0", "version: 0.1.0"},
		{"license: MIT", "license: Apache-2.0"},
		{"homepage: https://example.org\n", ""},
		{"authors: [{name: Alice}]\n", ""},
		{"  idleTimeoutSeconds: 600\n", ""},
		{"  channel: stable\n", ""},
		{"include: [agent.yaml, AGENT.md, README.md, LICENSE]", "include: [agent.yaml, AGENT.md]"},
		{"modes: [autonomous, interactive]", "modes: [interactive, autonomous, interactive]"},
		{"dataAccess: [code, tickets]", "dataAccess: [tickets, code]"},
		{"    write: none\n", ""},
		{"  exec: none\n", ""},
		{"prompt: Which repository?", "prompt: \"  Which repository?  \""},
		{"    required: true\n", "    required: true\n    type: text\n"},
		{"schemaVersion: \"2\"", "schemaVersion: \"1\""},
		{"name: weekly-summary\n", "kind: prompt-agent\nname: weekly-summary\n"},
		{"  instruction: AGENT.md\n", "  instruction: AGENT.md\n  skill: SKILL.md\n"},
		{"  instruction: AGENT.md\n", "  instruction: AGENT.md\n  mcp: {command: node, transport: stdio}\n"},
		{"publish:\n", "dependencies:\n  agents:\n    - ref: alice/helper\n      version: ^1\npublish:\n"},
	} {
		same := strings.Replace(base, tc.old, tc.new, 1)
		if same == base {
			t.Fatalf("the edit %q did not apply", tc.old)
		}
		if p := proofOf(t, same, text); p.Manifest != want.Manifest {
			t.Errorf("%q → %q changed the proof, but the Builder sets or drops it", tc.old, tc.new)
		}
	}

	// Two writings of the same thing prove alike: a text with CRLF, a lone
	// CR or LF line breaks, and what is empty once its spaces are gone (an
	// item, a list, an object, a member) against what is not there.
	const guide = "guide:\n  overview: Reads the issues.\n  prepare: [a token]\n"
	for _, tc := range []struct{ name, a, b string }{
		{"CRLF and LF in a text",
			strings.Replace(base, "summary: Summarizes the week's closed issues", `summary: "One.\r\nTwo."`, 1),
			strings.Replace(base, "summary: Summarizes the week's closed issues", `summary: "One.\nTwo."`, 1)},
		{"a lone CR and LF in a text",
			strings.Replace(base, "summary: Summarizes the week's closed issues", `summary: "One.\rTwo."`, 1),
			strings.Replace(base, "summary: Summarizes the week's closed issues", `summary: "One.\nTwo."`, 1)},
		{"spaces at the ends of a text",
			strings.Replace(base, "summary: Summarizes the week's closed issues", `summary: "  One.\nTwo. \n"`, 1),
			strings.Replace(base, "summary: Summarizes the week's closed issues", `summary: "One.\nTwo."`, 1)},
		{"a list holding only a blank item",
			strings.Replace(base, guide, "guide:\n  overview: Reads the issues.\n  prepare: [\"  \"]\n", 1),
			strings.Replace(base, guide, "guide:\n  overview: Reads the issues.\n", 1)},
		{"an object holding only blanks",
			strings.Replace(base, guide, "guide:\n  overview: \"  \"\n  prepare: [\"  \"]\n", 1),
			strings.Replace(base, guide, "", 1)},
		{"a blank member of an object",
			strings.Replace(base, guide, "guide:\n  overview: \"  \"\n  prepare: [a token]\n", 1),
			strings.Replace(base, guide, "guide:\n  prepare: [a token]\n", 1)},
	} {
		if tc.a == base || tc.b == base {
			t.Fatalf("%s: the edit did not apply", tc.name)
		}
		if proofOf(t, tc.a, text) != proofOf(t, tc.b, text) {
			t.Errorf("%s: the two writings do not prove alike", tc.name)
		}
	}
	if proofOf(t, strings.Replace(base, "summary: Summarizes the week's closed issues", `summary: "One.\nTwo."`, 1), text) ==
		proofOf(t, strings.Replace(base, "summary: Summarizes the week's closed issues", `summary: "One. Two."`, 1), text) {
		t.Error("a line break inside a text is part of what it says")
	}

	// Each digest is "sha256:" and 64 hex digits, and the proof that crosses
	// from the sandbox host to the registry carries exactly the two keys.
	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	for name, d := range map[string]string{"manifest": want.Manifest, "instruction": want.Instruction} {
		if !digest.MatchString(d) {
			t.Errorf("the %s digest is %q", name, d)
		}
	}
	wire, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]string
	if err := json.Unmarshal(wire, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys["manifest"] != want.Manifest || keys["instruction"] != want.Instruction {
		t.Errorf("the proof marshals as %s, want the keys manifest and instruction", wire)
	}
}

// TestTheInstructionTextIsReadWithItsLineBreaksAsLF: a browser's form post
// sends CRLF, and the Builder adds a final newline where there is none.
func TestTheInstructionTextIsReadWithItsLineBreaksAsLF(t *testing.T) {
	want := proofOf(t, base, "One.\nTwo.\n").Instruction
	for _, text := range []string{"One.\r\nTwo.\r\n", "One.\nTwo.", "One.\rTwo.\r", "One.\r\nTwo.\n\n\n"} {
		if got := proofOf(t, base, text).Instruction; got != want {
			t.Errorf("%q does not prove as %q", text, "One.\nTwo.\n")
		}
	}
	for _, text := range []string{"One.\nTwo. \n", " One.\nTwo.\n", "One.\n\nTwo.\n", "One.\tTwo.\n"} {
		if got := proofOf(t, base, text).Instruction; got == want {
			t.Errorf("%q proves as %q, but it is a different text", text, "One.\nTwo.\n")
		}
	}

	// The text that is proved: LF line breaks, exactly one final newline,
	// and nothing at all for a text with no characters but line breaks.
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"\n\n", ""},
		{"\r\n\r\n", ""},
		{"\r", ""},
		{"One.", "One.\n"},
		{"One.\r\nTwo.\r", "One.\nTwo.\n"},
		{"One.\n\n\n", "One.\n"},
		{"One.\n \n", "One.\n \n"},
		{" One. \n", " One. \n"},
		{"\nOne.\n", "\nOne.\n"},
	} {
		if got := string(NormalizeText([]byte(tc.in))); got != tc.want {
			t.Errorf("NormalizeText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestAPackageTheProofCannotReadIsNoProof: no manifest, a manifest that does
// not parse, no instruction entrypoint, one outside the package, a missing
// or linked instruction file: each is ErrNoProof, never a proof of nothing.
func TestAPackageTheProofCannotReadIsNoProof(t *testing.T) {
	write := func(t *testing.T, files map[string]string) string {
		dir := t.TempDir()
		for p, c := range files {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	for name, files := range map[string]map[string]string{
		"no manifest":         {"AGENT.md": "x\n"},
		"a broken manifest":   {"agent.yaml": "name: [", "AGENT.md": "x\n"},
		"no entrypoint":       {"agent.yaml": strings.Replace(base, "  instruction: AGENT.md\n", "", 1), "AGENT.md": "x\n"},
		"outside the package": {"agent.yaml": strings.Replace(base, "instruction: AGENT.md", "instruction: ../AGENT.md", 1)},
		"no instruction file": {"agent.yaml": base},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := OfDir(write(t, files)); !errors.Is(err, ErrNoProof) {
				t.Fatalf("got %v, want ErrNoProof", err)
			}
		})
	}
	// The instruction path must name a file inside the package, and the
	// refusal says so: a file that exists where the path points outside, an
	// absolute path (read under the package root it would be found), the
	// package root itself and its parent are each "no instruction file".
	for _, tc := range []struct{ name, path string }{
		{"a file one level up", "../AGENT.md"},
		{"a file reached by climbing out of a directory", "docs/../../AGENT.md"},
		{"an absolute path", "/AGENT.md"},
		{"the package root", "."},
		{"the package root with a slash", "./"},
		{"the parent directory", ".."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outer := t.TempDir()
			pkg := filepath.Join(outer, "pkg")
			for p, c := range map[string]string{
				"AGENT.md":       "outside\n",
				"pkg/AGENT.md":   "inside\n",
				"pkg/agent.yaml": strings.Replace(base, "instruction: AGENT.md", "instruction: "+tc.path, 1),
			} {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(outer, p)), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(outer, p), []byte(c), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, rel, err := OfDir(pkg)
			if !errors.Is(err, ErrNoProof) || !strings.Contains(err.Error(), "no instruction file") || rel != "" {
				t.Fatalf("got %q, %v; want ErrNoProof, no instruction file", rel, err)
			}
		})
	}
	t.Run("a directory for the instruction file", func(t *testing.T) {
		dir := write(t, map[string]string{"agent.yaml": strings.Replace(base, "instruction: AGENT.md", "instruction: docs", 1), "docs/x.md": "x\n"})
		if _, _, err := OfDir(dir); !errors.Is(err, ErrNoProof) || !strings.Contains(err.Error(), "not a file the proof reads") {
			t.Fatalf("got %v, want ErrNoProof, not a file the proof reads", err)
		}
	})
	t.Run("a linked manifest", func(t *testing.T) {
		dir := write(t, map[string]string{"real.yaml": base, "AGENT.md": "x\n"})
		if err := os.Symlink(filepath.Join(dir, "real.yaml"), filepath.Join(dir, ManifestFile)); err != nil {
			t.Skip(err)
		}
		if _, _, err := OfDir(dir); !errors.Is(err, ErrNoProof) {
			t.Fatalf("got %v, want ErrNoProof", err)
		}
	})
	t.Run("an unreadable instruction file", func(t *testing.T) {
		dir := write(t, map[string]string{"agent.yaml": base, "AGENT.md": "x\n"})
		if err := os.Chmod(filepath.Join(dir, "AGENT.md"), 0); err != nil {
			t.Skip(err)
		}
		if f, err := os.Open(filepath.Join(dir, "AGENT.md")); err == nil {
			_ = f.Close()
			t.Skip("the file is readable whatever its mode (running as root)")
		}
		if _, _, err := OfDir(dir); !errors.Is(err, ErrNoProof) {
			t.Fatalf("got %v, want ErrNoProof", err)
		}
	})
	// A file of at most 4 MiB is read, one byte more is not a file a draft
	// wrote: the limit holds for the instruction file and for the manifest.
	t.Run("the size a file may have", func(t *testing.T) {
		const limit = 4 << 20
		pad := func(n int) string { return strings.Repeat("a", n) }
		for _, tc := range []struct {
			name  string
			files map[string]string
			ok    bool
		}{
			{"an instruction file of 4 MiB", map[string]string{"agent.yaml": base, "AGENT.md": pad(limit)}, true},
			{"an instruction file of 4 MiB and a byte", map[string]string{"agent.yaml": base, "AGENT.md": pad(limit + 1)}, false},
			{"a manifest of 4 MiB", map[string]string{"agent.yaml": base + "#" + pad(limit-len(base)-1), "AGENT.md": "x\n"}, true},
			{"a manifest of 4 MiB and a byte", map[string]string{"agent.yaml": base + "#" + pad(limit-len(base)), "AGENT.md": "x\n"}, false},
		} {
			_, _, err := OfDir(write(t, tc.files))
			switch {
			case tc.ok && err != nil:
				t.Errorf("%s: %v", tc.name, err)
			case !tc.ok && (!errors.Is(err, ErrNoProof) || !strings.Contains(err.Error(), "not a file the proof reads")):
				t.Errorf("%s: got %v, want ErrNoProof, not a file the proof reads", tc.name, err)
			}
		}
	})
	// The path OfDir names is the instruction file's, cleaned and relative,
	// and the proof of a directory is the proof of the two files it holds.
	t.Run("the proof of a directory is the proof of its files", func(t *testing.T) {
		const text = "Summarize.\r\nThe week.\r\n"
		dir := write(t, map[string]string{
			"agent.yaml":    strings.Replace(base, "instruction: AGENT.md", "instruction: ./docs//AGENT.md", 1),
			"docs/AGENT.md": text,
		})
		got, rel, err := OfDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if rel != "docs/AGENT.md" {
			t.Errorf("the instruction file is %q, want docs/AGENT.md", rel)
		}
		if want := proofOf(t, base, text); got != want {
			t.Errorf("OfDir = %+v, Of = %+v", got, want)
		}
	})
	t.Run("a manifest that does not parse", func(t *testing.T) {
		if _, err := Of([]byte("name: ["), []byte("x\n")); !errors.Is(err, ErrNoProof) {
			t.Fatalf("got %v, want ErrNoProof", err)
		}
	})
	t.Run("a linked instruction file", func(t *testing.T) {
		dir := write(t, map[string]string{"agent.yaml": base, "real.md": "x\n"})
		if err := os.Symlink(filepath.Join(dir, "real.md"), filepath.Join(dir, "AGENT.md")); err != nil {
			t.Skip(err)
		}
		if _, _, err := OfDir(dir); !errors.Is(err, ErrNoProof) {
			t.Fatalf("got %v, want ErrNoProof", err)
		}
	})
}
