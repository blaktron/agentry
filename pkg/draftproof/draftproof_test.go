package draftproof

import (
	"errors"
	"os"
	"path/filepath"
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
	} {
		same := strings.Replace(base, tc.old, tc.new, 1)
		if same == base {
			t.Fatalf("the edit %q did not apply", tc.old)
		}
		if p := proofOf(t, same, text); p.Manifest != want.Manifest {
			t.Errorf("%q → %q changed the proof, but the Builder sets or drops it", tc.old, tc.new)
		}
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
