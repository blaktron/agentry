// Package draftproof is the proof that a published version is the one a
// hosted draft wrote.
//
// A revision is published through the Builder's form, not as the draft's
// package/: the Builder sets the QuickAgent's own name, namespace, version
// and licence, writes its own README and LICENSE, drops the fields it
// cannot hold, renders agent.yaml with its own writer, and a browser posts
// the instruction file with CRLF line breaks. So no file of the draft is a
// file of the version byte for byte, and the proof is two digests of what
// the Builder keeps:
//
//   - the manifest, parsed and canonicalised, without what the Builder sets
//     or cannot hold (Manifest);
//   - the instruction file's text with its line breaks as LF and exactly one
//     final newline (Instruction).
//
// The sandbox host computes the proof over the draft's package/ before it
// seals the output; the registry computes it over the submitted files.
// One function on both sides, and only digests cross: the registry never
// reads a draft's body. README.md, LICENSE and every other file are
// outside the proof and are scanned as for any version.
package draftproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blaktron/agentry/pkg/manifest"
)

// ManifestFile is the manifest's path in a package.
const ManifestFile = "agent.yaml"

// maxFile bounds what OfDir reads of either file: a package's own limits
// are smaller, so a larger file is not one a draft wrote.
const maxFile = 4 << 20

// Proof is the two digests, each "sha256:" and 64 hex digits.
type Proof struct {
	Manifest    string `json:"manifest"`
	Instruction string `json:"instruction"`
}

// ErrNoProof is a package the proof cannot read: no manifest, a manifest
// that does not parse, or no instruction file.
var ErrNoProof = errors.New("draftproof: no proof for this package")

// Of computes the proof of a manifest's bytes and its instruction file's.
func Of(manifestYAML, instruction []byte) (Proof, error) {
	m, err := manifest.Parse(manifestYAML)
	if err != nil {
		return Proof{}, fmt.Errorf("%w: %v", ErrNoProof, err)
	}
	canon, err := Canonical(m)
	if err != nil {
		return Proof{}, err
	}
	return Proof{Manifest: digest(canon), Instruction: digest(NormalizeText(instruction))}, nil
}

// OfDir computes the proof of the package rooted at dir, and names the
// instruction file it read (slash-separated, relative to dir).
func OfDir(dir string) (Proof, string, error) {
	raw, err := readFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return Proof{}, "", err
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		return Proof{}, "", fmt.Errorf("%w: %v", ErrNoProof, err)
	}
	rel := path.Clean(strings.TrimPrefix(m.Entrypoints.Instruction, "./"))
	if m.Entrypoints.Instruction == "" || rel == "." || path.IsAbs(rel) || strings.HasPrefix(rel, "../") || rel == ".." {
		return Proof{}, "", fmt.Errorf("%w: no instruction file", ErrNoProof)
	}
	text, err := readFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return Proof{}, "", err
	}
	canon, err := Canonical(m)
	if err != nil {
		return Proof{}, "", err
	}
	return Proof{Manifest: digest(canon), Instruction: digest(NormalizeText(text))}, rel, nil
}

// Canonical is the manifest as the proof reads it: what the Builder keeps,
// in the manifest's canonical JSON (sorted keys, empty values pruned),
// with the differences that are only how the Builder writes a value taken
// out.
//
// Left out, because the Builder sets them: schemaVersion, kind, name,
// namespace, version, license, the instruction entrypoint's path (the
// instruction file is proved by its text) and publish. Left out, because
// the Builder cannot hold them and drops them without a word: homepage,
// authors, the skill and MCP entrypoints, interactive.idleTimeoutSeconds,
// knowledge.ships, runtime and dependencies.
//
// Read as the same, because the Builder only writes them differently: a
// capability declared none and one not declared; egress that lists "*" and
// egress "*"; every text with CRLF line breaks and with the spaces at its
// ends; an empty text or list item and none; an intake question of type
// text and one with no type; modes and data categories in any order or
// repeated. Anything else the Builder changes (a multi-word choice
// hyphenated, a value with a space dropped) changes what the version
// declares, and the proof does not hold.
func Canonical(m *manifest.Manifest) ([]byte, error) {
	c := *m
	c.SchemaVersion, c.Kind, c.Name, c.Namespace, c.Version, c.License = "", "", "", "", "", ""
	c.Homepage, c.Authors = "", nil
	c.Entrypoints = manifest.Entrypoints{}
	c.Runtime = manifest.Runtime{}
	c.Dependencies = manifest.Dependencies{}
	c.Publish = manifest.Publish{}
	if m.Interactive != nil {
		h := *m.Interactive
		h.IdleTimeoutSeconds = 0
		c.Interactive = &h
	}
	if m.Knowledge != nil {
		k := *m.Knowledge
		k.Ships = nil
		c.Knowledge = &k
	}
	caps := c.Capabilities
	if caps.Network.Egress.None || len(caps.Network.Egress.Hosts) == 0 {
		caps.Network.Egress = manifest.Egress{}
	} else if slices.Contains(caps.Network.Egress.Hosts, "*") {
		caps.Network.Egress = manifest.Egress{Hosts: []string{"*"}}
	}
	if caps.Filesystem.Read.Mode == manifest.FSModeNone {
		caps.Filesystem.Read = manifest.FSAccess{}
	}
	if caps.Filesystem.Write.Mode == manifest.FSModeNone {
		caps.Filesystem.Write = manifest.FSAccess{}
	}
	if caps.Exec.None {
		caps.Exec = manifest.ExecCapability{}
	}
	caps.DataAccess = setOf(caps.DataAccess)
	c.Capabilities = caps
	c.Modes = setOf(c.Modes)
	if len(m.Intake) > 0 {
		c.Intake = make([]manifest.IntakeQuestion, len(m.Intake))
		for i, q := range m.Intake {
			if q.Type == manifest.IntakeText {
				q.Type = ""
			}
			c.Intake[i] = q
		}
	}
	raw, err := manifest.CanonicalJSON(&c)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("draftproof: re-decoding: %w", err)
	}
	return json.Marshal(tidy(v))
}

// setOf is a list read as a set: sorted, each value once.
func setOf[T ~string](xs []T) []T {
	if len(xs) == 0 {
		return nil
	}
	out := slices.Clone(xs)
	slices.Sort(out)
	return slices.Compact(out)
}

// tidy reads every text with LF line breaks and without the spaces at its
// ends, and drops what is then empty: a text, a list item, a list, an
// object. Maps marshal with their keys sorted.
func tidy(v any) any {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(t, "\r\n", "\n"), "\r", "\n"))
		if s == "" {
			return nil
		}
		return s
	case []any:
		out := make([]any, 0, len(t))
		for _, x := range t {
			if y := tidy(x); y != nil {
				out = append(out, y)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if y := tidy(x); y != nil {
				out[k] = y
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return v
	}
}

// NormalizeText is an instruction file's text as the proof reads it: CRLF
// and lone CR line breaks as LF, and the text ending in exactly one
// newline (none for an empty text).
func NormalizeText(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	b = bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
	b = bytes.TrimRight(b, "\n")
	if len(b) == 0 {
		return b
	}
	return append(b, '\n')
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// readFile reads a regular file of at most maxFile bytes; a link, a
// directory or a larger file is no proof.
func readFile(p string) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoProof, err)
	}
	if !st.Mode().IsRegular() || st.Size() > maxFile {
		return nil, fmt.Errorf("%w: %s is not a file the proof reads", ErrNoProof, filepath.Base(p))
	}
	b, err := os.ReadFile(p) //nolint:gosec // a package extracted by the hardened extractor
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoProof, err)
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%w: %s is not a file the proof reads", ErrNoProof, filepath.Base(p))
	}
	return b, nil
}
