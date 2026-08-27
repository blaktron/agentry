package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// S1 — Inventory & hygiene (§8.3). Unpacks were done by the orchestrator;
// S1 builds the file inventory (content-sniffed types), flags binaries and
// executables (blocked for all kinds in v1), nested archives, and non-UTF-8
// text. It populates Input.Files for the downstream stages.
type S1Inventory struct{}

func (S1Inventory) ID() string { return "S1" }

// imageExt and archiveExt drive content classification.
var imageExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".bmp": true, ".ico": true}
var archiveMagic = [][]byte{
	{0x50, 0x4b, 0x03, 0x04},       // zip
	{0x1f, 0x8b},                   // gzip
	{0x28, 0xb5, 0x2f, 0xfd},       // zstd
	{0x42, 0x5a, 0x68},             // bzip2
	{0xfd, 0x37, 0x7a, 0x58},       // xz
	{0x75, 0x73, 0x74, 0x61, 0x72}, // ustar (tar) — offset 257, handled below
}
var execMagic = [][]byte{
	{0x7f, 0x45, 0x4c, 0x46}, // ELF
	{0xcf, 0xfa, 0xed, 0xfe}, // Mach-O 64 LE
	{0xfe, 0xed, 0xfa, 0xcf}, // Mach-O 64 BE
	{0xca, 0xfe, 0xba, 0xbe}, // Mach-O universal / Java class
	{0x4d, 0x5a},             // PE/DOS (MZ)
}

func (S1Inventory) Run(sc stageContext, in *Input) StageResult {
	var findings []Finding
	var inv []FileEntry

	err := filepath.Walk(in.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(in.Dir, path)
		rel = filepath.ToSlash(rel)

		entry := FileEntry{Path: rel, Size: info.Size()}
		// Read a bounded head for sniffing; full content for text files.
		data, _ := os.ReadFile(path) //nolint:gosec // read-only extracted archive
		head := data
		if len(head) > 512 {
			head = head[:512]
		}

		switch {
		case hasAnyPrefix(data, execMagic):
			findings = append(findings, Finding{
				Scanner: "S1/binary-executable", Severity: SevCritical, Confidence: ConfHigh,
				Title: "Executable binary in package", FilePath: rel,
				Detail:   map[string]any{"reason": "executables and shared libraries are blocked for all kinds in v1"},
				Taxonomy: []string{"ASI05"},
			})
		case isArchive(data):
			findings = append(findings, Finding{
				Scanner: "S1/nested-archive", Severity: SevCritical, Confidence: ConfHigh,
				Title: "Nested archive in package", FilePath: rel,
				Detail:   map[string]any{"reason": "nested archives are not allowed (unpack depth > 1)"},
				Taxonomy: []string{"ASI05"},
			})
		case imageExt[strings.ToLower(filepath.Ext(rel))]:
			entry.IsImage = true
		case looksText(head):
			entry.IsText = true
			if !utf8.Valid(data) {
				findings = append(findings, Finding{
					Scanner: "S1/non-utf8", Severity: SevLow, Confidence: ConfMedium,
					Title: "Non-UTF-8 text file", FilePath: rel,
				})
			}
			if int64(len(data)) <= textScanCap {
				entry.Content = data
			} else {
				entry.Content = data[:textScanCap]
			}
		default:
			// Unknown binary blob (not exec, not archive, not image): allowed
			// but flagged for reviewer attention.
			findings = append(findings, Finding{
				Scanner: "S1/opaque-binary", Severity: SevInfo, Confidence: ConfLow,
				Title: "Opaque binary file", FilePath: rel,
			})
		}
		inv = append(inv, entry)
		return nil
	})
	if err != nil {
		return StageResult{Scanner: "S1", Err: err}
	}
	in.Files = inv
	return StageResult{Scanner: "S1", Findings: findings}
}

func hasAnyPrefix(data []byte, magics [][]byte) bool {
	for _, m := range magics {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

func isArchive(data []byte) bool {
	for _, m := range archiveMagic[:len(archiveMagic)-1] {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	// ustar magic lives at offset 257.
	if len(data) > 262 && bytes.Equal(data[257:262], []byte("ustar")) {
		return true
	}
	return false
}

// looksText reports whether head is plausibly text (no NUL, mostly printable).
func looksText(head []byte) bool {
	if len(head) == 0 {
		return true
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	nonPrint := 0
	for _, b := range head {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			nonPrint++
		}
	}
	return nonPrint*100/len(head) < 5
}

// S3S4Content wraps the pkg/rules S3 hidden-content detectors and S4
// signature engine (§8.3). It runs on the inventoried text files.
type S3S4Content struct{}

func (S3S4Content) ID() string { return "S3S4" }

func (S3S4Content) Run(sc stageContext, in *Input) StageResult {
	rfs := rulesScan(sc, in)
	findings := make([]Finding, 0, len(rfs))
	for _, rf := range rfs {
		findings = append(findings, fromRules(rf))
	}
	return StageResult{Scanner: "S3S4", Findings: findings}
}
