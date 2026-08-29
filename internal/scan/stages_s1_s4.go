package scan

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/PLACEHOLDER_ORG/agentry/pkg/rules"
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
		data, readErr := os.ReadFile(path) //nolint:gosec // read-only extracted archive
		if readErr != nil {
			// A file we cannot read is a file no scanner examines. Silently
			// treating it as empty means S3/S4/S5/S6 all pass over content
			// that will still ship — so it becomes a finding and the version
			// routes to a human instead (§7 fail toward review).
			findings = append(findings, Finding{
				Scanner: "S1/unreadable-file", Severity: SevMedium, Confidence: ConfHigh,
				Title: "File in package could not be read for scanning", FilePath: rel,
				Detail: map[string]any{
					"error":  readErr.Error(),
					"reason": "unscanned content cannot be cleared automatically",
				},
				Taxonomy: []string{"ASI05"},
			})
			inv = append(inv, entry)
			return nil
		}
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

// inventoryDir builds a text-file inventory for a directory without emitting
// findings. S9 uses it for the PREVIOUS published version's archive, where the
// question is only "what did the last release contain" — that archive already
// passed its own scan, and re-reporting its hygiene here would attribute the
// old version's findings to the new one.
func inventoryDir(dir string) []FileEntry {
	var inv []FileEntry
	if dir == "" {
		return nil
	}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil //nolint:nilerr // an unreadable baseline is "not comparable", not fatal
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		data, readErr := os.ReadFile(path) //nolint:gosec // read-only extracted archive
		if readErr != nil {
			return nil
		}
		entry := FileEntry{Path: rel, Size: info.Size()}
		head := data
		if len(head) > 512 {
			head = head[:512]
		}
		switch {
		case imageExt[strings.ToLower(filepath.Ext(rel))]:
			entry.IsImage = true
		case looksText(head):
			entry.IsText = true
			if int64(len(data)) <= textScanCap {
				entry.Content = data
			} else {
				entry.Content = data[:textScanCap]
			}
		}
		inv = append(inv, entry)
		return nil
	})
	sort.Slice(inv, func(i, j int) bool { return inv[i].Path < inv[j].Path })
	return inv
}

// readArchiveFile reads one inventoried file's bytes back off disk, refusing
// any path that would escape the extraction root. Stages that need raw bytes
// S1 did not retain (images) go through here rather than joining paths
// themselves.
func readArchiveFile(dir, rel string) ([]byte, error) {
	full := filepath.Join(dir, filepath.FromSlash(rel))
	clean := filepath.Clean(full)
	root := filepath.Clean(dir)
	if clean != root && !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return nil, fmt.Errorf("scan: path %q escapes archive root", rel)
	}
	return os.ReadFile(clean) //nolint:gosec // containment checked above
}

// S3S4Content wraps the pkg/rules S3 hidden-content detectors and S4
// signature engine (§8.3). It runs on the inventoried text files, and on the
// text recovered from image metadata.
type S3S4Content struct{}

func (S3S4Content) ID() string { return "S3S4" }

func (S3S4Content) Run(sc stageContext, in *Input) StageResult {
	rfs := rulesScan(sc, in)
	findings := make([]Finding, 0, len(rfs))
	for _, rf := range rfs {
		findings = append(findings, fromRules(rf))
	}
	findings = append(findings, imageMetadataFindings(sc, in)...)
	return StageResult{Scanner: "S3S4", Findings: findings}
}

// imageMetadataFindings runs the S3/S4 detectors over strings recovered from
// image metadata (§8.3 S3: "image alt-text/EXIF text extraction for
// instruction-bearing strings").
//
// Markdown alt-text needs no special handling — it is literal text in the .md
// file and the rules above already read it. EXIF and PNG text chunks do: they
// render as nothing, survive every diff view, and are the only place in an
// allowed file type where an instruction can hide from a human reviewer
// completely. A hit is therefore reported at medium severity at minimum
// regardless of what the underlying rule would score in prose.
func imageMetadataFindings(sc stageContext, in *Input) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, f := range in.Files {
		if !f.IsImage {
			continue
		}
		data, err := readArchiveFile(in.Dir, f.Path)
		if err != nil {
			continue
		}
		for _, ms := range extractImageText(data) {
			virt := f.Path + "#" + ms.Field
			hits := rules.ScanS3(virt, []byte(ms.Text))
			if sc.bundle != nil {
				hits = append(hits, sc.bundle.Scan(virt, []byte(ms.Text))...)
			}
			for _, h := range hits {
				// Hygiene-class hits (trailing whitespace, NFC deltas) say
				// nothing about intent; only instruction-bearing content is
				// worth surfacing from a place no human will look.
				if severityRank(Severity(h.Severity)) < severityRank(SevMedium) {
					continue
				}
				key := f.Path + "\x00" + ms.Field + "\x00" + h.RuleID
				if seen[key] {
					continue
				}
				seen[key] = true
				sev := Severity(h.Severity)
				if severityRank(sev) < severityRank(SevMedium) {
					sev = SevMedium
				}
				out = append(out, Finding{
					Scanner: "S3/image-metadata", Severity: sev, Confidence: ConfHigh,
					Title:    "Instruction-bearing text hidden in image metadata: " + ms.Field,
					FilePath: f.Path,
					Excerpt:  truncateStr(ms.Text, 200),
					Detail: map[string]any{
						"field": ms.Field, "ruleId": h.RuleID, "ruleTitle": h.Title,
						"reason": "image metadata is invisible in every renderer and every diff",
					},
					Taxonomy: []string{"LLM01", "ASI06"},
				})
			}
		}
	}
	return out
}
