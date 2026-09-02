package scan

import (
	"encoding/json"
	"fmt"
	"github.com/blaktron/agentry/pkg/manifest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/blaktron/agentry/pkg/archive"
	"github.com/blaktron/agentry/pkg/rules"
)

// S1 — Inventory & hygiene (§8.3). Unpacks were done by the orchestrator;
// S1 builds the file inventory (content-sniffed types), flags binaries and
// executables (blocked for all kinds in v1), nested archives, and non-UTF-8
// text. It populates Input.Files for the downstream stages.
type S1Inventory struct{}

func (S1Inventory) ID() string { return "S1" }

// Content classification (magic tables, text heuristic, image extensions)
// lives in pkg/archive so the CLI's `agentry validate` shares it (D-12).

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
		case archive.IsExecutable(data):
			findings = append(findings, Finding{
				Scanner: "S1/binary-executable", Severity: SevCritical, Confidence: ConfHigh,
				Title: "Executable binary in package", FilePath: rel,
				Detail:   map[string]any{"reason": "executables and shared libraries are blocked for all kinds in v1"},
				Taxonomy: []string{"ASI05"},
			})
		case archive.IsArchiveData(data):
			findings = append(findings, Finding{
				Scanner: "S1/nested-archive", Severity: SevCritical, Confidence: ConfHigh,
				Title: "Nested archive in package", FilePath: rel,
				Detail:   map[string]any{"reason": "nested archives are not allowed (unpack depth > 1)"},
				Taxonomy: []string{"ASI05"},
			})
		case archive.IsImagePath(rel):
			entry.IsImage = true
		case archive.LooksText(head):
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
				// DEV-036 closure: bytes past the cap are NOT read by
				// S3/S4/S5, which without a finding was a silent evasion
				// window — a payload appended after byte 1,048,576 of a
				// large text file reached publication with no detector and
				// no reviewer ever seeing it, and the report did not say
				// content was skipped. Medium severity routes the version
				// to human review, where the file viewer shows the whole
				// file. (inventoryDir below truncates the S9 BASELINE the
				// same way without a finding, deliberately: that archive
				// already passed its own scan as the previous release.)
				entry.Content = data[:textScanCap]
				findings = append(findings, Finding{
					Scanner: "S1/text-scan-truncated", Severity: SevMedium, Confidence: ConfHigh,
					Title:    "Text file exceeds the scan cap — content past 1 MiB was not scanned",
					FilePath: rel,
					Detail:   map[string]any{"fileBytes": len(data), "scannedBytes": textScanCap},
				})
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
	findings = append(findings, s1Frontmatter(in)...)
	return StageResult{Scanner: "S1", Findings: findings}
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
		case archive.IsImagePath(rel):
			entry.IsImage = true
		case archive.LooksText(head):
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

// s1Frontmatter is the scan-side half of agentry#47 (DEV-044): the skill
// entrypoint's YAML frontmatter is what the installed skill shows the
// consuming runtime, so a `name`/`description` that contradicts the signed
// manifest is a hygiene finding on the report. V9 rejects a contradicting
// name at submission; this catches every path (rescans, uploads that
// predate V9) and records the description divergence for the reviewer.
func s1Frontmatter(in *Input) []Finding {
	var m struct {
		Name        string `json:"name"`
		Summary     string `json:"summary"`
		Entrypoints struct {
			Skill string `json:"skill"`
		} `json:"entrypoints"`
	}
	if err := json.Unmarshal(in.ManifestJSON, &m); err != nil || m.Entrypoints.Skill == "" {
		return nil
	}
	var file *FileEntry
	for i := range in.Files {
		if in.Files[i].Path == m.Entrypoints.Skill {
			file = &in.Files[i]
			break
		}
	}
	if file == nil || !file.IsText || file.Content == nil {
		return nil
	}
	fm, ok, perr := manifest.ParseFrontmatter(file.Content)
	if !ok || perr != nil {
		return nil // V9 reports a malformed block; nothing to compare here
	}
	var out []Finding
	if fm.Name != "" && fm.Name != m.Name {
		out = append(out, Finding{
			Scanner: "S1/frontmatter-name-mismatch", Severity: SevMedium, Confidence: ConfHigh,
			Title:    "Skill frontmatter name contradicts the manifest",
			FilePath: file.Path, LineStart: 1, LineEnd: 1,
			Detail:   map[string]any{"frontmatter": fm.Name, "manifest": m.Name},
			Taxonomy: []string{"LLM09"},
		})
	}
	if fm.Description != "" && manifest.NormalizeProse(fm.Description) != manifest.NormalizeProse(m.Summary) {
		out = append(out, Finding{
			Scanner: "S1/frontmatter-description-differs", Severity: SevLow, Confidence: ConfHigh,
			Title:    "Skill frontmatter description differs from the manifest summary",
			FilePath: file.Path, LineStart: 1, LineEnd: 1,
			Excerpt:  fm.Description,
			Detail:   map[string]any{"summary": m.Summary, "reason": "the installed skill shows the frontmatter; the registry shows the summary (DEV-044)"},
			Taxonomy: []string{"LLM09"},
		})
	}
	return out
}
