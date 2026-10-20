package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/blaktron/agentry/pkg/archive"
)

// blobFake serves one archive from memory.
type blobFake struct {
	data []byte
	err  error
}

func (b blobFake) Get(context.Context, string) (io.ReadCloser, error) {
	if b.err != nil {
		return nil, b.err
	}
	return io.NopCloser(bytes.NewReader(b.data)), nil
}

func archiveWith(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var headers []tar.Header
	var bodies [][]byte
	for name, body := range files {
		headers = append(headers, tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644})
		bodies = append(bodies, []byte(body))
	}
	return tarZst(t, headers, bodies)
}

func TestExtractREADMEFindsTheRootReadme(t *testing.T) {
	blob := blobFake{data: archiveWith(t, map[string]string{
		"agent.yaml": "modes: [autonomous]\n",
		"README.md":  "# Widget\n\nSummarizes invoices.\n",
	})}
	got, err := ExtractREADME(t.Context(), blob, "releases/aa/x.tar.zst", nil)
	if err != nil {
		t.Fatalf("ExtractREADME: %v", err)
	}
	if !strings.Contains(string(got), "Summarizes invoices") {
		t.Errorf("README body = %q", got)
	}
}

func TestExtractREADMETriesAlternateNames(t *testing.T) {
	for _, name := range []string{"readme.md", "Readme.md", "README", "README.markdown"} {
		t.Run(name, func(t *testing.T) {
			blob := blobFake{data: archiveWith(t, map[string]string{name: "content here"})}
			got, err := ExtractREADME(t.Context(), blob, "k", nil)
			if err != nil {
				t.Fatalf("ExtractREADME(%s): %v", name, err)
			}
			if string(got) != "content here" {
				t.Errorf("body = %q", got)
			}
		})
	}

	// When an archive has several, the first name in the list wins.
	blob := blobFake{data: archiveWith(t, map[string]string{
		"README.markdown": "markdown", "README": "bare", "Readme.md": "mixed", "readme.md": "lower", "README.md": "upper",
	})}
	if got, err := ExtractREADME(t.Context(), blob, "k", nil); err != nil || string(got) != "upper" {
		t.Errorf("got %q %v, want README.md's", got, err)
	}
	blob = blobFake{data: archiveWith(t, map[string]string{"README.markdown": "markdown", "README": "bare", "Readme.md": "mixed", "readme.md": "lower"})}
	if got, err := ExtractREADME(t.Context(), blob, "k", nil); err != nil || string(got) != "lower" {
		t.Errorf("got %q %v, want readme.md's", got, err)
	}
	blob = blobFake{data: archiveWith(t, map[string]string{"README.markdown": "markdown", "README": "bare", "Readme.md": "mixed"})}
	if got, err := ExtractREADME(t.Context(), blob, "k", nil); err != nil || string(got) != "mixed" {
		t.Errorf("got %q %v, want Readme.md's", got, err)
	}
	blob = blobFake{data: archiveWith(t, map[string]string{"README.markdown": "markdown", "README": "bare"})}
	if got, err := ExtractREADME(t.Context(), blob, "k", nil); err != nil || string(got) != "bare" {
		t.Errorf("got %q %v, want README's", got, err)
	}
}

// A README nested inside the tree documents a subdirectory, not the agent.
// Indexing it would let a vendored dependency's docs decide what the agent
// appears to be about in search.
func TestExtractREADMEIgnoresNestedReadmes(t *testing.T) {
	blob := blobFake{data: archiveWith(t, map[string]string{
		"agent.yaml":       "modes: [autonomous]\n",
		"vendor/README.md": "# Some Other Project\n",
	})}
	_, err := ExtractREADME(t.Context(), blob, "k", nil)
	if !errors.Is(err, ErrNoReadme) {
		t.Errorf("err = %v, want ErrNoReadme (a nested README is not the agent's)", err)
	}
}

func TestExtractREADMEReportsAbsence(t *testing.T) {
	blob := blobFake{data: archiveWith(t, map[string]string{"agent.yaml": "modes: [autonomous]\n"})}
	if _, err := ExtractREADME(t.Context(), blob, "k", nil); !errors.Is(err, ErrNoReadme) {
		t.Errorf("err = %v, want ErrNoReadme", err)
	}
}

func TestExtractREADMEHandlesAMissingStore(t *testing.T) {
	if _, err := ExtractREADME(t.Context(), nil, "k", nil); !errors.Is(err, ErrNoReadme) {
		t.Errorf("err = %v, want ErrNoReadme for a nil blob store", err)
	}
	blob := blobFake{err: errors.New("no such key")}
	if _, err := ExtractREADME(t.Context(), blob, "k", nil); err == nil {
		t.Error("a blob-store failure was reported as success")
	}
	// A store that fails is not an archive without a README.
	if _, err := ExtractREADME(t.Context(), blob, "k", nil); errors.Is(err, ErrNoReadme) || err.Error() != "no such key" {
		t.Errorf("err = %v, want the store's own error", err)
	}
}

// The README comes through the same extractor as the scans do, with its
// quotas and its ratio check, and a violation is that and not "no README".
func TestExtractREADMEInheritsTheExtractorsQuotas(t *testing.T) {
	// 11 MiB of one file is past what any single file of an archive may be.
	big := blobFake{data: archiveWith(t, map[string]string{"README.md": "# Widget\n", "data.txt": strings.Repeat("0", 11<<20)})}
	if _, err := ExtractREADME(t.Context(), big, "k", nil); !errors.Is(err, archive.ErrArchiveViolation) {
		t.Errorf("an oversized file: err = %v, want an archive violation", err)
	}
	// A small archive of a large expansion is refused when its size is known,
	// and read when it is not told.
	bomb := blobFake{data: archiveWith(t, map[string]string{"README.md": "# Widget\n", "data.txt": strings.Repeat("0", 4<<20)})}
	size := int64(len(bomb.data))
	if _, err := ExtractREADME(t.Context(), bomb, "k", &size); !errors.Is(err, archive.ErrArchiveViolation) {
		t.Errorf("a ratio over 200 with %d compressed bytes: err = %v, want an archive violation", size, err)
	}
	if got, err := ExtractREADME(t.Context(), bomb, "k", nil); err != nil || string(got) != "# Widget\n" {
		t.Errorf("without the size the ratio is not checked: %q %v", got, err)
	}
	ok := blobFake{data: archiveWith(t, map[string]string{"README.md": "# Widget\n"})}
	small := int64(len(ok.data))
	if got, err := ExtractREADME(t.Context(), ok, "k", &small); err != nil || string(got) != "# Widget\n" {
		t.Errorf("an ordinary archive of known size: %q %v", got, err)
	}
}

// to_tsvector runs in a BEFORE trigger on every agent write and errors past a
// 1 MB output, so an oversized README must be truncated here rather than
// turning a publish into a failed transaction.
func TestReadmeIndexTextIsBounded(t *testing.T) {
	huge := strings.Repeat("word ", MaxIndexedReadmeBytes)
	got := ReadmeIndexText([]byte(huge))
	if len(got) > MaxIndexedReadmeBytes {
		t.Errorf("len = %d, want <= %d", len(got), MaxIndexedReadmeBytes)
	}
	if !utf8.ValidString(got) {
		t.Error("truncation produced invalid UTF-8")
	}
	// The bound is 64 KiB of text, kept whole up to it.
	if MaxIndexedReadmeBytes != 64<<10 || len(got) != 64<<10 || got != huge[:64<<10] {
		t.Errorf("the bound is %d and %d bytes were kept", MaxIndexedReadmeBytes, len(got))
	}
	exact := strings.Repeat("a", 64<<10)
	if got := ReadmeIndexText([]byte(exact)); got != exact {
		t.Errorf("a README of exactly 64 KiB was cut to %d bytes", len(got))
	}
	if got := ReadmeIndexText([]byte(exact + "b")); got != exact {
		t.Errorf("a README of 64 KiB and a byte was kept to %d bytes", len(got))
	}
}

// Truncating mid-rune must drop the partial tail, not store a replacement
// character that would index as a token of its own.
func TestReadmeIndexTextTruncatesOnRuneBoundaries(t *testing.T) {
	// Fill to just past the cap with a 3-byte rune so the boundary splits one.
	body := strings.Repeat("é", MaxIndexedReadmeBytes)
	got := ReadmeIndexText([]byte(body))
	if !utf8.ValidString(got) {
		t.Fatalf("truncated text is not valid UTF-8 (len %d)", len(got))
	}
	if strings.Contains(got, "\ufffd") {
		t.Error("truncation left a replacement character in the index text")
	}
	// A three-byte letter is split by the bound (65536 is not a multiple of
	// 3): its partial tail goes, and the text before it stays.
	euros := strings.Repeat("\u20ac", MaxIndexedReadmeBytes)
	got = ReadmeIndexText([]byte(euros))
	if !utf8.ValidString(got) || strings.Contains(got, "\ufffd") || len(got) != 3*21845 || got != euros[:3*21845] {
		t.Fatalf("a bound inside a three-byte letter: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
}

// Postgres text columns reject NUL bytes; a README carrying one must not turn
// a publish into a database error.
func TestReadmeIndexTextStripsNulBytes(t *testing.T) {
	got := ReadmeIndexText([]byte("before\x00after"))
	if strings.ContainsRune(got, 0) {
		t.Errorf("NUL survived into the index text: %q", got)
	}
	if got != "beforeafter" {
		t.Errorf("got %q", got)
	}
}

func TestReadmeIndexTextRepairsInvalidUTF8(t *testing.T) {
	got := ReadmeIndexText([]byte{'o', 'k', 0xff, 0xfe})
	if !utf8.ValidString(got) {
		t.Errorf("invalid UTF-8 survived: %q", got)
	}
	if !strings.HasPrefix(got, "ok") {
		t.Errorf("valid prefix was lost: %q", got)
	}
	// Bytes that are not text are dropped, not replaced by a character that
	// would index as a token of its own.
	if got != "ok" {
		t.Errorf("got %q, want the bad bytes dropped", got)
	}
}

func TestReadmeIndexTextHandlesEmpty(t *testing.T) {
	if got := ReadmeIndexText(nil); got != "" {
		t.Errorf("nil README produced %q, want empty", got)
	}
}
