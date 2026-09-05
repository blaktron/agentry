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
	if strings.Contains(got, "�") {
		t.Error("truncation left a replacement character in the index text")
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
}

func TestReadmeIndexTextHandlesEmpty(t *testing.T) {
	if got := ReadmeIndexText(nil); got != "" {
		t.Errorf("nil README produced %q, want empty", got)
	}
}
