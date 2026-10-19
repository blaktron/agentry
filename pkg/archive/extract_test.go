package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// tarZst builds a tar.zst from name→content (raw entries, for hostile cases).
func tarZst(t *testing.T, entries []tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for i, h := range entries {
		hh := h
		if hh.Typeflag == tar.TypeReg && hh.Size == 0 {
			hh.Size = int64(len(bodies[i]))
		}
		_ = tw.WriteHeader(&hh)
		if hh.Typeflag == tar.TypeReg {
			_, _ = tw.Write(bodies[i])
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestExtractRejectsHostileArchives(t *testing.T) {
	lim := DefaultLimits()
	cases := []struct {
		name    string
		entries []tar.Header
		bodies  [][]byte
		says    string // the refusal's own words
	}{
		{"path traversal", []tar.Header{{Name: "../escape", Typeflag: tar.TypeReg}}, [][]byte{[]byte("x")}, `unsafe path "../escape"`},
		{"absolute path", []tar.Header{{Name: "/etc/passwd", Typeflag: tar.TypeReg}}, [][]byte{[]byte("x")}, `unsafe path "/etc/passwd"`},
		{"symlink", []tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}, [][]byte{nil}, `non-regular entry "link"`},
		{"hardlink", []tar.Header{{Name: "hl", Typeflag: tar.TypeLink, Linkname: "target"}}, [][]byte{nil}, `non-regular entry "hl"`},
		{"device node", []tar.Header{{Name: "dev", Typeflag: tar.TypeChar}}, [][]byte{nil}, `non-regular entry "dev"`},
		{"dotdot in middle", []tar.Header{{Name: "a/../../b", Typeflag: tar.TypeReg}}, [][]byte{[]byte("x")}, `unsafe path "a/../../b"`},
		// A second entry of the same name would overwrite the first one,
		// which the scanners may already have read.
		{"duplicate entry", []tar.Header{{Name: "a.txt", Typeflag: tar.TypeReg}, {Name: "a.txt", Typeflag: tar.TypeReg}}, [][]byte{[]byte("x"), []byte("y")}, `open "a.txt"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tarZst(t, tc.entries, tc.bodies)
			dst := t.TempDir()
			err := Extract(bytes.NewReader(data), dst, int64(len(data)), lim)
			if err == nil {
				t.Fatalf("%s: expected rejection", tc.name)
			}
			if !errors.Is(err, ErrArchiveViolation) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("%s: err = %v, want the archive violation saying %s", tc.name, err, tc.says)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "escape")); err == nil {
				t.Fatalf("%s: a file was written outside the destination", tc.name)
			}
		})
	}
}

func TestExtractEnforcesLimits(t *testing.T) {
	// Per-file cap.
	lim := ExtractLimits{MaxFileBytes: 10, MaxTotalBytes: 1000, MaxFiles: 100}
	data := tarZst(t, []tar.Header{{Name: "big.txt", Typeflag: tar.TypeReg}}, [][]byte{bytes.Repeat([]byte("A"), 100)})
	if err := Extract(bytes.NewReader(data), t.TempDir(), int64(len(data)), lim); err == nil {
		t.Fatal("per-file limit not enforced")
	}
	// File-count cap.
	lim = ExtractLimits{MaxFileBytes: 1000, MaxTotalBytes: 100000, MaxFiles: 2}
	var hdrs []tar.Header
	var bodies [][]byte
	for i := 0; i < 5; i++ {
		hdrs = append(hdrs, tar.Header{Name: filepath.Join("d", string(rune('a'+i))+".txt"), Typeflag: tar.TypeReg})
		bodies = append(bodies, []byte("x"))
	}
	data = tarZst(t, hdrs, bodies)
	if err := Extract(bytes.NewReader(data), t.TempDir(), int64(len(data)), lim); err == nil {
		t.Fatal("file-count limit not enforced")
	}

	// Each limit at its boundary: the limit itself is taken, one more is
	// refused with that limit's own words.
	files := func(sizes []int) ([]tar.Header, [][]byte) {
		var h []tar.Header
		var b [][]byte
		for i, size := range sizes {
			h = append(h, tar.Header{Name: fmt.Sprintf("f%02d.txt", i), Typeflag: tar.TypeReg})
			b = append(b, bytes.Repeat([]byte("A"), size))
		}
		return h, b
	}
	for _, tc := range []struct {
		name     string
		lim      ExtractLimits
		sizes    []int
		ratioOff bool   // pass compressedSize 0, which skips the ratio check
		says     string // "" when the archive is taken
	}{
		{"a file of the per-file limit", ExtractLimits{MaxFileBytes: 10, MaxTotalBytes: 1000, MaxFiles: 100}, []int{10}, true, ""},
		{"a file one byte over it", ExtractLimits{MaxFileBytes: 10, MaxTotalBytes: 1000, MaxFiles: 100}, []int{11}, true, "exceeds per-file limit"},
		{"the file-count limit", ExtractLimits{MaxFileBytes: 10, MaxTotalBytes: 1000, MaxFiles: 2}, []int{1, 1}, true, ""},
		{"one file over it", ExtractLimits{MaxFileBytes: 10, MaxTotalBytes: 1000, MaxFiles: 2}, []int{1, 1, 1}, true, "file count exceeds 2"},
		{"the total limit", ExtractLimits{MaxFileBytes: 20, MaxTotalBytes: 30, MaxFiles: 100}, []int{10, 10, 10}, true, ""},
		{"one byte over the total", ExtractLimits{MaxFileBytes: 20, MaxTotalBytes: 30, MaxFiles: 100}, []int{10, 10, 11}, true, "total size exceeds limit"},
		{"a compression bomb", ExtractLimits{MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxFiles: 10, MaxRatio: 10}, []int{100000}, false, "compression ratio exceeds 10"},
		{"the same bytes with the ratio check off", ExtractLimits{MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxFiles: 10}, []int{100000}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, b := files(tc.sizes)
			data := tarZst(t, h, b)
			compressed := int64(len(data))
			if tc.ratioOff {
				compressed = 0
			}
			err := Extract(bytes.NewReader(data), t.TempDir(), compressed, tc.lim)
			switch {
			case tc.says == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.says != "" && (!errors.Is(err, ErrArchiveViolation) || !strings.Contains(err.Error(), tc.says)):
				t.Fatalf("err = %v, want the archive violation saying %q", err, tc.says)
			}
		})
	}
}

func TestExtractAcceptsGoodArchive(t *testing.T) {
	data := tarZst(t,
		[]tar.Header{
			{Name: "dir", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "dir/file.txt", Typeflag: tar.TypeReg, Mode: 0o644},
		},
		[][]byte{nil, []byte("hello")})
	dst := t.TempDir()
	if err := Extract(bytes.NewReader(data), dst, int64(len(data)), DefaultLimits()); err != nil {
		t.Fatalf("good archive rejected: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "dir/file.txt"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("extracted content wrong: %q %v", got, err)
	}
}

// goodSeed builds one valid tar.zst for the fuzz corpus without needing a T.
func goodSeed() []byte {
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Typeflag: tar.TypeReg, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

// FuzzExtract crash-tests the extractor against arbitrary bytes:
// it must never panic and never escape the destination directory.
func FuzzExtract(f *testing.F) {
	f.Add(goodSeed())
	f.Add([]byte("not an archive at all"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		dst := t.TempDir()
		_ = Extract(bytes.NewReader(data), dst, int64(len(data)), DefaultLimits())
	})
}
