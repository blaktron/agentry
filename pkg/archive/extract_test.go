package archive

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
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
	}{
		{"path traversal", []tar.Header{{Name: "../escape", Typeflag: tar.TypeReg}}, [][]byte{[]byte("x")}},
		{"absolute path", []tar.Header{{Name: "/etc/passwd", Typeflag: tar.TypeReg}}, [][]byte{[]byte("x")}},
		{"symlink", []tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}, [][]byte{nil}},
		{"hardlink", []tar.Header{{Name: "hl", Typeflag: tar.TypeLink, Linkname: "target"}}, [][]byte{nil}},
		{"device node", []tar.Header{{Name: "dev", Typeflag: tar.TypeChar}}, [][]byte{nil}},
		{"dotdot in middle", []tar.Header{{Name: "a/../../b", Typeflag: tar.TypeReg}}, [][]byte{[]byte("x")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tarZst(t, tc.entries, tc.bodies)
			err := Extract(bytes.NewReader(data), t.TempDir(), int64(len(data)), lim)
			if err == nil {
				t.Fatalf("%s: expected rejection", tc.name)
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
