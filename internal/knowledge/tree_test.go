package knowledge

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/scan"
)

// digestFixture is agentry-cli's (pkg/knowledge/pack_test.go), and its
// digest is the literal that CLI pins, computed by a POSIX ustar encoder
// written by hand from the field table TreeDigest documents: the core and
// the CLI agree on a pack's digest because both agree with it.
var digestFixture = []scan.PackFile{
	{Path: "wiki/index.md", Content: []byte("# Index\n")},
	{Path: "wiki/log.md", Content: []byte("# Log\n")},
	{Path: "wiki/topics/a-page.md", Content: []byte("---\ntitle: A page\n---\nbody\n")},
	{Path: "sources/doc.txt", Content: []byte("the document\n")},
}

const digestFixtureSHA = "sha256:88a677666a5288a1222fc455a730b580215be6b4f213d7cd0def6468a24ef951"

func treeBytes(t *testing.T, files []scan.PackFile) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := WriteTree(&b, files); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestReadTreeIsTheCLIsDigest(t *testing.T) {
	tree, err := ReadTree(bytes.NewReader(treeBytes(t, digestFixture)), digestFixtureSHA)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Digest != digestFixtureSHA || tree.Bytes != 54 || tree.Pages != 1 || len(tree.Files) != 4 {
		t.Fatalf("tree = digest %s, %d bytes, %d pages, %d files", tree.Digest, tree.Bytes, tree.Pages, len(tree.Files))
	}
	if tree.Files[0].Path != "sources/doc.txt" || string(tree.Files[0].Content) != "the document\n" {
		t.Fatalf("first file = %+v", tree.Files[0])
	}
}

// rawTar writes headers as given, for the trees a canonical writer cannot.
func rawTar(t *testing.T, entries ...tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range entries {
		body := strings.Repeat("x", int(h.Size))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// digestOf is the plain hash of a tree's bytes: the refusals below are
// for a tree whose digest is right and whose form is not.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestReadTreeRefuses(t *testing.T) {
	reg := func(name string, size int64) tar.Header {
		return tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: size, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
	}
	good := treeBytes(t, digestFixture)
	tests := []struct {
		name   string
		tree   []byte
		digest string
		is     error
	}{
		{name: "another digest", tree: good, digest: "sha256:" + strings.Repeat("0", 64), is: ErrDigest},
		{name: "a byte changed", tree: bytes.Replace(bytes.Clone(good), []byte("the document"), []byte("the documenT"), 1), digest: digestFixtureSHA, is: ErrDigest},
		{name: "a symlink", tree: rawTar(t, tar.Header{Typeflag: tar.TypeSymlink, Name: "wiki/x.md", Linkname: "/etc/passwd", ModTime: time.Unix(0, 0), Format: tar.FormatPAX})},
		{name: "a directory entry", tree: rawTar(t, tar.Header{Typeflag: tar.TypeDir, Name: "wiki/", Mode: 0o755, ModTime: time.Unix(0, 0), Format: tar.FormatPAX})},
		{name: "a path that climbs", tree: rawTar(t, reg("wiki/../../etc/cron.d/x", 1))},
		{name: "outside the tree", tree: rawTar(t, reg("manifest.json", 1))},
		{name: "a backslash", tree: rawTar(t, reg(`wiki\..\x.md`, 1))},
		{name: "a name twice", tree: rawTar(t, reg("wiki/a.md", 1), reg("wiki/a.md", 1))},
		{name: "out of order", tree: rawTar(t, reg("wiki/b.md", 1), reg("wiki/a.md", 1))},
		{name: "not canonical: a mode", tree: rawTar(t, tar.Header{Typeflag: tar.TypeReg, Name: "wiki/a.md", Mode: 0o755, Size: 1, ModTime: time.Unix(0, 0), Format: tar.FormatPAX})},
		{name: "not a tar", tree: []byte("PK\x03\x04 a zip, not a tree")},
		{name: "past the cap", tree: rawTar(t, reg("sources/a.txt", MaxBytes), reg("sources/b.txt", 1)), is: ErrTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			digest, want := tc.digest, tc.is
			if digest == "" {
				digest = digestOf(tc.tree)
			}
			if want == nil {
				want = ErrTree
			}
			if _, err := ReadTree(bytes.NewReader(tc.tree), digest); !errors.Is(err, want) {
				t.Fatalf("err = %v, want %v", err, want)
			}
		})
	}
}
