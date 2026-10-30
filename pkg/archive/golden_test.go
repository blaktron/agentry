package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blaktron/agentry/pkg/manifest"
)

// goldenArchiveDigest is the digest BuildArchive produces for the tree
// goldenFixture writes. Every release's digest is what its signature, its scan
// and every install bind, and the registry accepts an upload only when the
// digest the client computed equals its own, so the archive bytes are part of
// the product's contract. Regenerate this value only as part of a deliberate
// move of the archive compressor (see "Moving the archive compressor" in
// CONTRIBUTING.md), never to make a test pass.
const goldenArchiveDigest = "sha256:38fcfd1d5d5a85cf54333c5116a7b5419b5fb95538ddd74b90325cd31f520734"

// goldenFixture writes the fixed tree the golden digest is taken over: a
// manifest, a prose file, a nested prompt and an executable script, with
// contents long enough for the compressor to emit matches and a literal block.
func goldenFixture(t *testing.T) (string, []manifest.FileInfo) {
	t.Helper()
	dir := t.TempDir()
	mtime := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	repeated := goldenProse()
	files := []struct {
		path string
		body []byte
		mode os.FileMode
	}{
		{"agent.yaml", []byte("schemaVersion: \"1\"\nname: golden\n"), 0o644},
		{"README.md", []byte("# Golden fixture\n\nThis tree pins the archive bytes.\n"), 0o600},
		{"prompts/main.md", repeated, 0o644},
		{"scripts/run.sh", []byte("#!/bin/sh\nexec echo golden\n"), 0o700},
	}
	var include []manifest.FileInfo
	for _, f := range files {
		full := filepath.Join(dir, filepath.FromSlash(f.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, f.body, f.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(full, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		include = append(include, manifest.FileInfo{Path: f.path, Size: int64(len(f.body))})
	}
	return dir, include
}

// TestArchiveGoldenDigest pins the exact bytes of a small archive. It fails
// when anything that shapes them moves: the zstd encoder (a release of
// github.com/klauspost/compress), its options, or the tar normalisation.
func TestArchiveGoldenDigest(t *testing.T) {
	dir, include := goldenFixture(t)
	var buf bytes.Buffer
	info, err := BuildArchive(dir, include, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if info.Digest == goldenArchiveDigest {
		return
	}
	t.Fatalf(`the archive bytes changed.

  got    %s
  golden %s

The digest of a published release is what its signature, its scan and every
install bind, and the registry accepts an upload only when the digest the
client computed equals the registry's own build. A different compressor
release or tar layout therefore changes every digest and locks out every
client that still packs the old way.

If this is a deliberate move of the archive compressor, follow "Moving the
archive compressor" in CONTRIBUTING.md: move github.com/klauspost/compress in
the core, the CLI, the desktop and the enterprise build together, replace
goldenArchiveDigest with the "got" value above, give every built-in package a
new version, and release the core and the CLI together. Published archives are
never rebuilt.

If you did not mean to change the archive, revert the change to the compressor,
its options or the tar header normalisation in BuildArchive.`, info.Digest, goldenArchiveDigest)
}

// goldenProse returns about 150 KB of deterministic prose built from a fixed
// vocabulary of 400 made-up words: large and varied enough that the encoder's
// match finder and block coder make the same choices they make on a real
// prompt file, so a change to either shows in the digest. A small or highly
// repetitive input would encode identically under neighbouring compressor
// releases and prove nothing. It uses an xorshift generator, so nothing
// depends on a random source or on the Go release.
func goldenProse() []byte {
	x := uint32(2463534242)
	next := func() uint32 {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		return x
	}
	words := make([]string, 400)
	for i := range words {
		w := make([]byte, 2+next()%9)
		for j := range w {
			w[j] = 'a' + byte(next()%26)
		}
		words[i] = string(w)
	}
	var b bytes.Buffer
	for line := 0; line < 2000; line++ {
		for w := 0; w < 12; w++ {
			if w > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(words[next()%uint32(len(words))])
		}
		b.WriteString(".\n")
	}
	return b.Bytes()
}
