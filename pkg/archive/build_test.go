package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blaktron/agentry/pkg/manifest"
)

// TestArchiveReproducible pins D-15: identical trees produce byte-identical
// archives regardless of mtimes, walk order, or when they are built.
func TestArchiveReproducible(t *testing.T) {
	build := func(dir string) (ArchiveInfo, []byte) {
		files, err := WalkWorkspace(dir)
		if err != nil {
			t.Fatal(err)
		}
		include := manifest.ResolveInclude([]string{"agent.yaml", "README.md", "prompts/**"}, files)
		if len(include) != 3 {
			t.Fatalf("include set: %+v", include)
		}
		var buf bytes.Buffer
		info, err := BuildArchive(dir, include, &buf)
		if err != nil {
			t.Fatal(err)
		}
		return info, buf.Bytes()
	}

	mk := func(mtimeSkew time.Duration) string {
		dir := t.TempDir()
		for path, content := range map[string]string{
			"agent.yaml":       "schemaVersion: \"1\"\n",
			"README.md":        "# hello\n",
			"prompts/main.md":  "prompt body\n",
			"excluded/junk.md": "never shipped\n",
		} {
			full := filepath.Join(dir, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			mt := time.Now().Add(mtimeSkew)
			if err := os.Chtimes(full, mt, mt); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	infoA, bytesA := build(mk(0))
	infoB, bytesB := build(mk(-48 * time.Hour))
	if infoA.Digest != infoB.Digest {
		t.Fatalf("digests differ: %s vs %s", infoA.Digest, infoB.Digest)
	}
	if !bytes.Equal(bytesA, bytesB) {
		t.Fatal("archive bytes differ across builds")
	}
	if infoA.Size != int64(len(bytesA)) {
		t.Fatalf("size mismatch: %d vs %d", infoA.Size, len(bytesA))
	}

	// Round-trip through the hardened extractor.
	dst := t.TempDir()
	if err := Unpack(bytes.NewReader(bytesA), dst, 1<<20, 10<<20); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"agent.yaml", "README.md", "prompts/main.md"} {
		if _, err := os.Stat(filepath.Join(dst, want)); err != nil {
			t.Fatalf("extracted tree missing %s", want)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "excluded/junk.md")); err == nil {
		t.Fatal("allowlist filter failed: excluded file shipped")
	}
}
