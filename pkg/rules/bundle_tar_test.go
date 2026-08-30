package rules_test

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blaktron/agentry/pkg/rules"
	"github.com/blaktron/agentry/pkg/ruleset"
)

// tarWith builds a tar from alternating name/content arguments.
func tarWith(t *testing.T, nameContent ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i+1 < len(nameContent); i += 2 {
		name, content := nameContent[i], nameContent[i+1]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestBundleTarRoundTrip is the property the whole `--rules-update` trust
// story rests on: serialize a bundle, extract it, reload it, and the digest
// is the same. If this breaks, a digest a registry advertises stops being a
// digest a client can recompute, and pinning becomes theatre.
func TestBundleTarRoundTrip(t *testing.T) {
	orig, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}

	data, err := orig.Tar()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	names, err := rules.UntarBundle(data, func(name string, content []byte) error {
		return os.WriteFile(filepath.Join(dir, name), content, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 2 || names[0] != "bundle.yaml" {
		t.Fatalf("entries = %v, want bundle.yaml first plus rule files", names)
	}

	back, err := rules.LoadBundle(os.DirFS(dir), ".")
	if err != nil {
		t.Fatalf("reload extracted bundle: %v", err)
	}
	if back.Digest() != orig.Digest() {
		t.Fatalf("digest drifted across serialization: %s -> %s", orig.Digest(), back.Digest())
	}
	if back.Version() != orig.Version() {
		t.Fatalf("version drifted: %s -> %s", orig.Version(), back.Version())
	}
	if len(back.Rules()) != len(orig.Rules()) {
		t.Fatalf("rule count drifted: %d -> %d", len(orig.Rules()), len(back.Rules()))
	}
}

// TestBundleTarDeterministic: two serializations of one bundle are identical
// bytes, so the archive itself can be cached and compared.
func TestBundleTarDeterministic(t *testing.T) {
	b, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	first, err := b.Tar()
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Tar()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("Tar() is not byte-reproducible")
	}
}

// TestUntarBundleRejectsStructure: an archive from a registry is untrusted
// input. Anything with a path, a directory, or a non-YAML payload in it did
// not come from Tar() and must be refused rather than written out.
func TestUntarBundleRejectsStructure(t *testing.T) {
	cases := map[string][]byte{
		"path traversal": tarWith(t, "../escape.yaml", "rules: []"),
		"subdirectory":   tarWith(t, "nested/rules.yaml", "rules: []"),
		"non-yaml":       tarWith(t, "payload.sh", "#!/bin/sh\n"),
		"empty archive":  tarWith(t),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var written []string
			_, err := rules.UntarBundle(data, func(n string, _ []byte) error {
				written = append(written, n)
				return nil
			})
			if err == nil {
				t.Fatalf("accepted %s archive", name)
			}
			for _, w := range written {
				if w != "bundle.yaml" {
					t.Errorf("wrote %q before refusing", w)
				}
			}
		})
	}
}
