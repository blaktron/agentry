package rules_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

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

// tarEntry builds a tar holding one header of any type and no content.
func tarEntry(t *testing.T, hdr tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr.Size = 0
	if hdr.Mode == 0 {
		hdr.Mode = 0o644
	}
	if err := tw.WriteHeader(&hdr); err != nil {
		t.Fatal(err)
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

	// And the bytes are the canonical form: bundle.yaml first, then the rule
	// files in name order, each a regular file with a fixed mode, no owner,
	// the epoch as its time, ustar headers, and the file's exact content.
	tr := tar.NewReader(bytes.NewReader(first))
	var names []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, hdr.Name)
		if hdr.Typeflag != tar.TypeReg || hdr.Mode != 0o644 || hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" || hdr.Gname != "" {
			t.Errorf("%s: type %q mode %o owner %d:%d %q:%q, want a plain 0644 file with no owner", hdr.Name, hdr.Typeflag, hdr.Mode, hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname)
		}
		if !hdr.ModTime.Equal(time.Unix(0, 0)) {
			t.Errorf("%s: ModTime = %v, want the epoch", hdr.Name, hdr.ModTime)
		}
		if hdr.Format != tar.FormatUSTAR {
			t.Errorf("%s: format %v, want ustar", hdr.Name, hdr.Format)
		}
		got := new(bytes.Buffer)
		if _, err := got.ReadFrom(tr); err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join("..", "ruleset", "rules", hdr.Name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), want) || hdr.Size != int64(len(want)) {
			t.Errorf("%s: %d bytes in the archive differ from the bundle's file (%d bytes)", hdr.Name, got.Len(), len(want))
		}
	}
	if len(names) < 8 || names[0] != "bundle.yaml" || !sort.StringsAreSorted(names[1:]) {
		t.Errorf("entries = %v, want bundle.yaml first and then the rule files in name order", names)
	}
	// The fixed epoch and ordering make the bytes themselves stable across
	// bundles with the same files: the end of an archive is two zero blocks.
	if !bytes.HasSuffix(first, make([]byte, 1024)) {
		t.Error("the archive does not end with the two zero blocks")
	}
}

// TestUntarBundleRejectsStructure: an archive from a registry is untrusted
// input. Anything with a path, a directory, or a non-YAML payload in it did
// not come from Tar() and must be refused rather than written out.
func TestUntarBundleRejectsStructure(t *testing.T) {
	good := tarWith(t, "ok.yaml", "rules: []")
	// The archive of one good entry with its end-of-archive blocks cut off:
	// what follows is read as the next header.
	open := good[:len(good)-1024]
	garbage := bytes.Repeat([]byte{0x7f}, 512)
	big := tarWith(t, "big.yaml", strings.Repeat("a", 1000))
	many := func(n int) []byte {
		var args []string
		for i := 0; i < n; i++ {
			args = append(args, fmt.Sprintf("f%03d.yaml", i), "x")
		}
		return tarWith(t, args...)
	}
	var firstEntries []string
	for i := 0; i < 256; i++ {
		firstEntries = append(firstEntries, fmt.Sprintf("f%03d.yaml", i))
	}
	cases := []struct {
		name    string
		data    []byte
		wantErr string
		wrote   []string // the entries handed to write before the refusal
	}{
		{"path traversal", tarWith(t, "../escape.yaml", "rules: []"), "is not a flat file name", nil},
		{"subdirectory", tarWith(t, "nested/rules.yaml", "rules: []"), "is not a flat file name", nil},
		{"non-yaml", tarWith(t, "payload.sh", "#!/bin/sh\n"), "is not a YAML file", nil},
		{"empty archive", tarWith(t), "bundle archive is empty", nil},
		{"backslash traversal", tarWith(t, `..\escape.yaml`, "rules: []"), "is not a flat file name", nil},
		{"backslash path", tarWith(t, `sub\rules.yaml`, "rules: []"), "is not a flat file name", nil},
		{"absolute path", tarWith(t, "/etc/rules.yaml", "rules: []"), "is not a flat file name", nil},
		{"dot dot", tarWith(t, "..", "rules: []"), "is not a flat file name", nil},
		{"dot", tarWith(t, ".", "rules: []"), "is not a flat file name", nil},
		{"no extension", tarWith(t, "rules", "rules: []"), "is not a YAML file", nil},
		{"yaml as a directory name", tarWith(t, "yaml", "rules: []"), "is not a YAML file", nil},
		{"a double extension", tarWith(t, "rules.yaml.sh", "rules: []"), "is not a YAML file", nil},
		{"a symbolic link", tarEntry(t, tar.Header{Name: "link.yaml", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}), "is not a regular file", nil},
		{"a hard link", tarEntry(t, tar.Header{Name: "link.yaml", Typeflag: tar.TypeLink, Linkname: "bundle.yaml"}), "is not a regular file", nil},
		{"a directory", tarEntry(t, tar.Header{Name: "dir.yaml", Typeflag: tar.TypeDir, Mode: 0o755}), "is not a regular file", nil},
		{"a device", tarEntry(t, tar.Header{Name: "dev.yaml", Typeflag: tar.TypeChar}), "is not a regular file", nil},
		{"not a tar at all", []byte("this is not a tar archive"), "read bundle archive", nil},
		{"a corrupt header after a good entry", append(append([]byte{}, open...), garbage...), "read bundle archive", []string{"ok.yaml"}},
		{"an entry cut short", big[:512+100], "from bundle archive", nil},
		{"an entry over the size limit", tarWith(t, "big.yaml", strings.Repeat("a", 4<<20+1)), "exceeds 4194304 bytes", nil},
		{"257 entries", many(257), "more than 256 entries", firstEntries},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var written []string
			_, err := rules.UntarBundle(c.data, func(n string, _ []byte) error {
				written = append(written, n)
				return nil
			})
			if err == nil {
				t.Fatalf("accepted %s archive", c.name)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, c.wantErr)
			}
			if !reflect.DeepEqual(written, c.wrote) {
				t.Errorf("wrote %d entries %v before refusing, want %d %v", len(written), written, len(c.wrote), c.wrote)
			}
		})
	}

	// At the limits an archive is accepted: 256 entries, a 4 MiB entry, and
	// any case of the extension; names come back in archive order.
	names, err := rules.UntarBundle(many(256), func(string, []byte) error { return nil })
	if err != nil || len(names) != 256 || names[0] != "f000.yaml" || names[255] != "f255.yaml" {
		t.Errorf("256 entries: %d names, %v", len(names), err)
	}
	var size int
	names, err = rules.UntarBundle(tarWith(t, "big.yaml", strings.Repeat("a", 4<<20)), func(_ string, c []byte) error { size = len(c); return nil })
	if err != nil || !reflect.DeepEqual(names, []string{"big.yaml"}) || size != 4<<20 {
		t.Errorf("a 4 MiB entry: %v, %d bytes, %v", names, size, err)
	}
	content := map[string]string{}
	names, err = rules.UntarBundle(tarWith(t, "z.yml", "one", "A.YAML", "two", "b.Yml", "three"), func(n string, c []byte) error { content[n] = string(c); return nil })
	if err != nil || !reflect.DeepEqual(names, []string{"z.yml", "A.YAML", "b.Yml"}) || content["A.YAML"] != "two" || content["b.Yml"] != "three" {
		t.Errorf(".yml and upper-case extensions: %v, %v, %v", names, content, err)
	}

	// An error from the caller's write stops the unpacking and is returned
	// as it is.
	boom := errors.New("disk full")
	var seen []string
	_, err = rules.UntarBundle(tarWith(t, "a.yaml", "1", "b.yaml", "2"), func(n string, _ []byte) error {
		seen = append(seen, n)
		return boom
	})
	if !errors.Is(err, boom) || !reflect.DeepEqual(seen, []string{"a.yaml"}) {
		t.Errorf("write error: err = %v, entries written %v, want the error and only a.yaml", err, seen)
	}
}

// A name Windows gives a meaning to is refused before anything is written:
// a colon (a drive-relative name, an alternate data stream), a reserved device
// name in any case and with any extension, a trailing dot or space, and the
// characters and control codes its file systems refuse. Names that only look
// like one are kept.
func TestUntarBundleRefusesNamesWindowsGivesAMeaning(t *testing.T) {
	for _, c := range []struct{ name, entry, wantErr string }{
		{"a drive-relative name", "C:x.yaml", "colon"},
		{"an alternate data stream", "bundle.yaml:stream.yaml", "colon"},
		{"the null device", "NUL.yaml", "reserved device name"},
		{"the console, lower case", "con.yaml", "reserved device name"},
		{"a serial port", "COM1.yaml", "reserved device name"},
		{"a serial port with a superscript digit", "COM\u00b9.yaml", "reserved device name"},
		{"a printer port, mixed case", "lPt9.yml", "reserved device name"},
		{"a device with a double extension", "AUX.rules.yaml", "reserved device name"},
		{"a device with a trailing space before the extension", "PRN .yaml", "reserved device name"},
		{"the console input", "CONIN$.yaml", "reserved device name"},
		{"a trailing dot", "rules.yaml.", "ends in a dot or a space"},
		{"a trailing space", "rules.yaml ", "ends in a dot or a space"},
		{"a question mark", "what?.yaml", "'?'"},
		{"a pipe", "a|b.yaml", "'|'"},
		{"a control character", "a\x01b.yaml", "control character"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var written []string
			_, err := rules.UntarBundle(tarWith(t, "ok.yaml", "rules: []", c.entry, "rules: []"), func(n string, _ []byte) error {
				written = append(written, n)
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), "not a plain file name on every system") || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want a refusal naming %q", err, c.wantErr)
			}
			if len(written) != 1 || written[0] != "ok.yaml" {
				t.Fatalf("written %q, want only the entry before the hostile one", written)
			}
		})
	}
	for _, name := range []string{"con-rules.yaml", "nullish.yaml", "COM10.yaml", "auxiliary.yml", "rules.v2.yaml"} {
		if _, err := rules.UntarBundle(tarWith(t, name, "rules: []"), func(string, []byte) error { return nil }); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
