package registry

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The local store, the self-host and dev BlobStore: put once, read back,
// exists, delete twice without complaint, and a key that climbs out of the
// root is refused.
func TestLocalFSRoundTripAndDelete(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	st, err := NewLocalFS(root)
	if err != nil {
		t.Fatal(err)
	}
	key := "runs/acct/run-1/result.json"
	if err := st.Put(t.Context(), key, strings.NewReader("payload")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ok, err := st.Exists(t.Context(), key); err != nil || !ok {
		t.Fatalf("Exists = %v, %v; want true", ok, err)
	}
	rc, err := st.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != "payload" {
		t.Fatalf("Get = %q", got)
	}
	if err := st.Delete(t.Context(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "runs", "acct", "run-1", "result.json")); !os.IsNotExist(err) {
		t.Fatalf("the file survived its delete: %v", err)
	}
	if err := st.Delete(t.Context(), key); err != nil {
		t.Fatalf("a second Delete is an error: %v", err)
	}
	if err := st.Delete(t.Context(), "../outside"); err == nil {
		t.Fatal("a key climbing out of the root was accepted")
	}

	t.Run("a key that leaves the root is refused by every operation", func(t *testing.T) {
		// Every operation refuses a key that leaves the root, however it is
		// spelled, and an absolute key; nothing is written outside.
		for _, bad := range []string{"../outside", "a/../../outside", "..", "/abs/key"} {
			if err := st.Put(t.Context(), bad, strings.NewReader("x")); err == nil {
				t.Errorf("Put accepted %q", bad)
			}
			if rc, err := st.Get(t.Context(), bad); err == nil {
				_ = rc.Close()
				t.Errorf("Get accepted %q", bad)
			}
			if ok, err := st.Exists(t.Context(), bad); err == nil || ok {
				t.Errorf("Exists(%q) = %v, %v; want an error", bad, ok, err)
			}
			if err := st.Delete(t.Context(), bad); err == nil {
				t.Errorf("Delete accepted %q", bad)
			}
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(root), "outside")); !os.IsNotExist(err) {
			t.Errorf("a refused Put wrote outside the root: %v", err)
		}
	})
	// Objects are write-once: a second Put to a stored key succeeds and leaves
	// the first bytes; a Put whose reader fails stores nothing and leaves no
	// temporary file; an absent key is not an error for Exists and is one for
	// Get; the root and the files are not readable by others.
	t.Run("objects are write-once and atomic", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "store")
		st, err := NewLocalFS(root)
		if err != nil {
			t.Fatal(err)
		}
		read := func(key string) string {
			t.Helper()
			rc, err := st.Get(t.Context(), key)
			if err != nil {
				t.Fatalf("Get %s: %v", key, err)
			}
			defer func() { _ = rc.Close() }()
			b, _ := io.ReadAll(rc)
			return string(b)
		}
		key := ArchiveKey("sha256:abcdef0123456789")
		if err := st.Put(t.Context(), key, strings.NewReader("first")); err != nil {
			t.Fatal(err)
		}
		if err := st.Put(t.Context(), key, strings.NewReader("second")); err != nil {
			t.Fatalf("a second Put to a stored key must be a no-op, got %v", err)
		}
		if got := read(key); got != "first" {
			t.Errorf("the stored object is %q after a second Put, want it untouched", got)
		}

		boom := errors.New("reader failed")
		failing := io.MultiReader(strings.NewReader("partial"), &errReader{boom})
		other := ArchiveKey("sha256:0011223344556677")
		err = st.Put(t.Context(), other, failing)
		if !errors.Is(err, boom) || !strings.Contains(err.Error(), "blobstore: write") {
			t.Fatalf("Put with a failing reader = %v, want a wrapped write error", err)
		}
		if ok, err := st.Exists(t.Context(), other); err != nil || ok {
			t.Errorf("a failed Put left the object: %v, %v", ok, err)
		}
		entries, err := os.ReadDir(filepath.Dir(filepath.Join(root, filepath.FromSlash(other))))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".upload-") {
				t.Errorf("a failed Put left the temporary file %s", e.Name())
			}
		}

		if ok, err := st.Exists(t.Context(), "releases/zz/absent"); err != nil || ok {
			t.Errorf("Exists on an absent key = %v, %v; want false, nil", ok, err)
		}
		if _, err := st.Get(t.Context(), "releases/zz/absent"); !errors.Is(err, fs.ErrNotExist) || !strings.HasPrefix(err.Error(), "blobstore: ") {
			t.Errorf("Get on an absent key = %v, want a wrapped not-exist error", err)
		}
		// A key that runs through a file cannot be answered: that is an error,
		// not an absent object, and nothing is silently removed.
		if ok, err := st.Exists(t.Context(), key+"/child"); err == nil || ok {
			t.Errorf("Exists through a file = %v, %v; want an error", ok, err)
		}
		if err := st.Delete(t.Context(), key+"/child"); err == nil || !strings.Contains(err.Error(), "blobstore: delete") {
			t.Errorf("Delete through a file = %v, want a wrapped delete error", err)
		}
		if got := read(key); got != "first" {
			t.Errorf("the object changed: %q", got)
		}

		if runtime.GOOS != "windows" {
			for _, p := range []string{root, filepath.Dir(filepath.Join(root, filepath.FromSlash(key))), filepath.Join(root, filepath.FromSlash(key))} {
				fi, err := os.Stat(p)
				if err != nil {
					t.Fatal(err)
				}
				if fi.Mode().Perm()&0o027 != 0 {
					t.Errorf("%s is %v: readable by others or writable by the group", p, fi.Mode().Perm())
				}
			}
		}

		// A root that cannot be created is an error, not a store.
		blocked := filepath.Join(root, filepath.FromSlash(key))
		if got, err := NewLocalFS(filepath.Join(blocked, "under")); err == nil || got != nil || !strings.HasPrefix(err.Error(), "blobstore: ") {
			t.Errorf("NewLocalFS under a file = %v, %v; want a wrapped error and no store", got, err)
		}
	})
}

type errReader struct{ err error }

func (r *errReader) Read([]byte) (int, error) { return 0, r.err }

// ArchiveKey is the name an archive is stored under: the digest without its
// algorithm prefix, sharded by its first two characters, ending ".tar.zst".
// A digest too short to shard goes under "xx".
func TestArchiveKeyIsTheContentAddressedName(t *testing.T) {
	const hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	for _, c := range []struct{ digest, want string }{
		{"sha256:" + hex, "releases/ab/" + hex + ".tar.zst"},
		{hex, "releases/ab/" + hex + ".tar.zst"},
		{"sha256:ab", "releases/ab/ab.tar.zst"},
		{"sha256:a", "releases/xx/a.tar.zst"},
		{"sha256:", "releases/xx/.tar.zst"},
		{"", "releases/xx/.tar.zst"},
	} {
		if got := ArchiveKey(c.digest); got != c.want {
			t.Errorf("ArchiveKey(%q) = %q, want %q", c.digest, got, c.want)
		}
	}
}
