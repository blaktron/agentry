package registry

import (
	"io"
	"os"
	"path/filepath"
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
}
