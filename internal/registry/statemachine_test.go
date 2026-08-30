package registry

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/pkg/manifest"
)

// TestStateMachineEdges pins the §7 transition table.
func TestStateMachineEdges(t *testing.T) {
	allowed := []struct{ from, to Status }{
		{StatusSubmitted, StatusScanning},
		{StatusScanning, StatusPublished},
		{StatusScanning, StatusNeedsReview},
		{StatusScanning, StatusRejected},
		{StatusNeedsReview, StatusPublished},
		{StatusNeedsReview, StatusRejected},
		{StatusPublished, StatusQuarantined},
		{StatusPublished, StatusYanked},
		{StatusQuarantined, StatusPublished},
		{StatusQuarantined, StatusYanked},
		{StatusQuarantined, StatusBlocked},
	}
	for _, tc := range allowed {
		if !transitionAllowed(tc.from, tc.to) {
			t.Errorf("%s → %s must be allowed", tc.from, tc.to)
		}
	}
	denied := []struct{ from, to Status }{
		{StatusSubmitted, StatusPublished}, // no path skips the gate
		{StatusRejected, StatusPublished},  // rejected is terminal
		{StatusYanked, StatusPublished},    // yank is permanent
		{StatusScanning, StatusYanked},
		{StatusNeedsReview, StatusScanning},
		{StatusBlocked, StatusPublished}, // reinstate goes via quarantine
	}
	for _, tc := range denied {
		if transitionAllowed(tc.from, tc.to) {
			t.Errorf("%s → %s must be denied", tc.from, tc.to)
		}
	}
	// Property: nothing reaches published except from scanning,
	// needs_review, or quarantined (§7 "no path skips the gate").
	for from := range allowedTransitions {
		for _, to := range allowedTransitions[from] {
			if to == StatusPublished {
				switch from {
				case StatusScanning, StatusNeedsReview, StatusQuarantined:
				default:
					t.Errorf("published reachable from %s", from)
				}
			}
		}
	}
}

// failingWriter fails after n bytes, standing in for the temp-file write
// errors (ENOSPC, EIO) that stageArchive has to survive.
type failingWriter struct {
	remaining int
	err       error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, w.err
	}
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, w.err
	}
	w.remaining -= len(p)
	return len(p), nil
}

// TestStageArchiveDoesNotLeakOnWriteFailure pins B-18: when the destination
// write fails, the BuildArchive goroutine is parked in pw.Write and used to
// stay there forever — one leaked goroutine (holding the whole archive
// pipeline) per failed publish. stageArchive must close the reader with an
// error and wait for the builder to exit.
func TestStageArchiveDoesNotLeakOnWriteFailure(t *testing.T) {
	dir := t.TempDir()
	// Big enough that BuildArchive is still writing when the sink gives up.
	body := strings.Repeat("payload for the archive body\n", 20000)
	for path, content := range map[string]string{
		"agent.yaml": "schemaVersion: \"1\"\n",
		"README.md":  body,
		"SKILL.md":   body,
	} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := WalkWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	include := manifest.ResolveInclude([]string{"agent.yaml", "README.md", "SKILL.md"}, files)

	before := runtime.NumGoroutine()
	wantErr := errors.New("disk full")

	done := make(chan error, 1)
	go func() {
		_, err := stageArchive(dir, include, &failingWriter{remaining: 64, err: wantErr})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stageArchive returned nil on a failing destination")
		}
		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want it to wrap %v", err, wantErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stageArchive hung: the builder goroutine is still blocked on pw.Write")
	}

	// The builder must be gone, not merely unobserved.
	for i := 0; i < 100; i++ {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: %d before, %d after", before, runtime.NumGoroutine())
}

// TestStageArchiveSucceeds is the happy path next to it: the staged bytes and
// digest must match a direct BuildArchive.
func TestStageArchiveSucceeds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte("schemaVersion: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := WalkWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	include := manifest.ResolveInclude([]string{"agent.yaml"}, files)

	var direct bytes.Buffer
	want, err := BuildArchive(dir, include, &direct)
	if err != nil {
		t.Fatal(err)
	}
	var staged bytes.Buffer
	got, err := stageArchive(dir, include, &staged)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != want.Digest || got.Size != want.Size {
		t.Fatalf("staged %+v, direct %+v", got, want)
	}
	if !bytes.Equal(staged.Bytes(), direct.Bytes()) {
		t.Fatal("staged bytes differ from a direct build")
	}
}
