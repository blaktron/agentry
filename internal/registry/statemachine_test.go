package registry

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/pkg/manifest"
)

// TestStateMachineEdges pins the transition table.
func TestStateMachineEdges(t *testing.T) {
	allowed := []struct{ from, to Status }{
		{StatusSubmitted, StatusScanning},
		{StatusSubmitted, StatusPublished}, // unscanned, a private org agent's only
		{StatusScanning, StatusPublished},
		{StatusScanning, StatusNeedsReview},
		{StatusScanning, StatusRejected},
		{StatusNeedsReview, StatusPublished},
		{StatusNeedsReview, StatusRejected},
		{StatusPublished, StatusQuarantined},
		{StatusPublished, StatusYanked},
		{StatusPublished, StatusBlocked}, // T&S confirming a malicious published package: one atomic step
		{StatusQuarantined, StatusPublished},
		{StatusQuarantined, StatusYanked},
		{StatusQuarantined, StatusBlocked},
		{StatusBlocked, StatusQuarantined}, // the platform's reinstate path
	}
	for _, tc := range allowed {
		if !transitionAllowed(tc.from, tc.to) {
			t.Errorf("%s → %s must be allowed", tc.from, tc.to)
		}
	}
	denied := []struct{ from, to Status }{
		{StatusRejected, StatusPublished}, // rejected is terminal
		{StatusYanked, StatusPublished},   // yank is permanent
		{StatusScanning, StatusYanked},
		{StatusNeedsReview, StatusScanning},
		{StatusBlocked, StatusPublished}, // reinstate goes via quarantine
	}
	for _, tc := range denied {
		if transitionAllowed(tc.from, tc.to) {
			t.Errorf("%s → %s must be denied", tc.from, tc.to)
		}
	}

	// The table is closed: of every pair of states, the reserved approved
	// state and one that is no state at all included, exactly the allowed
	// edges above are edges. A state with no edge out (rejected, yanked,
	// approved, an unknown one) stays terminal, and a state is not its own
	// successor.
	listed := map[[2]Status]bool{}
	for _, tc := range allowed {
		listed[[2]Status{tc.from, tc.to}] = true
	}
	states := []Status{
		StatusSubmitted, StatusScanning, StatusNeedsReview, StatusApproved, StatusPublished,
		StatusRejected, StatusYanked, StatusQuarantined, StatusBlocked, Status("unknown"),
	}
	edges := 0
	for _, from := range states {
		for _, to := range states {
			got := transitionAllowed(from, to)
			if got != listed[[2]Status{from, to}] {
				t.Errorf("%s → %s: allowed = %v, want %v", from, to, got, !got)
			}
			if got {
				edges++
			}
		}
	}
	if edges != len(allowed) {
		t.Errorf("%d edges in the table, want %d", edges, len(allowed))
	}
	// The gate-skipping edge is that one pair and no other.
	for _, from := range states {
		for _, to := range states {
			want := from == StatusSubmitted && to == StatusPublished
			if got := skipsTheGate(from, to); got != want {
				t.Errorf("skipsTheGate(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}
}

// transitionEvent names the webhook each edge raises: a version that
// publishes, is rejected, goes to review or is yanked, and an agent that is
// quarantined or comes back from quarantine. The edges that raise nothing
// (scanning starts, a block) answer "".
func TestTransitionEventNamesTheWebhookOfEachEdge(t *testing.T) {
	for _, tc := range []struct {
		from, to Status
		want     string
	}{
		{StatusSubmitted, StatusScanning, ""},
		{StatusSubmitted, StatusPublished, "version.published"},
		{StatusScanning, StatusPublished, "version.published"},
		{StatusNeedsReview, StatusPublished, "version.published"},
		{StatusQuarantined, StatusPublished, "agent.reinstated"},
		{StatusScanning, StatusRejected, "version.rejected"},
		{StatusNeedsReview, StatusRejected, "version.rejected"},
		{StatusScanning, StatusNeedsReview, "version.needs_review"},
		{StatusPublished, StatusYanked, "version.yanked"},
		{StatusQuarantined, StatusYanked, "version.yanked"},
		{StatusPublished, StatusQuarantined, "agent.quarantined"},
		{StatusBlocked, StatusQuarantined, "agent.quarantined"},
		{StatusPublished, StatusBlocked, ""},
		{StatusQuarantined, StatusBlocked, ""},
		{StatusPublished, StatusApproved, ""},
	} {
		if got := transitionEvent(tc.from, tc.to); got != tc.want {
			t.Errorf("%s → %s: event %q, want %q", tc.from, tc.to, got, tc.want)
		}
	}
}

// TestNoPathToPublishedSkipsTheGateForAPublicAgent is the "no path to
// published skips the gate" property, qualified for unscanned publishing:
// every edge into published is the gate's — from scanning, needs_review or
// quarantined — except one, submitted → published, which skipsTheGate
// names and TransitionInTx opens only to a version marked skipped. The
// marking is SubmitVersion's, for an agent whose administrator set the
// flag, which the API refuses on a public agent and in a personal
// namespace, and the private → public change is refused while the flag
// is set or a version published unscanned stands (the api package's
// tests). So for a public agent the property is unqualified.
func TestNoPathToPublishedSkipsTheGateForAPublicAgent(t *testing.T) {
	gated := map[Status]bool{StatusScanning: true, StatusNeedsReview: true, StatusQuarantined: true}
	skipping := 0
	for from := range allowedTransitions {
		for _, to := range allowedTransitions[from] {
			if to != StatusPublished {
				if skipsTheGate(from, to) {
					t.Errorf("%s → %s is not an edge into published, yet skipsTheGate says so", from, to)
				}
				continue
			}
			switch {
			case gated[from]:
				if skipsTheGate(from, to) {
					t.Errorf("%s → %s is the gate's edge, yet skipsTheGate says otherwise", from, to)
				}
			case skipsTheGate(from, to):
				skipping++
			default:
				t.Errorf("published reachable from %s by an edge that is neither the gate's nor the one for unscanned versions", from)
			}
		}
	}
	if skipping != 1 || !skipsTheGate(StatusSubmitted, StatusPublished) {
		t.Fatalf("%d gate-skipping edges, want exactly one: submitted → published", skipping)
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

// TestStageArchiveDoesNotLeakOnWriteFailure pins the failure path: when the destination
// write fails, the BuildArchive goroutine is parked in pw.Write and would
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

	wantErr := errors.New("disk full")

	// Which failure is reported. A sink that fails on the last byte of an
	// archive that was built whole: the copy failed, the build did not, so
	// the staging error is the one returned, wrapped. A build that fails
	// itself (a file that is gone) is the build error, wrapped, with the sink
	// untouched by it. And when both fail, the sink failure that aborted the
	// build comes back as the build's error, which says more.
	t.Run("the failing side is named", func(t *testing.T) {
		small := t.TempDir()
		if err := os.WriteFile(filepath.Join(small, "agent.yaml"), []byte("schemaVersion: \"1\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		smallFiles, err := WalkWorkspace(small)
		if err != nil {
			t.Fatal(err)
		}
		smallInclude := manifest.ResolveInclude([]string{"agent.yaml"}, smallFiles)
		var whole bytes.Buffer
		if _, err := BuildArchive(small, smallInclude, &whole); err != nil {
			t.Fatal(err)
		}
		_, err = stageArchive(small, smallInclude, &failingWriter{remaining: whole.Len() - 1, err: wantErr})
		if !errors.Is(err, wantErr) || !strings.HasPrefix(err.Error(), "registry: stage archive: ") {
			t.Errorf("a sink that fails on the last byte: %v, want the wrapped staging error", err)
		}

		gone := append(append([]manifest.FileInfo(nil), smallInclude...), manifest.FileInfo{Path: "gone.md", Size: 3})
		var sink bytes.Buffer
		_, err = stageArchive(small, gone, &sink)
		if !errors.Is(err, fs.ErrNotExist) || !strings.HasPrefix(err.Error(), "registry: build archive: ") {
			t.Errorf("a build that fails: %v, want the wrapped build error", err)
		}
	})

	before := runtime.NumGoroutine()

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
		if !strings.HasPrefix(err.Error(), "registry: build archive: ") {
			t.Fatalf("error = %v, want the build's own error, which the sink failure aborted", err)
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
