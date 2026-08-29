package audit

// The §12.6 continuous NDJSON archive.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFileStreamWritesNDJSON(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFileStream(dir, time.Hour, nil) // manual flush only
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	org := uuid.New()
	for i := 0; i < 3; i++ {
		st.Append(Record{
			ID: uuid.New(), OccurredAt: time.Now().UTC(), ActorKind: string(ActorUser),
			OrgID: &org, Action: string(ActionOrgCreate), TargetKind: "org",
			Detail: json.RawMessage(`{"handle":"acme"}`),
		})
	}
	if err := st.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	name := "audit-" + time.Now().UTC().Format("20060102") + ".ndjson"
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("archive file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), raw)
	}
	// Every line must be a standalone JSON object — that is what makes the
	// archive greppable and Athena-queryable.
	for _, line := range lines {
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line is not valid JSON: %v (%s)", err, line)
		}
		if rec.Action != string(ActionOrgCreate) || rec.OrgID == nil || *rec.OrgID != org {
			t.Fatalf("record lost fields in the round trip: %+v", rec)
		}
	}

	// A second flush with nothing queued must not append an empty line.
	if err := st.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(filepath.Join(dir, name))
	if len(raw2) != len(raw) {
		t.Fatal("an empty flush rewrote the archive file")
	}
}

func TestFileStreamRotatesDaily(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFileStream(dir, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Open yesterday's file, then let a flush roll it over to today: the
	// handle must follow the date, not stay on whatever it opened first.
	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	if _, err := st.fileFor(yesterday); err != nil {
		t.Fatal(err)
	}
	st.Append(Record{ID: uuid.New(), OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionAuditPrune)})
	if err := st.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	today := filepath.Join(dir, "audit-"+time.Now().UTC().Format("20060102")+".ndjson")
	info, err := os.Stat(today)
	if err != nil {
		t.Fatalf("today's archive not written: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("today's archive is empty — the record went to the stale handle")
	}
}

func TestFileStreamDropsWhenBufferFull(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFileStream(dir, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Archival must never block the request path: past the cap, records are
	// dropped and logged rather than queued without bound.
	for i := 0; i < fileStreamBufferMax+50; i++ {
		st.Append(Record{ID: uuid.New(), OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionUserLogin)})
	}
	st.mu.Lock()
	n := len(st.buf)
	st.mu.Unlock()
	if n != fileStreamBufferMax {
		t.Fatalf("buffer grew to %d, want it capped at %d", n, fileStreamBufferMax)
	}
}

func TestNewStreamKinds(t *testing.T) {
	dir := t.TempDir()
	if _, ok := NewStream("none", dir, "", time.Second, nil).(NopStream); !ok {
		t.Fatal(`kind "none" must yield the no-op sink`)
	}
	if _, ok := NewStream("", dir, "", time.Second, nil).(NopStream); !ok {
		t.Fatal("an unset kind must yield the no-op sink")
	}
	if _, ok := NewStream("nonsense", dir, "", time.Second, nil).(NopStream); !ok {
		t.Fatal("an unknown kind must degrade to the no-op sink, not panic")
	}
	// The S3 sink is a declared stub: it must refuse rather than silently
	// pretend to archive (DEV-020).
	if _, err := NewS3Stream("bucket", time.Second, nil); err == nil {
		t.Fatal("NewS3Stream must return an error until it is implemented")
	}
	if _, ok := NewStream("s3", dir, "bucket", time.Second, nil).(NopStream); !ok {
		t.Fatal("an unavailable s3 sink must degrade to the no-op sink")
	}
	fs, ok := NewStream("file", dir, "", time.Second, nil).(*FileStream)
	if !ok {
		t.Fatal(`kind "file" must yield a FileStream`)
	}
	_ = fs.Close()
}

func TestWriterStreamDefaultsToNop(t *testing.T) {
	w := NewWriter(nil)
	if _, ok := w.Stream().(NopStream); !ok {
		t.Fatal("a writer with no stream attached must not have a nil sink")
	}
	// Appending through the default sink is a no-op, not a panic.
	w.Stream().Append(Record{ID: uuid.New()})
	w.SetStream(nil)
	if _, ok := w.Stream().(NopStream); !ok {
		t.Fatal("SetStream(nil) must fall back to the no-op sink")
	}
}
