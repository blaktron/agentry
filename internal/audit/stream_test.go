package audit

// The continuous NDJSON archive.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/logx"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// line parses the one JSON line in buf.
func line(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("not one JSON line: %v: %q", err, buf.String())
	}
	return m
}

// archiveLines reads the day file in dir and returns its lines.
func archiveLines(t *testing.T, dir string) []string {
	t.Helper()
	name := "audit-" + time.Now().UTC().Format("20060102") + ".ndjson"
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("archive file: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// waitFor yields the processor until cond holds, failing when the test's
// context ends first; it needs no timer of its own.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for !cond() {
		if ctx.Err() != nil {
			t.Fatalf("gave up waiting for %s", what)
		}
		runtime.Gosched()
	}
}

// loopGoroutines counts the live background flushers.
func loopGoroutines() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	return strings.Count(string(buf), "audit.(*FileStream).loop")
}

func TestFileStreamWritesNDJSON(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFileStream(dir, time.Hour, nil) // manual flush only
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Nothing queued yet: a flush must not even create the day file.
	if err := st.Flush(context.Background()); err != nil {
		t.Fatalf("flush of an empty stream: %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("an empty flush created %d entries in the archive directory (err %v)", len(entries), err)
	}

	org := uuid.New()
	for i := 0; i < 3; i++ {
		st.Append(Record{
			ID: uuid.New(), OccurredAt: time.Now().UTC(), ActorKind: string(ActorUser),
			OrgID: &org, Action: string(ActionOrgCreate), TargetKind: "org",
			Detail: json.RawMessage(`{"handle":"acme"}`),
			// The caller's address, agent and request are on the row and the
			// log mirror; the file archive keeps the API's shape without them.
			IP: "203.0.113.7", UserAgent: "curl/8", RequestID: "req-1",
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
		// The archive's field names are the API's AuditEvent shape: exactly
		// these keys, camelCase, with the optional ones omitted when unset
		// and the caller's address, agent and request never written.
		var keys map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &keys); err != nil {
			t.Fatal(err)
		}
		var got []string
		for k := range keys {
			got = append(got, k)
		}
		want := map[string]bool{"id": true, "occurredAt": true, "actorKind": true, "orgId": true, "action": true, "targetKind": true, "detail": true}
		if len(got) != len(want) {
			t.Fatalf("archive line keys = %v, want exactly %v", got, want)
		}
		for _, k := range got {
			if !want[k] {
				t.Fatalf("archive line carries key %q: %s", k, line)
			}
		}
		if strings.Contains(line, "203.0.113.7") || strings.Contains(line, "curl/8") || strings.Contains(line, "req-1") {
			t.Fatalf("the file archive wrote the address, agent or request id: %s", line)
		}
	}
	// The archive is owner and group only: never world-readable, and the
	// archive directory is private to its group.
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&^0o640 != 0 {
		t.Fatalf("archive file mode %v is wider than 0640", info.Mode().Perm())
	}

	// A second flush with nothing queued must not append an empty line.
	if err := st.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(filepath.Join(dir, name))
	if len(raw2) != len(raw) {
		t.Fatal("an empty flush rewrote the archive file")
	}

	// Append-only: a second stream opened on the same day's file adds to it
	// and leaves every earlier line byte for byte as it was.
	st2, err := NewFileStream(dir, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	st2.Append(Record{ID: uuid.New(), OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionAuditPrune)})
	if err := st2.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw3, _ := os.ReadFile(filepath.Join(dir, name))
	if !bytes.HasPrefix(raw3, raw) || len(strings.Split(strings.TrimSpace(string(raw3)), "\n")) != 4 {
		t.Fatalf("a later stream did not append to the day's file:\n%s", raw3)
	}
	// A record with only its required fields writes only those keys.
	var sparse map[string]json.RawMessage
	all := strings.Split(strings.TrimSpace(string(raw3)), "\n")
	if err := json.Unmarshal([]byte(all[3]), &sparse); err != nil {
		t.Fatal(err)
	}
	if len(sparse) != 4 {
		t.Fatalf("a record with no optional fields wrote %d keys: %s", len(sparse), all[3])
	}
	for _, k := range []string{"id", "occurredAt", "actorKind", "action"} {
		if _, ok := sparse[k]; !ok {
			t.Fatalf("a record lost its %q key: %s", k, all[3])
		}
	}

	// A flush the disk refuses keeps the records for the next one, ahead of
	// anything queued since, and a record the encoder cannot write is an
	// error rather than a silent loss.
	gone := t.TempDir()
	st3, err := NewFileStream(filepath.Join(gone, "archive"), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st3.Close() })
	first, second := uuid.New(), uuid.New()
	st3.Append(Record{ID: first, OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionAuditPrune)})
	if err := os.RemoveAll(filepath.Join(gone, "archive")); err != nil {
		t.Fatal(err)
	}
	if err := st3.Flush(context.Background()); err == nil || !strings.Contains(err.Error(), "audit: open") {
		t.Fatalf("flush into a missing directory = %v, want an open error", err)
	}
	st3.mu.Lock()
	kept := len(st3.buf)
	st3.mu.Unlock()
	if kept != 1 {
		t.Fatalf("a failed flush kept %d records, want the 1 it could not write", kept)
	}
	st3.Append(Record{ID: second, OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionAuditPrune)})
	if err := os.MkdirAll(filepath.Join(gone, "archive"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := st3.Flush(context.Background()); err != nil {
		t.Fatalf("flush after the directory returned: %v", err)
	}
	retried := archiveLines(t, filepath.Join(gone, "archive"))
	if len(retried) != 2 || !strings.Contains(retried[0], first.String()) || !strings.Contains(retried[1], second.String()) {
		t.Fatalf("the retried records are not both there in order:\n%s", strings.Join(retried, "\n"))
	}
	st3.Append(Record{ID: uuid.New(), OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionAuditPrune), Detail: json.RawMessage(`{bad`)})
	if err := st3.Flush(context.Background()); err == nil || !strings.Contains(err.Error(), "audit: stream encode") {
		t.Fatalf("a record the encoder refuses must fail the flush, got %v", err)
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
	stale, err := st.fileFor(yesterday)
	if err != nil {
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
	// The yesterday handle is released at the rotation, not left open, and
	// its file keeps nothing of today.
	if _, err := stale.Write([]byte("x")); err == nil {
		t.Fatal("the previous day's handle is still open after the rotation")
	}
	yinfo, err := os.Stat(filepath.Join(dir, "audit-"+yesterday.Format("20060102")+".ndjson"))
	if err != nil || yinfo.Size() != 0 {
		t.Fatalf("yesterday's file = %v (err %v), want it empty", yinfo, err)
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
	// dropped and logged rather than queued without bound — and every drop
	// is reported to the hook that counts fail-open events.
	drops := 0
	st.OnDrop = func() { drops++ }
	for i := 0; i < fileStreamBufferMax+50; i++ {
		st.Append(Record{ID: uuid.New(), OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionUserLogin)})
	}
	st.mu.Lock()
	n := len(st.buf)
	st.mu.Unlock()
	if n != fileStreamBufferMax {
		t.Fatalf("buffer grew to %d, want it capped at %d", n, fileStreamBufferMax)
	}
	if drops != 50 {
		t.Fatalf("OnDrop fired %d times, want 50", drops)
	}

	// Exactly at the cap nothing is dropped; the next record is, and the log
	// line names the fail-open event, the action and the record's id.
	var logbuf bytes.Buffer
	lst, err := NewFileStream(t.TempDir(), time.Hour, logx.New(logx.Options{W: &logbuf}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lst.Close() })
	lost := 0
	lst.OnDrop = func() { lost++ }
	for i := 0; i < fileStreamBufferMax; i++ {
		lst.Append(Record{ID: uuid.New(), OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionUserLogin)})
	}
	if lost != 0 || logbuf.Len() != 0 {
		t.Fatalf("%d records dropped at exactly the cap (log %q)", lost, logbuf.String())
	}
	extra := uuid.New()
	lst.Append(Record{ID: extra, OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionPATRevoke)})
	if lost != 1 {
		t.Fatalf("OnDrop fired %d times for the record past the cap, want 1", lost)
	}
	var drop map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logbuf.Bytes()), &drop); err != nil {
		t.Fatalf("drop log is not one JSON line: %v: %q", err, logbuf.String())
	}
	if drop["event"] != "failopen.audit_stream_drop" || drop["action"] != string(ActionPATRevoke) || drop["id"] != extra.String() || drop["level"] != "ERROR" {
		t.Fatalf("drop log line = %v", drop)
	}
	if err := lst.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, l := range archiveLines(t, lst.dir) {
		if strings.Contains(l, extra.String()) {
			t.Fatal("the dropped record reached the archive")
		}
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
	// pretend to archive.
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
	if _, ok := NewStream("log", "", "", time.Second, nil).(LogStream); !ok {
		t.Fatal(`kind "log" with no logger must still yield a LogStream`)
	}

	// An unavailable sink degrades to the no-op sink and says so on the
	// logger it was given (or the default one when none was); a configured
	// "none" is silent.
	for _, c := range []struct {
		kind, dir string
		want      []string
	}{
		{"none", dir, nil},
		{"", dir, nil},
		{"nonsense", dir, []string{"audit stream: unknown kind, archiving disabled", `"kind":"nonsense"`}},
		{"s3", dir, []string{"audit stream: s3 sink unavailable, archiving disabled", "audit: s3 stream is not configured in this build"}},
		{"file", "", []string{"audit stream: file sink unavailable, archiving disabled", "file stream needs a directory"}},
	} {
		var buf bytes.Buffer
		got := NewStream(c.kind, c.dir, "bucket", time.Second, logx.New(logx.Options{W: &buf}))
		if _, ok := got.(NopStream); !ok {
			t.Errorf("kind %q dir %q = %T, want the no-op sink", c.kind, c.dir, got)
		}
		if len(c.want) == 0 && buf.Len() != 0 {
			t.Errorf("kind %q logged %q, want silence", c.kind, buf.String())
		}
		for _, w := range c.want {
			if !strings.Contains(buf.String(), w) {
				t.Errorf("kind %q log %q lacks %q", c.kind, buf.String(), w)
			}
		}
		if len(c.want) > 0 && !strings.Contains(buf.String(), `"level":"ERROR"`) {
			t.Errorf("kind %q log %q is not at error level", c.kind, buf.String())
		}
	}
	// With no logger of its own the failure goes to the process default
	// rather than into a nil pointer.
	prev := slog.Default()
	var defbuf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&defbuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	for _, kind := range []string{"file", "s3", "nonsense"} {
		if _, ok := NewStream(kind, "", "", time.Second, nil).(NopStream); !ok {
			t.Errorf("kind %q with no logger must yield the no-op sink", kind)
		}
	}
	if strings.Count(defbuf.String(), "archiving disabled") != 3 {
		t.Errorf("the default logger got %q, want three archiving-disabled lines", defbuf.String())
	}
	// The S3 refusal names the bucket it was asked for.
	if _, err := NewS3Stream("my-bucket", time.Second, nil); err == nil || !strings.Contains(err.Error(), `"my-bucket"`) || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("NewS3Stream error = %v", err)
	}
	t.Run("file sink preconditions", fileStreamPreconditions)
}

// fileStreamPreconditions: a directory is required and created private, an
// unusable one is refused, and the flush interval defaults.
func fileStreamPreconditions(t *testing.T) {
	if _, err := NewFileStream("", time.Second, nil); err == nil || !strings.Contains(err.Error(), "file stream needs a directory") {
		t.Fatalf("empty directory = %v, want it refused", err)
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStream(filepath.Join(blocker, "sub"), time.Second, nil); err == nil || !strings.Contains(err.Error(), "audit: file stream dir") {
		t.Fatalf("a directory under a regular file = %v, want it refused", err)
	}
	private := filepath.Join(t.TempDir(), "a", "b")
	st, err := NewFileStream(private, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	info, err := os.Stat(private)
	if err != nil || !info.IsDir() {
		t.Fatalf("archive directory not created: %v", err)
	}
	if info.Mode().Perm()&^0o750 != 0 {
		t.Fatalf("archive directory mode %v is wider than 0750", info.Mode().Perm())
	}
	if st.flush != time.Hour {
		t.Fatalf("flush interval = %v, want the configured hour", st.flush)
	}
	for _, d := range []time.Duration{0, -time.Second} {
		z, err := NewFileStream(t.TempDir(), d, nil)
		if err != nil {
			t.Fatal(err)
		}
		if z.flush != 30*time.Second {
			t.Errorf("flush interval for %v = %v, want the 30s default", d, z.flush)
		}
		_ = z.Close()
	}
}

// Delivery is asynchronous: the background loop writes what was queued
// without anyone calling Flush, Close writes the rest and releases the day's
// file and the loop, and closing twice is harmless.
func TestFileStreamBackgroundFlushAndClose(t *testing.T) {
	waitFor(t, "earlier flushers to exit", func() bool { return loopGoroutines() == 0 })
	dir := t.TempDir()
	st, err := NewFileStream(dir, time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the flusher to start", func() bool { return loopGoroutines() == 1 })
	id := uuid.New()
	st.Append(Record{ID: id, OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionAuditPrune)})
	name := filepath.Join(dir, "audit-"+time.Now().UTC().Format("20060102")+".ndjson")
	waitFor(t, "the background flush", func() bool {
		raw, err := os.ReadFile(name)
		return err == nil && strings.Contains(string(raw), id.String())
	})
	st.mu.Lock()
	handle := st.f
	st.mu.Unlock()
	if handle == nil {
		t.Fatal("no day file is open after a flush")
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the flusher to exit", func() bool { return loopGoroutines() == 0 })
	st.mu.Lock()
	closed := st.f == nil
	st.mu.Unlock()
	if !closed {
		t.Fatal("Close left the day's file open")
	}
	if _, err := handle.Write([]byte("x")); err == nil {
		t.Fatal("the day's file handle is still open after Close")
	}
	if err := st.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	// Close writes what is still queued when the interval never fired.
	slow := t.TempDir()
	ls, err := NewFileStream(slow, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	pending := uuid.New()
	ls.Append(Record{ID: pending, OccurredAt: time.Now().UTC(), ActorKind: string(ActorSystem), Action: string(ActionAuditPrune)})
	if err := ls.Close(); err != nil {
		t.Fatal(err)
	}
	if lines := archiveLines(t, slow); len(lines) != 1 || !strings.Contains(lines[0], pending.String()) {
		t.Fatalf("Close did not write the queued record: %v", lines)
	}
	waitFor(t, "the flusher to exit", func() bool { return loopGoroutines() == 0 })
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
	rs := &recordingStream{}
	w.SetStream(rs)
	if w.Stream() != Stream(rs) {
		t.Fatal("SetStream did not attach the sink")
	}
}

// The `log` kind mirrors a record as one line named audit.<action> with the
// record's fields — including the three the file archive omits — and the
// detail walked by the contract's sanitiser; the row write path is untouched
// (Write still inserts first, see TestAuditCoverage in internal/api).
func TestLogStreamMirrorsRecordAsLine(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf})
	st := NewStream("log", "", "", time.Second, log)
	if _, ok := st.(LogStream); !ok {
		t.Fatalf(`kind "log" must yield a LogStream, got %T`, st)
	}
	actor, org := uuid.New(), uuid.New()
	id, occurred := uuid.New(), time.Now().UTC()
	tok, _ := auth.NewToken(auth.PATPrefix)
	st.Append(Record{
		ID: id, OccurredAt: occurred, ActorID: &actor, ActorKind: string(ActorUser),
		OrgID: &org, Action: string(ActionUserLogin), TargetKind: "user", TargetID: &actor,
		Detail: json.RawMessage(`{"via":"password","token":"` + tok + `","note":"x ` + tok + `"}`),
		IP:     "203.0.113.7", UserAgent: "curl/8", RequestID: "req-0123456789",
	})
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("not one JSON line: %v: %s", err, buf.String())
	}
	want := map[string]string{
		"event": "audit.user.login", "actor": actor.String(), "org": org.String(), "actor_kind": "user",
		"target_kind": "user", "client_ip": "203.0.113.7", "user_agent": "curl/8", "request_id": "req-0123456789",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %q", k, m[k], v)
		}
	}
	d, _ := m["detail"].(map[string]any)
	if d["via"] != "password" {
		t.Errorf("detail not carried as an object: %v", m["detail"])
	}
	if d["token"] != logx.Redacted || strings.Contains(buf.String(), tok) {
		t.Errorf("a token in the detail reached the line: %s", buf.String())
	}
	if err := st.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	// Every field the record carries is on the line under its own name.
	for k, v := range map[string]string{"msg": "audit", "level": "INFO", "audit_id": id.String(), "target_id": actor.String(), "occurred_at": occurred.Format(time.RFC3339Nano)} {
		if m[k] != v {
			t.Errorf("%s = %v, want %q", k, m[k], v)
		}
	}
	if !strings.Contains(buf.String(), `"note":"x `+tok[:12]+`…[redacted]"`) {
		t.Errorf("a token inside a detail string is not masked with its display prefix: %s", buf.String())
	}

	// A record with only its required fields writes only those: no empty
	// actor, org, target, address, agent, request or detail.
	buf.Reset()
	bare := uuid.New()
	st.Append(Record{ID: bare, OccurredAt: occurred, ActorKind: string(ActorSystem), Action: string(ActionAuditPrune), Detail: json.RawMessage(`{}`)})
	bareLine := line(t, &buf)
	if bareLine["event"] != "audit.audit.prune" || bareLine["audit_id"] != bare.String() || bareLine["actor_kind"] != "system" {
		t.Errorf("minimal line = %v", bareLine)
	}
	for _, k := range []string{"actor", "org", "target_kind", "target_id", "client_ip", "user_agent", "request_id", "detail"} {
		if _, ok := bareLine[k]; ok {
			t.Errorf("minimal line carries %q: %v", k, bareLine)
		}
	}
	buf.Reset()
	st.Append(Record{ID: bare, OccurredAt: occurred, ActorKind: string(ActorSystem), Action: string(ActionAuditPrune)})
	if _, ok := line(t, &buf)["detail"]; ok {
		t.Error("a record with no detail wrote a detail attribute")
	}
	// A detail that is not JSON is carried as the text it is, still masked.
	buf.Reset()
	st.Append(Record{ID: bare, OccurredAt: occurred, ActorKind: string(ActorSystem), Action: string(ActionAuditPrune), Detail: json.RawMessage(`not json ` + tok)})
	if d := line(t, &buf)["detail"]; d != "not json "+tok[:12]+"…"+logx.Redacted {
		t.Errorf("unparseable detail = %v", d)
	}
	// A mirror built with no logger writes to the process default.
	prev := slog.Default()
	var defbuf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&defbuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	NewLogStream(nil).Append(Record{ID: bare, OccurredAt: occurred, ActorKind: string(ActorSystem), Action: string(ActionAuditPrune)})
	if !strings.Contains(defbuf.String(), `"event":"audit.audit.prune"`) {
		t.Errorf("default logger got %q", defbuf.String())
	}
}

// recordingStream keeps what the writer hands the archive.
type recordingStream struct{ recs []Record }

func (r *recordingStream) Append(rec Record)           { r.recs = append(r.recs, rec) }
func (r *recordingStream) Flush(context.Context) error { return nil }
func (r *recordingStream) Close() error                { return nil }

// fakeDB stands in for the connection: it records every statement the writer
// runs and can be told to refuse the partition call or the insert.
type fakeDB struct {
	ensures     [][]any
	inserts     [][]any
	ensureError error
	insertError error
}

func (f *fakeDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "audit_ensure_partition") {
		f.ensures = append(f.ensures, args)
		return pgconn.CommandTag{}, f.ensureError
	}
	if strings.Contains(sql, "INSERT INTO audit_events") {
		f.inserts = append(f.inserts, args)
		return pgconn.CommandTag{}, f.insertError
	}
	panic("unexpected statement: " + sql)
}
func (f *fakeDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("the audit writer only executes statements")
}
func (f *fakeDB) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("the audit writer only executes statements")
}

// The writer's row and its archive copy: what is stored, what is left null,
// what is capped, what the request correlation adds, and what a failure does
// to the caller and to the archive. The row write itself is covered against a
// real database in internal/api; here the statement is observed.
func TestWriterWritesTheRowAndFeedsTheArchive(t *testing.T) {
	newWriter := func() (*Writer, *fakeDB, *recordingStream, *bytes.Buffer, *storegen.Queries) {
		var logbuf bytes.Buffer
		w := NewWriter(logx.New(logx.Options{W: &logbuf}))
		rs := &recordingStream{}
		w.SetStream(rs)
		db := &fakeDB{}
		return w, db, rs, &logbuf, storegen.New(db)
	}
	ctx := context.Background()

	t.Run("an unregistered action is refused before anything runs", func(t *testing.T) {
		w, db, rs, _, q := newWriter()
		err := w.Write(ctx, q, Event{ActorKind: ActorSystem, Action: Action("nope.nothing")})
		if err == nil || !strings.Contains(err.Error(), `unregistered action "nope.nothing"`) {
			t.Fatalf("err = %v", err)
		}
		if len(db.ensures)+len(db.inserts)+len(rs.recs) != 0 {
			t.Fatal("a refused action reached the database or the archive")
		}
	})

	t.Run("a full event is stored once and archived with the same id", func(t *testing.T) {
		w, db, rs, _, q := newWriter()
		actor, org, target := uuid.New(), uuid.New(), uuid.New()
		detail := map[string]any{"handle": "acme"}
		rctx := logx.WithRequestID(ctx, "req-42")
		e := Event{
			Actor: actor, ActorKind: ActorUser, OrgID: org, Action: ActionOrgCreate,
			TargetKind: "org", TargetID: target, IP: netip.MustParseAddr("203.0.113.7"),
			UserAgent: "curl/8", Detail: detail,
		}
		before := time.Now().UTC()
		if err := w.Write(rctx, q, e); err != nil {
			t.Fatal(err)
		}
		if len(db.ensures) != 1 || len(db.inserts) != 1 || len(rs.recs) != 1 {
			t.Fatalf("ensures %d inserts %d archived %d, want 1 each", len(db.ensures), len(db.inserts), len(rs.recs))
		}
		if d, ok := db.ensures[0][0].(pgtype.Date); !ok || !d.Valid || d.Time.Format("200601") != time.Now().UTC().Format("200601") {
			t.Fatalf("partition argument = %#v, want this month", db.ensures[0][0])
		}
		a := db.inserts[0]
		id, ok := a[0].(uuid.UUID)
		if !ok || id.Version() != 7 {
			t.Fatalf("row id = %v, want a version 7 uuid", a[0])
		}
		at, ok := a[1].(time.Time)
		if !ok || at.Location() != time.UTC || at.Before(before.Add(-time.Second)) || at.After(time.Now().Add(time.Second)) {
			t.Fatalf("occurred_at = %v, want now in UTC", a[1])
		}
		if p, ok := a[2].(*uuid.UUID); !ok || p == nil || *p != actor {
			t.Fatalf("actor = %v", a[2])
		}
		if a[3] != "user" || a[5] != "org.create" {
			t.Fatalf("actor kind %v action %v", a[3], a[5])
		}
		if p, ok := a[4].(*uuid.UUID); !ok || p == nil || *p != org {
			t.Fatalf("org = %v", a[4])
		}
		if p, ok := a[6].(*string); !ok || p == nil || *p != "org" {
			t.Fatalf("target kind = %v", a[6])
		}
		if p, ok := a[7].(*uuid.UUID); !ok || p == nil || *p != target {
			t.Fatalf("target id = %v", a[7])
		}
		if p, ok := a[8].(*netip.Addr); !ok || p == nil || p.String() != "203.0.113.7" {
			t.Fatalf("ip = %v", a[8])
		}
		if p, ok := a[9].(*string); !ok || p == nil || *p != "curl/8" {
			t.Fatalf("user agent = %v", a[9])
		}
		stored, ok := a[10].([]byte)
		if !ok || string(stored) != `{"handle":"acme","request_id":"req-42"}` {
			t.Fatalf("detail = %s, want the caller's keys plus the request id", a[10])
		}
		// The caller's map is theirs: the request id went into a copy.
		if len(detail) != 1 || detail["request_id"] != nil {
			t.Fatalf("the caller's detail map was changed: %v", detail)
		}
		rec := rs.recs[0]
		if rec.ID != id || !rec.OccurredAt.Equal(at) || rec.ActorKind != "user" || rec.Action != "org.create" || rec.TargetKind != "org" ||
			rec.ActorID == nil || *rec.ActorID != actor || rec.OrgID == nil || *rec.OrgID != org || rec.TargetID == nil || *rec.TargetID != target ||
			string(rec.Detail) != string(stored) || rec.IP != "203.0.113.7" || rec.UserAgent != "curl/8" || rec.RequestID != "req-42" {
			t.Fatalf("archive record = %+v does not match the stored row", rec)
		}
		// The partition is ensured once for the month, not on every write.
		if err := w.Write(rctx, q, e); err != nil {
			t.Fatal(err)
		}
		if len(db.ensures) != 1 || len(db.inserts) != 2 {
			t.Fatalf("after a second write: ensures %d inserts %d, want 1 and 2", len(db.ensures), len(db.inserts))
		}
	})

	t.Run("absent fields stay null and the detail is an empty object", func(t *testing.T) {
		w, db, rs, _, q := newWriter()
		if err := w.Write(ctx, q, Event{ActorKind: ActorSystem, Action: ActionAuditPrune}); err != nil {
			t.Fatal(err)
		}
		a := db.inserts[0]
		if p, ok := a[2].(*uuid.UUID); !ok || p != nil {
			t.Fatalf("actor = %#v, want a null", a[2])
		}
		if p, ok := a[4].(*uuid.UUID); !ok || p != nil {
			t.Fatalf("org = %#v, want a null", a[4])
		}
		if p, ok := a[6].(*string); !ok || p != nil {
			t.Fatalf("target kind = %#v, want a null", a[6])
		}
		if p, ok := a[7].(*uuid.UUID); !ok || p != nil {
			t.Fatalf("target id = %#v, want a null", a[7])
		}
		if p, ok := a[8].(*netip.Addr); !ok || p != nil {
			t.Fatalf("ip = %#v, want a null", a[8])
		}
		if p, ok := a[9].(*string); !ok || p != nil {
			t.Fatalf("user agent = %#v, want a null", a[9])
		}
		if string(a[10].([]byte)) != "{}" {
			t.Fatalf("detail = %s, want {} (no request id, no detail)", a[10])
		}
		rec := rs.recs[0]
		if rec.ActorID != nil || rec.OrgID != nil || rec.TargetID != nil || rec.IP != "" || rec.UserAgent != "" || rec.RequestID != "" || rec.TargetKind != "" {
			t.Fatalf("archive record carries absent fields: %+v", rec)
		}
	})

	t.Run("a request id the caller set is kept", func(t *testing.T) {
		w, db, rs, _, q := newWriter()
		rctx := logx.WithRequestID(ctx, "from-context")
		if err := w.Write(rctx, q, Event{ActorKind: ActorSystem, Action: ActionAuditPrune, Detail: map[string]any{"request_id": "mine"}}); err != nil {
			t.Fatal(err)
		}
		if got := string(db.inserts[0][10].([]byte)); got != `{"request_id":"mine"}` {
			t.Fatalf("detail = %s", got)
		}
		if rs.recs[0].RequestID != "from-context" {
			t.Fatalf("archive request id = %q, want the context's", rs.recs[0].RequestID)
		}
	})

	t.Run("a detail with no request in context gets no request id", func(t *testing.T) {
		w, db, _, _, q := newWriter()
		if err := w.Write(ctx, q, Event{ActorKind: ActorSystem, Action: ActionAuditPrune, Detail: map[string]any{"k": "v"}}); err != nil {
			t.Fatal(err)
		}
		if got := string(db.inserts[0][10].([]byte)); got != `{"k":"v"}` {
			t.Fatalf("detail = %s", got)
		}
	})

	t.Run("the user agent is stored up to 512 bytes and archived whole", func(t *testing.T) {
		for _, c := range []struct{ n, stored int }{{511, 511}, {512, 512}, {513, 512}, {2000, 512}} {
			w, db, rs, _, q := newWriter()
			ua := strings.Repeat("a", c.n)
			if err := w.Write(ctx, q, Event{ActorKind: ActorSystem, Action: ActionAuditPrune, UserAgent: ua}); err != nil {
				t.Fatal(err)
			}
			if got := *db.inserts[0][9].(*string); got != ua[:c.stored] {
				t.Errorf("a %d-byte user agent was stored as %d bytes, want %d", c.n, len(got), c.stored)
			}
			if rs.recs[0].UserAgent != ua {
				t.Errorf("the archive record's user agent is %d bytes, want the whole %d", len(rs.recs[0].UserAgent), c.n)
			}
		}
	})

	t.Run("a detail that cannot be encoded fails the write", func(t *testing.T) {
		w, db, rs, _, q := newWriter()
		err := w.Write(ctx, q, Event{ActorKind: ActorSystem, Action: ActionAuditPrune, Detail: map[string]any{"bad": make(chan int)}})
		if err == nil || !strings.Contains(err.Error(), "audit: detail marshal") {
			t.Fatalf("err = %v", err)
		}
		if len(db.inserts)+len(rs.recs) != 0 {
			t.Fatal("an unencodable event was stored or archived")
		}
	})

	t.Run("a refused insert fails the write, is logged, and is never archived", func(t *testing.T) {
		w, db, rs, logbuf, q := newWriter()
		boom := errors.New("disk on fire")
		db.insertError = boom
		err := w.Write(ctx, q, Event{ActorKind: ActorSystem, Action: ActionAuditPrune})
		if err == nil || !errors.Is(err, boom) || !strings.Contains(err.Error(), "audit: insert") {
			t.Fatalf("err = %v, want the insert error wrapped", err)
		}
		if len(rs.recs) != 0 {
			t.Fatal("the archive got an event the database refused")
		}
		l := line(t, logbuf)
		if l["msg"] != "audit write failed" || l["action"] != "audit.prune" || l["level"] != "ERROR" || !strings.Contains(fmt.Sprint(l["err"]), "disk on fire") {
			t.Fatalf("log line = %v", l)
		}
	})

	t.Run("a writer built with no logger logs to the default", func(t *testing.T) {
		prev := slog.Default()
		var defbuf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewJSONHandler(&defbuf, nil)))
		t.Cleanup(func() { slog.SetDefault(prev) })
		w := NewWriter(nil)
		db := &fakeDB{insertError: errors.New("refused")}
		if err := w.Write(ctx, storegen.New(db), Event{ActorKind: ActorSystem, Action: ActionAuditPrune}); err == nil {
			t.Fatal("want the insert error")
		}
		if !strings.Contains(defbuf.String(), "audit write failed") {
			t.Fatalf("default logger got %q", defbuf.String())
		}
	})

	t.Run("a refused partition fails the write and is retried, not remembered", func(t *testing.T) {
		w, db, rs, _, q := newWriter()
		boom := errors.New("no partition for you")
		db.ensureError = boom
		err := w.Write(ctx, q, Event{ActorKind: ActorSystem, Action: ActionAuditPrune})
		if err == nil || !errors.Is(err, boom) || !strings.Contains(err.Error(), "audit: ensure partition") {
			t.Fatalf("err = %v", err)
		}
		if len(db.inserts)+len(rs.recs) != 0 {
			t.Fatal("an event was stored without its partition")
		}
		db.ensureError = nil
		if err := w.Write(ctx, q, Event{ActorKind: ActorSystem, Action: ActionAuditPrune}); err != nil {
			t.Fatal(err)
		}
		if len(db.ensures) != 2 || len(db.inserts) != 1 {
			t.Fatalf("ensures %d inserts %d, want the failed call retried (2) then one insert", len(db.ensures), len(db.inserts))
		}
	})

	t.Run("a partition is ensured once per month", func(t *testing.T) {
		w, db, _, _, q := newWriter()
		oct := time.Date(2026, time.October, 31, 23, 0, 0, 0, time.UTC)
		nov := time.Date(2026, time.November, 1, 0, 30, 0, 0, time.UTC)
		for _, at := range []time.Time{oct, oct.Add(time.Minute), nov, nov.Add(time.Hour), oct} {
			if err := w.ensureMonth(ctx, q, at); err != nil {
				t.Fatal(err)
			}
		}
		if len(db.ensures) != 2 {
			t.Fatalf("%d partition calls for two months, want 2", len(db.ensures))
		}
		if d := db.ensures[1][0].(pgtype.Date); d.Time.Month() != time.November {
			t.Fatalf("second partition = %v, want November", d.Time)
		}
	})
}

// The action catalog is append-only: every id the source declares is
// registered and unique, the ids published so far are all still there, an
// unknown id is refused, and an extension can add its own but never take over
// a core one.
func TestActionRegistryIsAppendOnly(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "actions.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Action" {
			return true
		}
		for i, v := range vs.Values {
			lit, ok := v.(*ast.BasicLit)
			if !ok {
				continue
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			if prev, dup := declared[val]; dup {
				t.Errorf("action id %q is declared twice (%s and %s)", val, prev, vs.Names[i].Name)
			}
			declared[val] = vs.Names[i].Name
		}
		return true
	})
	shape := regexp.MustCompile(`^[a-z_]+\.[a-z_]+$`)
	for val, name := range declared {
		if !shape.MatchString(val) {
			t.Errorf("%s = %q is not <area>.<verb> lowercase", name, val)
		}
		if !Registered(Action(val)) {
			t.Errorf("%s (%q) is declared but not in the registry", name, val)
		}
	}
	// The ids already written into audit rows and archives: none may be
	// renamed, removed or reused.
	for _, id := range []string{
		"user.register",
		"user.login",
		"user.login_failed",
		"user.logout",
		"user.email_verified",
		"user.update",
		"user.totp_enabled",
		"user.trusted_device_add",
		"user.trusted_device_revoke",
		"user.trusted_device_use",
		"pat.create",
		"pat.revoke",
		"ssh_key.add",
		"ssh_key.remove",
		"user.directory_erase",
		"user.staff_sync",
		"user.delete",
		"user.data_clear",
		"org.create",
		"org.update",
		"org.member_set",
		"org.member_remove",
		"org.invite_create",
		"org.invite_revoke",
		"org.invite_accept",
		"org.member_decline",
		"org.logo_set",
		"org.logo_removed",
		"org.knowledge_create",
		"org.knowledge_update",
		"org.knowledge_delete",
		"org.knowledge_export",
		"org.knowledge_ship",
		"org.member_pending",
		"org.decommission",
		"org.erase",
		"org.suspend",
		"org.reinstate",
		"org.access_request",
		"team.create",
		"team.delete",
		"team.member_add",
		"team.member_remove",
		"agent.create",
		"agent.update",
		"agent.grant_set",
		"agent.grant_remove",
		"repo.push",
		"version.submit",
		"version.transition",
		"version.yank",
		"review.decision",
		"finding.verdict",
		"policy.update",
		"agent.quarantine",
		"agent.block",
		"agent.reinstate",
		"advisory.publish",
		"agent.dependency_alert",
		"ruleset.release",
		"abuse.report",
		"abuse.triage",
		"sso.connection_set",
		"sso.connection_delete",
		"sso.login",
		"scim.token_create",
		"scim.token_revoke",
		"scim.user_provision",
		"scim.user_deactivate",
		"scim.group_sync",
		"webhook.create",
		"webhook.update",
		"webhook.delete",
		"domain.claim",
		"domain.verified",
		"audit.export",
		"agent.star",
		"agent.unstar",
		"agent.install",
		"agent.uninstall",
		"agent.delete",
		"agent.retire",
		"agent.restore",
		"agent.fork",
		"agent.transfer",
		"webhook.ping",
		"audit.platform_read",
		"audit.prune",
		"user.social_login",
	} {
		if _, ok := declared[id]; !ok {
			t.Errorf("published action id %q is no longer declared", id)
		}
		if !Registered(Action(id)) {
			t.Errorf("published action id %q is not registered", id)
		}
	}
	if Registered(Action("nope.nothing")) || Registered(Action("")) {
		t.Fatal("an unknown or empty action is registered")
	}

	// Unique per run: the registry is process-wide and the test may repeat.
	ext := Action(fmt.Sprintf("probe.extension_%d", time.Now().UnixNano()))
	if Registered(ext) {
		t.Fatal("the probe action must start unregistered")
	}
	if !Register(ext) || !Registered(ext) {
		t.Fatal("a new action must register")
	}
	if Register(ext) {
		t.Fatal("registering an action twice must report false")
	}
	if Register(ActionUserLogin) || !Registered(ActionUserLogin) {
		t.Fatal("an extension must not be able to re-register a core action")
	}
}
