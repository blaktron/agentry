package audit

// The continuous audit stream (§12.6): "every … action → audit_events
// (partitioned) AND streamed to S3 (Firehose on SaaS; file/S3 writer
// self-host) as NDJSON within ~1 min".
//
// Two sinks, one guarantee ordering. audit_events is the system of record: a
// failed insert fails the mutation (see Writer.Write). The stream is the
// ARCHIVE — it is what survives partition pruning (§4.3) and what an auditor
// reads years later — so it is fed best-effort and never blocks a request. A
// full buffer drops and logs rather than stalling the API, because an audit
// archive that can wedge the write path is a denial-of-service surface, not a
// control.
//
// One consequence is worth stating plainly: events are handed to the stream
// by the writer, not by a committed-transaction tailer, so a mutation that
// rolls back AFTER its audit insert can leave a line in the archive with no
// matching hot row. That direction is deliberate — an archive with an extra
// "attempted" line is auditable; one missing a line is not.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/logx"
)

// Stream is the NDJSON archive sink.
type Stream interface {
	// Append queues one record. It never blocks and never returns an error:
	// callers are on the request path.
	Append(rec Record)
	// Flush writes everything queued so far.
	Flush(ctx context.Context) error
	// Close flushes and releases the sink.
	Close() error
}

// Record is one NDJSON line. Field names match the API's AuditEvent shape so
// the archive and the API describe events identically. The three fields the
// API does not carry — the caller's address and agent, and the request the
// event happened in — are on the row and reach the `log` sink; the file
// archive keeps the API's shape.
type Record struct {
	ID         uuid.UUID       `json:"id"`
	OccurredAt time.Time       `json:"occurredAt"`
	ActorID    *uuid.UUID      `json:"actorId,omitempty"`
	ActorKind  string          `json:"actorKind"`
	OrgID      *uuid.UUID      `json:"orgId,omitempty"`
	Action     string          `json:"action"`
	TargetKind string          `json:"targetKind,omitempty"`
	TargetID   *uuid.UUID      `json:"targetId,omitempty"`
	Detail     json.RawMessage `json:"detail,omitempty"`
	IP         string          `json:"-"`
	UserAgent  string          `json:"-"`
	RequestID  string          `json:"-"`
}

// NewStream builds the configured sink (§12.6). An unconfigured or
// unsupported kind yields a no-op sink and a log line — a self-host operator
// who has not set up archival still gets a working registry.
func NewStream(kind, dir, s3Bucket string, flush time.Duration, log *slog.Logger) Stream {
	if log == nil {
		log = slog.Default()
	}
	switch kind {
	case "", "none":
		return NopStream{}
	case "log":
		return NewLogStream(log)
	case "file":
		st, err := NewFileStream(dir, flush, log)
		if err != nil {
			log.Error("audit stream: file sink unavailable, archiving disabled", "dir", dir, "err", err)
			return NopStream{}
		}
		return st
	case "s3":
		// NewS3Stream is a stub that always refuses; it owns the message.
		_, err := NewS3Stream(s3Bucket, flush, log)
		log.Error("audit stream: s3 sink unavailable, archiving disabled", "err", err)
		return NopStream{}
	default:
		log.Error("audit stream: unknown kind, archiving disabled", "kind", kind)
		return NopStream{}
	}
}

// LogStream mirrors every record as one line on the server's logger —
// `event=audit.<action>` with the record's fields — so an audit event is
// searchable wherever the server's lines are shipped (plan log-stack.md §5.4,
// DEV-020 addendum). It is a mirror: the row in audit_events remains the
// record, and the file archive keeps its own shape. The write is
// synchronous — one line on stderr, microseconds — so there is no buffer and
// therefore no drop path of its own; what happens to the line after that is
// the log shipping's business, which is best-effort by design.
type LogStream struct{ log *slog.Logger }

// NewLogStream builds the mirror on log (nil means the default logger).
func NewLogStream(log *slog.Logger) LogStream {
	if log == nil {
		log = slog.Default()
	}
	return LogStream{log: log}
}

// Append implements Stream.
func (ls LogStream) Append(rec Record) {
	attrs := []slog.Attr{
		logevent.Audit(rec.Action).Attr(),
		slog.String("audit_id", rec.ID.String()),
		slog.Time("occurred_at", rec.OccurredAt),
		slog.String("actor_kind", rec.ActorKind),
	}
	if rec.ActorID != nil {
		attrs = append(attrs, slog.String("actor", rec.ActorID.String()))
	}
	if rec.OrgID != nil {
		attrs = append(attrs, slog.String("org", rec.OrgID.String()))
	}
	if rec.TargetKind != "" {
		attrs = append(attrs, slog.String("target_kind", rec.TargetKind))
	}
	if rec.TargetID != nil {
		attrs = append(attrs, slog.String("target_id", rec.TargetID.String()))
	}
	if rec.IP != "" {
		attrs = append(attrs, slog.String("client_ip", rec.IP))
	}
	if rec.UserAgent != "" {
		attrs = append(attrs, slog.String("user_agent", rec.UserAgent))
	}
	if rec.RequestID != "" {
		attrs = append(attrs, slog.String(logx.RequestIDKey, rec.RequestID))
	}
	if len(rec.Detail) > 0 && string(rec.Detail) != "{}" {
		// As an object, so the contract's sanitiser walks it; the raw text
		// only if the record's own JSON does not parse.
		var detail map[string]any
		if err := json.Unmarshal(rec.Detail, &detail); err == nil {
			attrs = append(attrs, slog.Any("detail", detail))
		} else {
			attrs = append(attrs, slog.String("detail", string(rec.Detail)))
		}
	}
	ls.log.LogAttrs(context.Background(), slog.LevelInfo, "audit", attrs...)
}

// Flush implements Stream: every line is written as it is appended.
func (LogStream) Flush(context.Context) error { return nil }

// Close implements Stream.
func (LogStream) Close() error { return nil }

// NopStream discards records (archiving disabled).
type NopStream struct{}

// Append implements Stream.
func (NopStream) Append(Record) {}

// Flush implements Stream.
func (NopStream) Flush(context.Context) error { return nil }

// Close implements Stream.
func (NopStream) Close() error { return nil }

// NewS3Stream is the SaaS sink (§12.6 "Firehose on SaaS"). Not built here:
// the deployment that needs it is the same one that provisions the delivery
// stream, and a half-written client that silently drops records would be
// worse than an explicit refusal at startup. Recorded as a deviation.
func NewS3Stream(bucket string, _ time.Duration, _ *slog.Logger) (Stream, error) {
	return nil, fmt.Errorf("audit: s3 stream is not configured in this build (bucket %q); "+
		"use streamKind=file, or the Firehose delivery stream on SaaS", bucket)
}

// ---- file sink ----

// FileStream appends NDJSON to one file per UTC day in a directory.
type FileStream struct {
	// OnDrop, when set, is called for every record dropped on a full buffer
	// (agentry#33: the metrics layer counts it as a fail-open event).
	OnDrop func()
	dir    string
	log    *slog.Logger
	flush  time.Duration

	// mu guards buf and the file/day pair; wmu serializes whole flushes so two
	// concurrent flushers cannot interleave half-written JSON lines.
	mu   sync.Mutex
	wmu  sync.Mutex
	buf  []Record
	f    *os.File
	day  string
	done chan struct{}
	once sync.Once
}

// fileStreamBufferMax bounds memory when the disk is slow or wedged. Past it
// records are dropped with a log line (see the package comment).
const fileStreamBufferMax = 8192

// NewFileStream opens (creating as needed) the archive directory and starts
// the background flusher.
func NewFileStream(dir string, flush time.Duration, log *slog.Logger) (*FileStream, error) {
	if dir == "" {
		return nil, fmt.Errorf("audit: file stream needs a directory")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("audit: file stream dir: %w", err)
	}
	if flush <= 0 {
		flush = 30 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	fs := &FileStream{dir: dir, log: log, flush: flush, done: make(chan struct{})}
	go fs.loop()
	return fs, nil
}

// Append implements Stream.
func (fs *FileStream) Append(rec Record) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.buf) >= fileStreamBufferMax {
		fs.log.Error("audit stream: buffer full, dropping record", logevent.FailOpenAuditStreamDrop.Attr(), "action", rec.Action, "id", rec.ID)
		if fs.OnDrop != nil {
			fs.OnDrop()
		}
		return
	}
	fs.buf = append(fs.buf, rec)
}

// Flush implements Stream.
func (fs *FileStream) Flush(context.Context) error {
	fs.wmu.Lock()
	defer fs.wmu.Unlock()
	fs.mu.Lock()
	pending := fs.buf
	fs.buf = nil
	fs.mu.Unlock()
	if len(pending) == 0 {
		return nil
	}
	f, err := fs.fileFor(time.Now().UTC())
	if err != nil {
		// Put the records back so a transient failure (a full disk that is
		// then cleared) does not lose them.
		fs.mu.Lock()
		fs.buf = append(pending, fs.buf...)
		fs.mu.Unlock()
		return err
	}
	enc := json.NewEncoder(f)
	for _, rec := range pending {
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("audit: stream encode: %w", err)
		}
	}
	return f.Sync()
}

// fileFor returns the handle for day t, rotating at the UTC date boundary.
func (fs *FileStream) fileFor(t time.Time) (*os.File, error) {
	day := t.Format("20060102")
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.f != nil && fs.day == day {
		return fs.f, nil
	}
	if fs.f != nil {
		_ = fs.f.Close()
		fs.f = nil
	}
	path := filepath.Join(fs.dir, "audit-"+day+".ndjson")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	fs.f, fs.day = f, day
	return f, nil
}

func (fs *FileStream) loop() {
	t := time.NewTicker(fs.flush)
	defer t.Stop()
	for {
		select {
		case <-fs.done:
			return
		case <-t.C:
			if err := fs.Flush(context.Background()); err != nil {
				fs.log.Error("audit stream flush", "err", err)
			}
		}
	}
}

// Close implements Stream.
func (fs *FileStream) Close() error {
	fs.once.Do(func() { close(fs.done) })
	err := fs.Flush(context.Background())
	fs.wmu.Lock()
	defer fs.wmu.Unlock()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.f != nil {
		if cerr := fs.f.Close(); err == nil {
			err = cerr
		}
		fs.f = nil
	}
	return err
}
