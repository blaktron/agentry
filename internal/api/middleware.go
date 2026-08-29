package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	actorKey
)

// RequestID returns the request id assigned by middleware, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// actorHolder carries the resolved caller back OUT to the access log.
// principalMiddleware runs inside the generated handler and derives a new
// context, which the outer logging middleware never sees; a pointer placed in
// the outer context is the seam between them. Ids only — §16.2 forbids
// logging the credential itself.
type actorHolder struct {
	mu      sync.Mutex
	userID  string
	via     string
	patID   string
	handle  string
	present bool
}

func (h *actorHolder) set(userID, handle, via, patID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.userID, h.handle, h.via, h.patID, h.present = userID, handle, via, patID, true
}

// logAttrs renders the actor fields for one access-log line.
func (h *actorHolder) logAttrs() []any {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.present {
		return []any{"actor", "anonymous"}
	}
	out := []any{"actor", h.userID, "actor_via", h.via}
	if h.handle != "" {
		out = append(out, "actor_handle", h.handle)
	}
	if h.patID != "" {
		out = append(out, "actor_pat", h.patID)
	}
	return out
}

// recordActor stores the resolved principal for the access log.
func recordActor(ctx context.Context, p *auth.Principal) {
	h, _ := ctx.Value(actorKey).(*actorHolder)
	if h == nil || p == nil || p.Anonymous {
		return
	}
	patID := ""
	if p.PATID != uuid.Nil {
		patID = p.PATID.String()
	}
	h.set(p.UserID.String(), p.Handle, p.Via, patID)
}

// withMiddleware wraps the router with the always-on middleware stack:
// request id → panic recovery → security headers → access log.
// AuthN/AuthZ middleware is added per-route-group in M1 (§12).
func withMiddleware(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		var buf [8]byte
		_, _ = rand.Read(buf[:])
		reqID := hex.EncodeToString(buf[:])
		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		actor := &actorHolder{}
		ctx = context.WithValue(ctx, actorKey, actor)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-Id", reqID)

		// Baseline security headers (§10.3 hardening happens in web; the API
		// still never wants sniffing or framing).
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		defer func() {
			if rec := recover(); rec != nil {
				log.Error("panic in handler",
					"request_id", reqID, "path", r.URL.Path, "panic", rec,
					"stack", string(debug.Stack()))
				if !sw.wrote {
					problemInternal(sw, r)
				}
			}
			// Access log: never log tokens/secrets (§16.2 lint rule); we log
			// method/path/status/duration/request id plus the resolved actor
			// ids, so an incident can be traced to a credential without the
			// credential ever appearing in the log.
			attrs := []any{
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"dur_ms", time.Since(start).Milliseconds(),
			}
			log.Info("http", append(attrs, actor.logAttrs()...)...)
		}()

		next.ServeHTTP(sw, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}
