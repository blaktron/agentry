package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

type ctxKey int

const requestIDKey ctxKey = iota

// RequestID returns the request id assigned by middleware, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
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
			// only method/path/status/duration/request id.
			log.Info("http",
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"dur_ms", time.Since(start).Milliseconds(),
			)
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
