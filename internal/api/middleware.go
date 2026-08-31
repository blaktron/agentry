package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/metrics"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	actorKey
	clientIPKey
)

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

// routeClass reduces a request to the low-cardinality label the §16.2 RED
// metrics are broken down by.
//
// Go 1.22 routing exposes the matched pattern on the request, which is exactly
// the right granularity: "/api/v1/agents/{ns}/{name}" rather than the concrete
// path. Using the raw path would let any caller mint unbounded time series by
// varying a segment — a metrics-cardinality DoS, and a slow one to diagnose.
// An unmatched request reports "other" for the same reason.
func routeClass(r *http.Request) string {
	if p := r.Pattern; p != "" {
		// The pattern carries the method ("GET /path"); the method is already
		// its own label, so keep only the path half.
		if i := strings.IndexByte(p, ' '); i >= 0 {
			p = p[i+1:]
		}
		return p
	}
	return "other"
}

// withMiddleware wraps the router with the always-on middleware stack:
// request id → panic recovery → security headers → access log → RED metrics.
// AuthN/AuthZ middleware is added per-route-group in M1 (§12).
//
// mx is a getter rather than a value so SetMetrics can be called after the
// handler is assembled: binding the instrument set at construction time would
// make the RED metrics silently depend on wiring order.
// trustedProxies is the configured hop count; see clientIPWithProxies.
func withMiddleware(next http.Handler, log *slog.Logger, mx func() *metrics.Metrics, trustedProxies int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		var buf [8]byte
		_, _ = rand.Read(buf[:])
		reqID := hex.EncodeToString(buf[:])
		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		actor := &actorHolder{}
		ctx = context.WithValue(ctx, actorKey, actor)
		// Resolve the caller's address ONCE, here, so the rate limiter and the
		// audit log can never disagree about who made the request — and so
		// there is exactly one place where the X-Forwarded-For trust decision
		// is made.
		ctx = context.WithValue(ctx, clientIPKey, clientIPWithProxies(r, trustedProxies))
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
			elapsed := time.Since(start)
			// §16.2 RED. Recorded in the same defer as the access log so a
			// panicking handler is still counted — a 500 that never reaches
			// the availability metric is the one you most need to see.
			mx().RecordHTTP(r.Context(), routeClass(r), r.Method, sw.status, elapsed)

			// Access log: never log tokens/secrets (§16.2 lint rule); we log
			// method/path/status/duration/request id plus the resolved actor
			// ids, so an incident can be traced to a credential without the
			// credential ever appearing in the log.
			attrs := []any{
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"route", routeClass(r),
				"status", sw.status,
				"dur_ms", elapsed.Milliseconds(),
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
