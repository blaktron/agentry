package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/logx"
	"github.com/blaktron/agentry/internal/metrics"
)

type ctxKey int

const actorKey ctxKey = iota

// requestIDHeader is minted per request and returned on every response; an
// inbound value is honoured under the same rule as the client address (see
// requestID).
const requestIDHeader = "X-Request-Id"

// inboundRequestIDRE bounds what an inbound id may look like. Deliberately
// wider than nginx's 32-hex `$request_id` (a hyphenated id from another
// proxy is fine) and narrow enough that nothing but an id fits: no spaces,
// no punctuation, nothing that could be read as a header or a log field.
var inboundRequestIDRE = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

// requestID returns the id this request is logged under. An inbound
// X-Request-Id is honoured only when the operator has said the hop in front
// sets it (http.proxyRequestID, which itself needs a trusted hop count), and
// only when it is well-formed. Anyone can send the header; a hop that merely
// forwards it would let a client stamp its own id onto the server's lines
// and audit rows, so the trusted hop count alone is not enough (the review
// of agentry#328 caught exactly that). Otherwise the server mints its own.
// (plan log-stack.md §5.1, D19)
func requestID(r *http.Request, honourInbound bool) string {
	if honourInbound {
		if v := r.Header.Get(requestIDHeader); v != "" && inboundRequestIDRE.MatchString(v) {
			return v
		}
	}
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// accessLogSkipped are the probes: scraped and polled every few seconds,
// they would be most of the access log and none of its information.
var accessLogSkipped = map[string]bool{"/healthz": true, "/readyz": true, "/metrics": true}

// actorHolder carries the resolved caller back OUT to the access log.
// principalMiddleware runs inside the generated handler and derives a new
// context, which the outer logging middleware never sees; a pointer placed in
// the outer context is the seam between them. Opaque ids only — never the
// credential (§16.2), and never the handle: a line carries no name of a
// person (docs/logging.md).
type actorHolder struct {
	mu      sync.Mutex
	userID  string
	via     string
	patID   string
	present bool
}

func (h *actorHolder) set(userID, via, patID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.userID, h.via, h.patID, h.present = userID, via, patID, true
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
	h.set(p.UserID.String(), p.Via, patID)
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
func withMiddleware(next http.Handler, log *slog.Logger, mx func() *metrics.Metrics, trustedProxies int, proxyRequestID bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		reqID := requestID(r, proxyRequestID && trustedProxies > 0)
		// The id rides the context (internal/logx): every line written under
		// it — and the audit row — carries it without naming it.
		ctx := logx.WithRequestID(r.Context(), reqID)
		actor := &actorHolder{}
		ctx = context.WithValue(ctx, actorKey, actor)
		// Resolve the caller's address ONCE, here, so the rate limiter and the
		// audit log can never disagree about who made the request — and so
		// there is exactly one place where the X-Forwarded-For trust decision
		// is made.
		ctx = auth.WithClientIP(ctx, clientIPWithProxies(r, trustedProxies))
		r = r.WithContext(ctx)
		w.Header().Set(requestIDHeader, reqID)

		// Baseline security headers (§10.3 hardening happens in web; the API
		// still never wants sniffing or framing).
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		defer func() {
			if rec := recover(); rec != nil {
				log.ErrorContext(ctx, "panic in handler",
					"path", r.URL.Path, "panic", rec,
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

			// The access line (docs/logging.md): method, path, the matched
			// route, status, duration, bytes, the caller's address and agent,
			// and the resolved actor ids — never the credential, so an
			// incident traces to a PAT without the PAT ever being in a line.
			// The request id comes from the context via the logx handler.
			// The probes are skipped: they would be most of the log and none
			// of its information (their metrics are still recorded above).
			if accessLogSkipped[r.URL.Path] {
				return
			}
			attrs := []any{
				logevent.HTTPRequest.Attr(),
				"method", r.Method,
				"path", r.URL.Path,
				"route", routeClass(r),
				"status", sw.status,
				"dur_ms", elapsed.Milliseconds(),
				"bytes", sw.bytes,
				"client_ip", auth.ClientIPFrom(ctx),
				"user_agent", r.UserAgent(),
			}
			log.InfoContext(ctx, "http", append(attrs, actor.logAttrs()...)...)
		}()

		next.ServeHTTP(sw, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
	bytes  int64
}

// Unwrap lets http.NewResponseController reach the underlying writer's
// Flush (server-sent events, agentry#65) and Hijack through this wrapper.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}
