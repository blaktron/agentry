// Package logx is the mechanism behind the log contract (docs/logging.md,
// plan log-stack.md §5): the request id carried in a context, the handler
// that stamps it on every line written under that context, and the
// sanitiser that keeps tokens and secrets out of a line and keeps a line
// below the size at which Docker splits it.
//
// The vocabulary — the `event` names a line may carry — lives in
// internal/logevent; this package knows nothing about what is logged, only
// how.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// RequestIDKey is the attribute every line written under a request carries.
const RequestIDKey = "request_id"

// MaxStringLen bounds any string attribute. Docker splits a log line above
// 16 KB into 16,384-byte pieces that are no longer JSON and that nothing
// downstream can reassemble (measured, plan log-stack.md §5.2a); a line
// whose largest value is 4 KB stays well under that with room for the rest
// of its fields.
const MaxStringLen = 4096

// Redacted replaces a value under a secret-named key.
const Redacted = "[redacted]"

// truncatedMarker follows a value cut at MaxStringLen.
const truncatedMarker = "…[truncated]"

// tokenRE matches every token kind the registry mints (internal/auth:
// `agy_` PATs, `agys_` sessions, `agyv_` verification tokens, each followed
// by 52 lowercase base32 characters). The 12-character display prefix a PAT
// is identified by is shorter than this and stays.
var tokenRE = regexp.MustCompile(`(?i)\bagy[sv]?_[a-z2-7]{52}\b`)

// tokenDisplayLen mirrors auth.PATDisplayPrefixLen: what survives a mask so
// an incident can still be traced to the credential.
const tokenDisplayLen = 12

// secretKeySuffixes are the attribute-key endings (compared case-insensitively)
// under which a value is never written. Bare "key" is deliberately absent:
// object keys, public keys and host-key fingerprints are legitimate log
// content; the specific secret kinds are listed instead.
var secretKeySuffixes = []string{
	"token", "secret", "password", "passwd", "authorization", "cookie",
	"api_key", "apikey", "private_key", "signing_key", "secret_key", "access_key",
	"client_secret", "credential", "credentials",
}

type ctxKey struct{}

// WithRequestID returns ctx carrying the request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestIDFrom returns the request id carried by ctx, or "".
func RequestIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// Options configure New.
type Options struct {
	// Level is the minimum level: debug, info (the default), warn, error.
	Level string
	// Service, Role and Version are stamped on every line (§5 of the plan):
	// the binary's name, the role it runs, the build.
	Service, Role, Version string
	// W is where lines go; nil means os.Stderr.
	W io.Writer
}

// New builds the contract's logger: JSON, one line per record, every
// attribute sanitised, the request id from the context on every line, the
// service identity on every line.
func New(o Options) *slog.Logger {
	w := o.W
	if w == nil {
		w = os.Stderr
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: ParseLevel(o.Level), ReplaceAttr: Sanitize})
	log := slog.New(Handler{h})
	var attrs []any
	if o.Service != "" {
		attrs = append(attrs, "service", o.Service)
	}
	if o.Role != "" {
		attrs = append(attrs, "role", o.Role)
	}
	if o.Version != "" {
		attrs = append(attrs, "version", o.Version)
	}
	if len(attrs) > 0 {
		log = log.With(attrs...)
	}
	return log
}

// ParseLevel maps the config's level names onto slog's; anything unknown is
// info, which is what the config's default has always meant.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Handler stamps the context's request id on every record it handles. It
// wraps any slog.Handler; the wrapped handler's ReplaceAttr still sees the
// stamped attribute, so a request id is sanitised like everything else.
type Handler struct{ slog.Handler }

// Handle implements slog.Handler.
func (h Handler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestIDFrom(ctx); id != "" {
		r.AddAttrs(slog.String(RequestIDKey, id))
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (h Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return Handler{h.Handler.WithAttrs(attrs)}
}

// WithGroup implements slog.Handler.
func (h Handler) WithGroup(name string) slog.Handler { return Handler{h.Handler.WithGroup(name)} }

// Sanitize is the ReplaceAttr of the contract's handler: a value under a
// secret-named key is replaced, every string is masked of token-shaped
// substrings and cut at MaxStringLen, and both rules recurse into groups,
// maps, slices and errors. Masked, never dropped: a line about an incident
// is worth more than the value it would have leaked.
func Sanitize(_ []string, a slog.Attr) slog.Attr {
	if a.Key == "" && a.Value.Kind() != slog.KindGroup {
		return a
	}
	if isSecretKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	a.Value = sanitizeValue(a.Value)
	return a
}

func isSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range secretKeySuffixes {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

func sanitizeValue(v slog.Value) slog.Value {
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(sanitizeString(v.String()))
	case slog.KindGroup:
		attrs := v.Group()
		out := make([]slog.Attr, 0, len(attrs))
		for _, a := range attrs {
			out = append(out, Sanitize(nil, a))
		}
		return slog.GroupValue(out...)
	case slog.KindAny:
		return slog.AnyValue(sanitizeAny(v.Any()))
	default:
		return v
	}
}

// sanitizeAny walks the shapes slog serialises as JSON objects: maps,
// slices, errors, Stringers. Anything else is left to the encoder.
func sanitizeAny(x any) any {
	switch t := x.(type) {
	case nil:
		return nil
	case string:
		return sanitizeString(t)
	case error:
		return sanitizeString(t.Error())
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			if isSecretKey(k) {
				out[k] = Redacted
				continue
			}
			out[k] = sanitizeAny(v)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(t))
		for k, v := range t {
			if isSecretKey(k) {
				out[k] = Redacted
				continue
			}
			out[k] = sanitizeString(v)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, v := range t {
			out[i] = sanitizeAny(v)
		}
		return out
	case []string:
		out := make([]any, len(t))
		for i, v := range t {
			out[i] = sanitizeString(v)
		}
		return out
	case fmt.Stringer:
		return sanitizeString(t.String())
	default:
		return x
	}
}

func sanitizeString(s string) string {
	s = MaskTokens(s)
	if len(s) > MaxStringLen {
		s = s[:MaxStringLen] + truncatedMarker
	}
	return s
}

// MaskEmail keeps the first character of the local part and the domain:
// enough to tell which mailbox a line is about, not enough to be an address
// of a person (docs/logging.md: none in a line the contract adds).
func MaskEmail(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 {
		return "…"
	}
	return addr[:1] + "…" + addr[at:]
}

// MaskTokens replaces every token-shaped substring with its display prefix
// and a marker. Exported for the tests of things that must never log one.
func MaskTokens(s string) string {
	if !strings.Contains(strings.ToLower(s), "agy") {
		return s
	}
	return tokenRE.ReplaceAllStringFunc(s, func(m string) string {
		return m[:tokenDisplayLen] + "…" + Redacted
	})
}
