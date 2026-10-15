package auth

import "context"

type clientIPKeyType struct{}

// WithClientIP records the caller's resolved address on the context. The
// API middleware sets it exactly once, after the X-Forwarded-For trust
// decision, so every consumer — rate limiting, audit, the registry's
// IP-cluster hash — sees the same value.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKeyType{}, ip)
}

// ClientIPFrom returns the address WithClientIP recorded, or "".
func ClientIPFrom(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKeyType{}).(string)
	return ip
}
