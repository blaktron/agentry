// Package dnsx abstracts DNS TXT lookups behind an interface so domain
// verification (§12.4) is testable with an injected fake resolver. The
// production implementation uses net.Resolver.
package dnsx

import (
	"context"
	"net"
	"strings"
)

// Resolver looks up TXT records for a name. net.Resolver satisfies a superset
// of this; SystemResolver adapts it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// SystemResolver is the production Resolver backed by the OS resolver.
type SystemResolver struct{}

// NewSystemResolver returns a Resolver using net.DefaultResolver.
func NewSystemResolver() SystemResolver { return SystemResolver{} }

// LookupTXT implements Resolver.
func (SystemResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// TXTName is the record name a domain must publish for verification. Agentry
// looks up a dedicated subdomain so the org's apex TXT records are untouched.
func TXTName(domain string) string {
	return "_agentry-challenge." + strings.ToLower(strings.TrimSuffix(domain, "."))
}

// VerifyTXT reports whether the verification token is present in any TXT record
// at TXTName(domain). Tokens are matched exactly (after trimming) and may be
// carried verbatim or as "agentry-domain-verification=<token>".
func VerifyTXT(ctx context.Context, r Resolver, domain, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	records, err := r.LookupTXT(ctx, TXTName(domain))
	if err != nil {
		// A missing record set (NXDOMAIN / no TXT) is "not verified", not a
		// hard error — the caller reports "not verified yet".
		var dnsErr *net.DNSError
		if ok := asDNSNotFound(err, &dnsErr); ok {
			return false, nil
		}
		return false, err
	}
	want := strings.TrimSpace(token)
	prefixed := "agentry-domain-verification=" + want
	for _, rec := range records {
		got := strings.TrimSpace(rec)
		if got == want || got == prefixed {
			return true, nil
		}
	}
	return false, nil
}

func asDNSNotFound(err error, target **net.DNSError) bool {
	if de, ok := err.(*net.DNSError); ok {
		*target = de
		return de.IsNotFound
	}
	return false
}
