package api

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/blaktron/agentry/internal/webhook"
)

// validateOIDCIssuer judges an issuer URL an organization admin supplies
// before it is stored, with the same policy the egress guard applies at dial
// time: the registry will fetch this address on the admin's say-so, and an
// org admin is any account with a verified email (security review
// 2026-09-20 §5.8.1). https to a public host, nothing else in the URL. The
// guard's AllowLoopback (dev mode) is the one allowance: a loopback IdP,
// which may be plain http, for a development stack.
//
// A hostname is judged again when it resolves — this check refuses what can
// be refused from the string alone, so a private address is never stored.
func validateOIDCIssuer(issuer string, g webhook.Guard) error {
	u, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return errors.New("the issuer must be an absolute https URL naming the IdP's host")
	}
	if u.User != nil {
		return errors.New("the issuer must not carry credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return errors.New("the issuer must not carry a query or a fragment: discovery appends /.well-known/openid-configuration to it")
	}
	host := u.Hostname()
	loopbackName := host == "localhost" || strings.HasSuffix(host, ".localhost")
	ip, isIP := parseHostIP(host)
	loopback := loopbackName || (isIP && ip.Unmap().IsLoopback())
	switch u.Scheme {
	case "https":
	case "http":
		if !g.AllowLoopback || !loopback {
			return errors.New("the issuer must use https")
		}
	default:
		return errors.New("the issuer must use https")
	}
	if loopback && !g.AllowLoopback {
		return errors.New("the issuer must name a public host, not this machine")
	}
	if isIP && !g.IsAllowedIP(ip) {
		return errors.New("the issuer must name a public host: private, link-local and local ranges are never fetched")
	}
	return nil
}

func parseHostIP(host string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}

// oidcStatusLine matches the shape go-oidc gives a non-200 discovery answer:
// "<status line>: <body>". The body is what an internal endpoint would have
// told the admin, so the summary keeps the status and drops the rest.
var oidcStatusLine = regexp.MustCompile(`(?s)\b(\d{3} [A-Za-z][A-Za-z \-]*?): `)

// oidcFailureSummary turns a discovery error into what the admin may learn:
// that the address was refused, that it could not be reached, or the status
// it answered — never the response body, and never more than a line.
func oidcFailureSummary(issuer string, err error) string {
	var blocked *webhook.ErrBlockedAddress
	if errors.As(err, &blocked) {
		return fmt.Sprintf("discovery against %s failed: the issuer resolves to a non-public address, which the registry never fetches", issuer)
	}
	msg := err.Error()
	if m := oidcStatusLine.FindStringSubmatch(msg); m != nil {
		return fmt.Sprintf("discovery against %s failed: the issuer answered %s to the discovery request", issuer, m[1])
	}
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return fmt.Sprintf("discovery against %s failed: %s", issuer, msg)
}
