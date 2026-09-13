package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
)

const (
	sessionCookieName = "agentry_session"
	// csrfCookieName is the CSRF cookie the site (agentry-web, lib/session.ts)
	// CSRF_COOKIE); the API sets it only in browser-mode sign-in, where no
	// JSON body carries the token (agentry#77).
	csrfCookieName = "agentry_csrf"
	csrfHeader     = "X-Agentry-CSRF"
)

type principalKeyType struct{}

var principalKey principalKeyType

// principalFrom returns the resolved principal (never nil after middleware).
func principalFrom(ctx context.Context) *auth.Principal {
	p, _ := ctx.Value(principalKey).(*auth.Principal)
	if p == nil {
		return &auth.Principal{Anonymous: true}
	}
	return p
}

// principalMiddleware resolves the caller: PAT bearer token, else session
// cookie (with CSRF enforcement on mutations), else anonymous. It also
// applies the per-class rate limits (§19) so every /api/v1 route is covered.
func (s *Server) principalMiddleware(next http.Handler) http.Handler {
	return s.principalMiddlewareOpts(next, principalOpts{})
}

// principalOpts narrows what the middleware does for one mount.
type principalOpts struct {
	// unthrottled is a set of "METHOD /full/path" keys the anonymous rate
	// class does not apply to (an extension's webhook receiver, whose only
	// credential is a signature and whose sender must never be throttled
	// into a lost event — plan subscription-tiers §5.5). The authed class
	// and everything else still apply.
	unthrottled map[string]bool
}

func (s *Server) principalMiddlewareOpts(next http.Handler, opts principalOpts) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &auth.Principal{Anonymous: true}

		// PATs: Authorization: Bearer agy_… (§9.1). Sessions are never
		// accepted from Authorization; PATs are never read from cookies.
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tok := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
			if auth.IsPAT(tok) {
				pp, err := s.resolvePAT(r, tok)
				if err != nil {
					problemUnauthorized(w, r, "This token is invalid or expired. Create a new token in account settings.")
					return
				}
				p = pp
			} else {
				problemUnauthorized(w, r, "The bearer token was not recognized.")
				return
			}
		} else if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			pp, csrf, err := s.resolveSession(r, c.Value)
			if err == nil {
				// CSRF: cookie-authenticated mutations must echo the token
				// (§9.1). GET/HEAD/OPTIONS are exempt.
				switch r.Method {
				case http.MethodGet, http.MethodHead, http.MethodOptions:
					p = pp
				default:
					if r.Header.Get(csrfHeader) == csrf && csrf != "" {
						p = pp
					} else {
						problemForbidden(w, r, "The CSRF token is missing or does not match this session. Reload the page and retry.")
						return
					}
				}
			}
			// Invalid session cookie degrades to anonymous (stale cookies
			// on public pages must not 401).
		}

		// Rate limiting by class. The §9.1 RateLimit-* headers are written on
		// every response, not only refusals, so a client can pace itself
		// before it is throttled.
		var res limitResult
		switch {
		case p.Anonymous && opts.unthrottled[r.Method+" "+r.URL.Path]:
			res = limitResult{OK: true}
		case p.Anonymous:
			res = s.limits.Allow("anon", clientIP(r), s.classes.anon, s.classes.anonBurst)
		default:
			res = s.limits.Allow("authed", p.UserID.String(), s.classes.authed, s.classes.authedBurst)
		}
		if res.Limit > 0 {
			writeRateLimitHeaders(w, res)
		}
		if !res.OK {
			if p.Anonymous {
				problemTooMany(w, r, "Anonymous requests have used up their rate limit. Wait for the Retry-After interval, or sign in.")
			} else {
				problemTooMany(w, r, "This account has used up its rate limit. Wait for the Retry-After interval.")
			}
			return
		}

		// PAT scope gate for route families the generic chokepoint cannot
		// express (§12.3 review:act, see authz_scope_routes.go).
		if !s.checkPathScope(w, r, p) {
			return
		}

		// The access log names the actor (§16.2 allows ids, never secrets);
		// the log line is emitted by the outer middleware, which sees only
		// the pre-auth request, so hand the identity back through the holder.
		recordActor(r.Context(), p)

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

// resolvePAT loads and validates a PAT credential.
func (s *Server) resolvePAT(r *http.Request, token string) (*auth.Principal, error) {
	if s.st == nil {
		return nil, auth.ErrUnauthorized
	}
	return auth.ResolvePAT(r.Context(), s.q(), token)
}

// resolveSession loads a session principal and returns its CSRF token.
func (s *Server) resolveSession(r *http.Request, token string) (*auth.Principal, string, error) {
	if s.st == nil {
		return nil, "", auth.ErrUnauthorized
	}
	ctx := r.Context()
	q := s.q()
	sess, err := q.GetSessionByHash(ctx, auth.HashToken(token))
	if err != nil {
		return nil, "", auth.ErrUnauthorized
	}
	u, err := q.GetUserByID(ctx, sess.UserID)
	if err != nil || u.State != "active" {
		return nil, "", auth.ErrUnauthorized
	}
	_ = q.TouchSession(ctx, sess.ID)
	roles, err := s.loadOrgRoles(ctx, sess.UserID)
	if err != nil {
		return nil, "", err
	}
	return &auth.Principal{
		UserID:        sess.UserID,
		Handle:        u.Handle,
		Via:           "session",
		OrgRoles:      roles,
		EmailVerified: u.EmailVerifiedAt != nil,
		PlatformStaff: u.PlatformStaff,
		SessionID:     sess.ID,
		SSOFresh:      parseSSOTags(sess.SsoTags),
	}, sess.CsrfToken, nil
}

// parseSSOTags decodes sessions.sso_tags ({"<org_id>":"<RFC3339 refreshed_at>"})
// into the per-org freshness map used by enforced SSO (§12.4).
func parseSSOTags(raw []byte) map[uuid.UUID]time.Time {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil || len(m) == 0 {
		return nil
	}
	out := make(map[uuid.UUID]time.Time, len(m))
	for k, v := range m {
		id, err := uuid.Parse(k)
		if err != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			continue
		}
		out[id] = t
	}
	return out
}

func (s *Server) loadOrgRoles(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]auth.OrgRole, error) {
	rows, err := s.q().ListUserMemberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	roles := make(map[uuid.UUID]auth.OrgRole, len(rows))
	for _, m := range rows {
		roles[m.OrgID] = auth.OrgRole(m.Role)
	}
	return roles, nil
}

// authorize runs the §12.2 chokepoint for the request and writes the problem
// response on denial. orgID is uuid.Nil for self/public actions. For
// org-scoped actions it additionally enforces SSO freshness / org-bound PATs
// when the org has sso_required set (§12.4) — a second gate layered on top of
// RBAC, applied uniformly to every org route through this one chokepoint.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, act auth.Action, orgID uuid.UUID) bool {
	p := principalFrom(r.Context())
	err := auth.Check(p, auth.Resource{OrgID: orgID}, act)
	switch err {
	case nil:
		// proceed to enforced-SSO gate below
	case auth.ErrUnauthorized:
		problemUnauthorized(w, r, "This request carried no valid session or token. Sign in and retry.")
		return false
	default:
		problemForbidden(w, r, "This credential does not carry the role or scope this action needs.")
		return false
	}
	if orgID != uuid.Nil && !p.Anonymous && !s.enforceSSO(r.Context(), p, orgID) {
		writeProblem(w, r, http.StatusForbidden, "sso-required",
			"SSO required", "This organization requires a fresh SSO session or an org-bound token. Sign in through SSO again.")
		return false
	}
	return true
}

// enforceSSO returns true when the caller may act on orgID's resources under
// the org's enforced-SSO policy (§12.4). Non-enforcing orgs always pass. The
// gate is skipped without a database (dev-only) since it cannot be evaluated.
func (s *Server) enforceSSO(ctx context.Context, p *auth.Principal, orgID uuid.UUID) bool {
	if s.st == nil {
		return true
	}
	org, err := s.q().GetOrgByID(ctx, orgID)
	if err != nil {
		return true // org lookup failure surfaces as a 404 in the handler
	}
	if !org.SsoRequired {
		return true
	}
	return p.SSOSatisfied(orgID, s.cfg.Auth.SSOMaxAge)
}
