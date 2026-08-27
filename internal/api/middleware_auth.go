package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
)

const (
	sessionCookieName = "agentry_session"
	csrfHeader        = "X-Agentry-CSRF"
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &auth.Principal{Anonymous: true}

		// PATs: Authorization: Bearer agy_… (§9.1). Sessions are never
		// accepted from Authorization; PATs are never read from cookies.
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tok := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
			if auth.IsPAT(tok) {
				pp, err := s.resolvePAT(r, tok)
				if err != nil {
					problemUnauthorized(w, r, "invalid or expired token")
					return
				}
				p = pp
			} else {
				problemUnauthorized(w, r, "unrecognized bearer token")
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
						problemForbidden(w, r, "missing or invalid CSRF token")
						return
					}
				}
			}
			// Invalid session cookie degrades to anonymous (stale cookies
			// on public pages must not 401).
		}

		// Rate limiting by class.
		if p.Anonymous {
			if !s.limits.allow("anon", clientIP(r), s.classes.anon, s.classes.anonBurst) {
				problemTooMany(w, r, "anonymous rate limit exceeded")
				return
			}
		} else {
			if !s.limits.allow("authed", p.UserID.String(), s.classes.authed, s.classes.authedBurst) {
				problemTooMany(w, r, "rate limit exceeded")
				return
			}
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

// resolvePAT loads and validates a PAT credential.
func (s *Server) resolvePAT(r *http.Request, token string) (*auth.Principal, error) {
	if s.st == nil {
		return nil, auth.ErrUnauthorized
	}
	ctx := r.Context()
	q := s.q()
	pat, err := q.GetPATByHash(ctx, auth.HashToken(token))
	if err != nil {
		return nil, auth.ErrUnauthorized
	}
	u, err := q.GetUserByID(ctx, pat.UserID)
	if err != nil || u.State != "active" {
		return nil, auth.ErrUnauthorized
	}
	_ = q.TouchPAT(ctx, pat.ID) // best-effort last_used tracking
	roles, err := s.loadOrgRoles(ctx, pat.UserID)
	if err != nil {
		return nil, err
	}
	return &auth.Principal{
		UserID:        pat.UserID,
		Handle:        u.Handle,
		Via:           "pat",
		Scopes:        pat.Scopes,
		OrgRoles:      roles,
		EmailVerified: u.EmailVerifiedAt != nil,
		PATID:         pat.ID,
	}, nil
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
		SessionID:     sess.ID,
	}, sess.CsrfToken, nil
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
// response on denial. orgID is uuid.Nil for self/public actions.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, act auth.Action, orgID uuid.UUID) bool {
	p := principalFrom(r.Context())
	err := auth.Check(p, auth.Resource{OrgID: orgID}, act)
	switch err {
	case nil:
		return true
	case auth.ErrUnauthorized:
		problemUnauthorized(w, r, "")
		return false
	default:
		problemForbidden(w, r, "")
		return false
	}
}
