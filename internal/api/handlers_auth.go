package api

import (
	"errors"
	"net/http"
	"net/netip"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/handle"
)

// Handle/name grammar shared with the DDL.
var reHandle = regexp.MustCompile(handle.Grammar)

// newUUID returns a UUIDv7; generation failure is unrecoverable.
func newUUID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return id
}

// isUniqueViolation reports a Postgres 23505 error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// uniqueViolationOn reports whether err is a unique violation of the named
// constraint or index, for a handler whose insert can collide on more than
// one.
func uniqueViolationOn(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// auditEvent builds the base event for this request's principal.
func auditEvent(r *http.Request, action audit.Action) audit.Event {
	p := principalFrom(r.Context())
	e := audit.Event{Action: action, ActorKind: audit.ActorSystem, UserAgent: r.UserAgent()}
	if !p.Anonymous {
		e.Actor = p.UserID
		if p.Via == "pat" {
			e.ActorKind = audit.ActorPAT
		} else {
			e.ActorKind = audit.ActorUser
		}
	}
	if ip, err := netip.ParseAddr(clientIP(r)); err == nil {
		e.IP = ip
	}
	return e
}

// requestFacts are the two things a credential row records about the request
// that presented it: the address it came from and the user agent it claimed.
// Both are display facts for the pages that list credentials — a session, a
// trusted device — and neither takes part in any decision, so a value the
// client can choose never influences what the server trusts. The address
// is choosable by the client; keeping it out of every decision is what
// makes it harmless here. Both are best-effort: an address that does not parse
// is left nil rather than refused.
func requestFacts(r *http.Request) (ip *netip.Addr, ua string) {
	if a, err := netip.ParseAddr(clientIP(r)); err == nil {
		ip = &a
	}
	return ip, r.UserAgent()
}

// VerifyEmail implements POST /auth/verify-email: the activation link's
// target. Following it confirms the address the link was mailed to and
// activates the account; extensions hear user.email_verified once the
// confirmation commits.
func (s *Server) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if !s.allowLogin(w, r) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var verified uuid.UUID
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		userID, err := q.ConsumeEmailVerification(r.Context(), auth.HashToken(req.Token))
		if err != nil {
			return err
		}
		u, err := q.GetUserByID(r.Context(), userID)
		if err != nil {
			return err
		}
		if u.State != "active" {
			// An erased or deactivated account's link activates nothing.
			return pgx.ErrNoRows
		}
		if err := q.MarkEmailVerified(r.Context(), userID); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserEmailVerified)
		e.Actor, e.ActorKind = userID, audit.ActorUser
		e.TargetKind, e.TargetID = "user", userID
		if err := s.auditW.Write(r.Context(), q, e); err != nil {
			return err
		}
		if u.EmailVerifiedAt == nil {
			verified = userID
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemValidation(w, r, "This verification link is invalid or expired.")
			return
		}
		s.log.ErrorContext(r.Context(), "verify-email", "err", err)
		problemInternal(w, r)
		return
	}
	// Extensions hear the address confirmed: a sign-up's
	// allowance and promo code wait for it.
	if verified != uuid.Nil {
		s.fireEvent(r.Context(), Event{Kind: "user.email_verified", UserID: verified})
	}
	w.WriteHeader(http.StatusNoContent)
}

// Logout implements POST /auth/logout (session-only).
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSecurityManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Via != "session" {
		problemForbidden(w, r, "Signing out requires a session, not a token.")
		return
	}
	// SP-initiated SAML Single Logout: resolved before
	// the revoke, which is what makes the session unreadable.
	idpLogout := s.samlLogoutURLForSession(r, p.SessionID)
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.RevokeSession(r.Context(), p.SessionID); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserLogout)
		e.TargetKind, e.TargetID = "user", p.UserID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "logout", "err", err)
		problemInternal(w, r)
		return
	}
	clearCookie(w, sessionCookieName, s.cfg.Auth.CookieSecure)
	if idpLogout != "" {
		writeJSON(w, http.StatusOK, LogoutResult{IdpLogoutUrl: idpLogout})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
