package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Trusted devices (plan trusted-devices.md, agentry#461).
//
// A trusted device is a credential of its own class: a browser that answered
// the second factor once may be remembered, so a later password sign-in from
// it skips the code. It is not a session, does not extend one, and grants
// nothing beyond that skip — a session still has to be earned by password on
// every sign-in, and the §12.4 24h absolute cap on sessions is untouched.
//
// Two rules shape everything below. The token is the whole decision (D5): the
// issuing address and user agent are recorded so the account page can describe
// the browser to its owner, and neither is consulted here, so nothing the
// client can choose influences trust. And the lifetime is absolute, not
// sliding (D9): use refreshes last_seen_at and never moves expires_at, so a
// stolen cookie does not become immortal by being used.

// trustedDeviceSkip reports whether this request carries a trusted-device
// cookie that is userID's and still live.
//
// It fails closed. An absent, empty, malformed, expired or revoked cookie, one
// belonging to somebody else, and — the case that matters most — a store that
// cannot be read, all answer false, and the caller demands the second factor.
// An outage must never be the way past a factor (the rule DEV-119 states for
// the SAML state sets, and the reason the record lives in the database rather
// than in a signed cookie nobody can revoke).
//
// The caller has already verified the password by the time this runs: the
// cookie skips the second factor and is never itself an authentication.
func (s *Server) trustedDeviceSkip(ctx context.Context, r *http.Request, userID uuid.UUID) bool {
	c, err := r.Cookie(trustedDeviceCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	row, err := s.q().GetTrustedDeviceByHash(ctx, storegen.GetTrustedDeviceByHashParams{
		TokenSha256: auth.HashToken(c.Value),
		UserID:      userID,
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.log.WarnContext(ctx, "trusted device: lookup failed, demanding the code", "err", err)
		}
		return false
	}
	if err := s.q().TouchTrustedDevice(ctx, row.ID); err != nil {
		// A touch that fails does not undo the skip: the record was read and
		// is live. last_seen_at is a display fact, not part of the decision.
		s.log.WarnContext(ctx, "trusted device: touch", "err", err)
	}
	return true
}

// createTrustedDevice records a new trusted device inside the caller's
// transaction — the same one that creates the session and writes the sign-in
// audit row, so a sign-in that earns trust records both or neither — and
// returns the token to set as the cookie.
//
// The token leaves the server exactly once, here. Only its hash is stored, so
// the row cannot be turned back into a credential by anyone who reads the
// database.
//
// A failure here fails the whole sign-in, because the mint is inside the
// transaction that creates the session. That is deliberate and it is the
// fail-closed direction: an optional convenience must not quietly not happen,
// and the realistic way this fails is a database that is already broken, in
// which case CreateSession a few lines earlier would have failed too. The cost
// is that a problem confined to this table — a migration that did not apply,
// say — turns a sign-in that asked to be remembered into a 500 while one that
// did not still works. That asymmetry is the tell, and it points at the table.
func (s *Server) createTrustedDevice(ctx context.Context, q *storegen.Queries, r *http.Request, userID uuid.UUID) (string, error) {
	token, err := auth.NewToken(auth.TrustedDevicePrefix)
	if err != nil {
		return "", err
	}
	ipPtr, ua := requestFacts(r)
	if _, err := q.CreateTrustedDevice(ctx, storegen.CreateTrustedDeviceParams{
		ID:          newUUID(),
		UserID:      userID,
		TokenSha256: auth.HashToken(token),
		Ip:          ipPtr,
		UserAgent:   &ua,
		ExpiresAt:   time.Now().Add(s.cfg.Auth.TrustedDeviceTTL),
	}); err != nil {
		return "", err
	}
	e := auditEvent(r, audit.ActionTrustedDeviceAdd)
	e.Actor, e.ActorKind = userID, audit.ActorUser
	e.TargetKind, e.TargetID = "user", userID
	if err := s.auditW.Write(ctx, q, e); err != nil {
		return "", err
	}
	return token, nil
}

// setTrustedDeviceCookie sets the cookie with the attributes every cookie this
// server sets, and a Max-Age equal to the record's lifetime so the browser
// drops it when the trust expires rather than presenting a dead token.
//
// clearCookie expires it with the same attributes, which is the rule
// agentry#413 established: a clear written bare carries nothing today and a
// value the day someone edits it.
func setTrustedDeviceCookie(w http.ResponseWriter, token string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     trustedDeviceCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}
