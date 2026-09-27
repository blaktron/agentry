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
	"github.com/blaktron/agentry/internal/auth/social"
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
//
// detail rides the user.trusted_device_add row: the directory path marks its
// records {"via": "directory"}, so an investigator can tell which sign-in
// earned one (agentry#670).
func (s *Server) createTrustedDevice(ctx context.Context, q *storegen.Queries, r *http.Request, userID uuid.UUID, detail map[string]any) (string, error) {
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
	e.Detail = detail
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
	setTrustedDeviceCookieAt(w, token, ttl, secure, "/", "")
}

// setTrustedDeviceCookieAt is the one place the cookie's flags are written;
// the native path scopes it to the whole host, the directory path to the
// directory's flow executor.
func setTrustedDeviceCookieAt(w http.ResponseWriter, token string, ttl time.Duration, secure bool, path, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     trustedDeviceCookieName,
		Value:    token,
		Path:     path,
		Domain:   domain,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// The directory path (agentry#670, DEV-163). Dev and production sign in
// through the directory, which shows the "Remember this device for 30 days"
// box on its own code page and passes the choice on as the ID-token claim
// agentry_remember_device. The registry mints the same record as above on the
// OIDC callback, and the directory asks the registry about it (the check
// route, directory_trust.go) before asking for the code.

// directoryFlowExecutorPath is where authentik's flow executor serves, and so
// the one path the directory-path cookie is scoped to. The directory's policy
// reads the cookie on the executor's requests; nothing of the registry's
// ever needs it, so no request to the registry carries it.
const directoryFlowExecutorPath = "/api/v3/flows/executor/"

// directoryRememberWindow is how recent the directory's sign-in must be for
// its token to earn a remembered browser: the seconds between answering the
// code and arriving at the callback, with room for clock skew.
const directoryRememberWindow = 5 * time.Minute

// directoryRemembers reports whether this directory sign-in earned a
// remembered browser. Everything must hold:
//
//   - the directory path is on (auth.idpTrustCheckToken is set);
//   - the token is the directory's own: another provider asserting the claim
//     is not the directory the registry takes it from;
//   - the claim asks, and `amr` names a second factor;
//   - `auth_time` is within directoryRememberWindow of now. The claim and
//     `amr` both come from the directory session's login event, so a later
//     authorize that a live directory session answers silently repeats them
//     with no code asked. Only auth_time, which is that event's time, says
//     the sign-in is old. Without this, each registry sign-in against one
//     directory session would mint a fresh 30 days and trust would renew
//     itself, which D9 forbids.
//
// A sign-in the directory let skip the factor carries no `mfa`, so a skip
// can never mint either: trust stays absolute.
func (s *Server) directoryRemembers(provider string, id *social.Identity) bool {
	if s.cfg.Auth.IdPTrustCheckToken == "" || provider != social.ProviderAuthentik {
		return false
	}
	if !id.RememberDevice || !id.MFAAsserted() || id.AuthTime.IsZero() {
		return false
	}
	age := time.Since(id.AuthTime)
	return age <= directoryRememberWindow && age >= -directoryRememberWindow
}

// setDirectoryTrustedDeviceCookie sets the directory path's cookie, scoped
// to the directory's flow executor and, when the directory is a subdomain of
// the registry, set for the domain that covers both (config's
// DirectoryTrustCookieDomain; "" is host-only). That domain also covers the
// registry's other subdomains, so on a deployment whose dev or staging host
// sits under the production registry's name, the token reaches their flow
// executors too; DEV-163 accepts this for the estate, where every such host is
// its own.
func setDirectoryTrustedDeviceCookie(w http.ResponseWriter, token string, ttl time.Duration, secure bool, domain string) {
	setTrustedDeviceCookieAt(w, token, ttl, secure, directoryFlowExecutorPath, domain)
}
