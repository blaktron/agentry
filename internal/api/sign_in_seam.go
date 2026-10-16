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
	oidcrp "github.com/blaktron/agentry/internal/auth/oidc"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// The sign-in seam: what an extension hears when someone signs in through
// an individual provider, and the remembered-browser credential it may mint
// from that sign-in. The rules stay the core's: who the account is, whether
// the sign-in answered a second factor, how the credential is stored.

// SignIn is a sign-in through an individual provider that is about to be
// given a session, as an extension's hook hears it.
type SignIn struct {
	// UserID is the account the sign-in resolved to.
	UserID uuid.UUID
	// Provider is the provider's id, and Subject the identity it signed in
	// ("<provider>:<sub>").
	Provider string
	Subject  string
	// Claims is every claim of the verified ID token, as JSON decoded it;
	// nil for a provider with no ID token. An extension that knows its IdP
	// reads that IdP's own claims here, and believes them only from that
	// provider.
	Claims map[string]any
	// AMR and AuthTime are the token's `amr` and `auth_time`, the evidence
	// MintRememberedBrowser asks for.
	AMR      []string
	AuthTime time.Time
	// Request is the callback's request, for MintRememberedBrowser and the
	// extension's own audit; its body is spent.
	Request *http.Request
	// SetCookie sets a cookie on the response that gives the session.
	SetCookie func(*http.Cookie)
}

// AddSignInHook registers a listener for every sign-in through an
// individual provider, called once the account is resolved and active and
// before the session is issued, so a cookie it sets rides the same
// response. It runs synchronously in the callback and cannot refuse the
// sign-in; a slow hook slows it. A panic is recovered and logged.
func (s *Server) AddSignInHook(h func(ctx context.Context, in SignIn)) {
	s.signInHooks = append(s.signInHooks, h)
}

func (s *Server) fireSignIn(ctx context.Context, in SignIn) {
	for _, h := range s.signInHooks {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					s.log.ErrorContext(ctx, "sign-in hook panicked", "provider", in.Provider, "panic", rec)
				}
			}()
			h(ctx, in)
		}()
	}
}

// rememberWindow is how recent a sign-in must be for its token to earn a
// remembered browser: the seconds between answering the code and arriving
// at the callback, with room for clock skew. A token an IdP minted silently
// against a live session of its own repeats the original `auth_time`, so
// without this every sign-in against one IdP session would mint a fresh
// lifetime, and trust would renew itself.
const rememberWindow = directoryRememberWindow

// ErrNoSecondFactor is MintRememberedBrowser's refusal of a sign-in whose
// evidence does not show a second factor answered just now.
var ErrNoSecondFactor = errors.New("api: a remembered browser needs a sign-in that answered a second factor just now")

// MintRememberedBrowser records a remembered browser for userID and returns
// the token to set as its cookie and the record's lifetime
// (pkg/extension.Deps.RememberedBrowsers). The core's rules hold whoever
// asks: the evidence must name a second factor (amr) from a sign-in no
// older than a few minutes (authTime), or it is ErrNoSecondFactor; the
// account must be active; only the token's SHA-256 is stored, bound to this
// one account; the lifetime is auth.trustedDeviceTTL and absolute. The
// record and its user.trusted_device_add audit row commit together, with
// detail on the row. The token leaves the server here and nowhere else.
func (s *Server) MintRememberedBrowser(r *http.Request, userID uuid.UUID, amr []string, authTime time.Time, detail map[string]any) (string, time.Duration, error) {
	if s.st == nil {
		return "", 0, errors.New("api: no database to record a remembered browser in")
	}
	if !oidcrp.AMRNamesSecondFactor(amr) || authTime.IsZero() {
		return "", 0, ErrNoSecondFactor
	}
	if age := time.Since(authTime); age > rememberWindow || age < -rememberWindow {
		return "", 0, ErrNoSecondFactor
	}
	ctx := r.Context()
	var token string
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		u, err := q.GetUserByID(ctx, userID)
		if err != nil {
			return err
		}
		if u.State != "active" {
			return errAccountNotActive
		}
		token, err = s.createTrustedDevice(ctx, q, r, userID, detail)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = errAccountNotActive
	}
	if err != nil {
		return "", 0, err
	}
	return token, s.cfg.Auth.TrustedDeviceTTL, nil
}

var errAccountNotActive = errors.New("api: the account is not active")

// UseRememberedBrowser reports whether token is a live remembered browser of
// userID's active account (pkg/extension.Deps.RememberedBrowsers), and
// records the use before it answers yes: a skip nobody could audit is not
// granted. Every "not this account's live record" is false with no error;
// only a store that could not answer is an error, which the caller must
// treat as no.
func (s *Server) UseRememberedBrowser(r *http.Request, userID uuid.UUID, token string, detail map[string]any) (bool, error) {
	if s.st == nil {
		return false, errors.New("api: no database to read remembered browsers from")
	}
	return s.useTrustedDevice(r.Context(), r, userID, token, detail)
}

// useTrustedDevice is the use of a remembered browser by something other
// than the native password sign-in: the directory's check, an extension's.
// The account must be active, and GetTrustedDeviceByHash filters owner,
// revocation and expiry in one statement. last_seen_at moves; expires_at
// never does. The audit row carries detail and the record's id.
func (s *Server) useTrustedDevice(ctx context.Context, r *http.Request, userID uuid.UUID, token string, detail map[string]any) (bool, error) {
	if token == "" {
		return false, nil
	}
	q := s.q()
	user, err := q.GetUserByID(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if user.State != "active" {
		return false, nil
	}
	row, err := q.GetTrustedDeviceByHash(ctx, storegen.GetTrustedDeviceByHashParams{
		TokenSha256: auth.HashToken(token),
		UserID:      user.ID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = s.st.WithTx(ctx, func(tq *storegen.Queries) error {
		if err := tq.TouchTrustedDevice(ctx, row.ID); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionTrustedDeviceUse)
		e.Actor, e.ActorKind = user.ID, audit.ActorUser
		e.TargetKind, e.TargetID = "user", user.ID
		e.Detail = map[string]any{"device": row.ID.String()}
		for k, v := range detail {
			if k != "device" {
				e.Detail[k] = v
			}
		}
		return s.auditW.Write(ctx, tq, e)
	})
	if err != nil {
		return false, err
	}
	return true, nil
}
