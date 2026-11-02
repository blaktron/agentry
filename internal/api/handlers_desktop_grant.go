package api

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// The desktop app's browser sign-in, hardened.
//
// The site's authorize form records a GRANT — a single-use code bound to
// the app's state nonce, valid for desktopGrantTTL — and the app exchanges
// the code from its own process. Handing the PAT itself to the app's
// loopback listener as ?token=… would leave the token in the browser's
// history. The PAT is minted at exchange time, so nothing
// token-shaped is ever stored or placed in a URL, and a code read from
// history later is already consumed or expired. This is the RFC 8252 §7.3
// loopback shape with a code exchange in place of the implicit token.

const desktopGrantTTL = 60 * time.Second

// desktopScopes is the fixed scope set a sign-in grant mints; auth owns
// it so the approval page names exactly what is granted.
var desktopScopes = auth.SignInGrantScopes()

var desktopStateRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

// runhostNameRE is a remote runhost's name as the clients spell it.
var runhostNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// CreateDesktopGrant implements POST /user/tokens/desktop-grant (session-only).
func (s *Server) CreateDesktopGrant(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserTokensManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req CreateDesktopGrantJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	if !desktopStateRE.MatchString(req.State) {
		problemValidation(w, r, "The registry rejected the desktop grant. Each field error says what to fix.", FieldError{Field: "state", Message: "Must match [A-Za-z0-9_-]{8,128} (letters, digits, hyphen and underscore)."})
		return
	}
	// A runhost's grant mints a token that can only open a credits
	// session, named for the runhost, so the server it is kept on can pay
	// for its runs' models and do nothing else with the account.
	scopes := desktopScopes
	name := "Agentry Desktop (" + time.Now().UTC().Format("2006-01-02") + ")"
	if req.Runhost != nil {
		if !runhostNameRE.MatchString(*req.Runhost) {
			problemValidation(w, r, "The registry rejected the desktop grant. Each field error says what to fix.", FieldError{Field: "runhost", Message: "Must be a runhost's name: 1-32 lowercase letters, digits and hyphens, starting and ending with a letter or digit."})
			return
		}
		scopes = []string{string(auth.ScopeCreditsSession)}
		name = "Runhost " + *req.Runhost + " (credits only)"
	}
	p := principalFrom(r.Context())
	code, err := auth.NewToken("agd_")
	if err != nil {
		problemInternal(w, r)
		return
	}
	expires := time.Now().Add(desktopGrantTTL)
	_, err = s.q().CreateDesktopGrant(r.Context(), storegen.CreateDesktopGrantParams{
		ID: newUUID(), UserID: p.UserID,
		CodeSha256: auth.HashToken(code), StateSha256: auth.HashToken(req.State),
		Scopes: scopes, Name: name, ExpiresAt: expires,
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "create desktop grant", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, DesktopGrant{Code: code, ExpiresAt: expires})
}

// ExchangeDesktopCode implements POST /auth/desktop/exchange (anonymous; the
// code is the credential). Consumes the grant and mints the PAT in one
// transaction; a second exchange, a wrong state, or an expired grant all get
// the same 403 so nothing about a code's status leaks.
func (s *Server) ExchangeDesktopCode(w http.ResponseWriter, r *http.Request) {
	if !s.allowLogin(w, r) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req ExchangeDesktopCodeJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	if req.Code == "" || !desktopStateRE.MatchString(req.State) {
		problemForbidden(w, r, "This sign-in code is invalid, expired, or already used. Start the sign-in again from the app.")
		return
	}
	token, err := auth.NewToken(auth.PATPrefix)
	if err != nil {
		problemInternal(w, r)
		return
	}
	var created storegen.Pat
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		g, err := q.ConsumeDesktopGrant(r.Context(), storegen.ConsumeDesktopGrantParams{
			CodeSha256: auth.HashToken(req.Code), StateSha256: auth.HashToken(req.State),
		})
		if err != nil {
			return err
		}
		pat, err := q.CreatePAT(r.Context(), storegen.CreatePATParams{
			ID: newUUID(), UserID: g.UserID, Name: g.Name,
			TokenSha256: auth.HashToken(token), TokenPrefix: auth.DisplayPrefix(token),
			Scopes: g.Scopes, ExpiresAt: time.Now().Add(s.cfg.Auth.PATMaxTTL),
		})
		if err != nil {
			return err
		}
		created = pat
		e := auditEvent(r, audit.ActionPATCreate)
		e.Actor, e.ActorKind = g.UserID, audit.ActorUser
		e.TargetKind, e.TargetID = "pat", pat.ID
		e.Detail = map[string]any{"name": g.Name, "scopes": g.Scopes, "via": "desktop-exchange", "grant": g.ID.String()}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemForbidden(w, r, "This sign-in code is invalid, expired, or already used. Start the sign-in again from the app.")
			return
		}
		s.log.ErrorContext(r.Context(), "exchange desktop code", "err", err)
		problemInternal(w, r)
		return
	}
	respScopes := append([]ScopeGranted(nil), created.Scopes...)
	writeJSON(w, http.StatusCreated, PatCreated{
		Id: created.ID, Name: created.Name, Prefix: created.TokenPrefix,
		Scopes: respScopes, ExpiresAt: created.ExpiresAt,
		CreatedAt: created.CreatedAt, Token: token,
	})
}
