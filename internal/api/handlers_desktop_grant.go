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

// The desktop app's browser sign-in, hardened (agentry#19, DEV-058 / D-015).
//
// Before: the site's authorize form minted a PAT and 303'd it to the
// app's loopback listener as ?token=…, which left the token in the browser's
// history. Now the form records a GRANT — a single-use code bound to the
// app's state nonce, valid for desktopGrantTTL — and the app exchanges the
// code from its own process. The PAT is minted at exchange time, so nothing
// token-shaped is ever stored or placed in a URL, and a code read from
// history later is already consumed or expired. This is the RFC 8252 §7.3
// loopback shape with a code exchange in place of the implicit token.

const desktopGrantTTL = 60 * time.Second

// desktopScopes is the scope set the desktop app's surfaces use: browse and
// install (agent:read, repo:read), Build → publish (agent:publish,
// repo:write), identity (user:profile). Deliberately no review:act and no org
// scopes. Fixed server-side so a caller of the grant endpoint cannot widen it.
var desktopScopes = []string{"agent:read", "agent:publish", "repo:read", "repo:write", "user:profile"}

var desktopStateRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

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
	p := principalFrom(r.Context())
	code, err := auth.NewToken("agd_")
	if err != nil {
		problemInternal(w, r)
		return
	}
	expires := time.Now().Add(desktopGrantTTL)
	name := "Agentry Desktop (" + time.Now().UTC().Format("2006-01-02") + ")"
	_, err = s.q().CreateDesktopGrant(r.Context(), storegen.CreateDesktopGrantParams{
		ID: newUUID(), UserID: p.UserID,
		CodeSha256: auth.HashToken(code), StateSha256: auth.HashToken(req.State),
		Scopes: desktopScopes, Name: name, ExpiresAt: expires,
	})
	if err != nil {
		s.log.Error("create desktop grant", "err", err)
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
		s.log.Error("exchange desktop code", "err", err)
		problemInternal(w, r)
		return
	}
	respScopes := make([]Scope, 0, len(created.Scopes))
	for _, sc := range created.Scopes {
		respScopes = append(respScopes, Scope(sc))
	}
	writeJSON(w, http.StatusCreated, PatCreated{
		Id: created.ID, Name: created.Name, Prefix: created.TokenPrefix,
		Scopes: respScopes, ExpiresAt: created.ExpiresAt,
		CreatedAt: created.CreatedAt, Token: token,
	})
}
