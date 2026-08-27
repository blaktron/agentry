package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// GetCurrentUser implements GET /user.
func (s *Server) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().GetUserByID(r.Context(), p.UserID)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, User{
		Id: row.ID, Handle: row.Handle, Email: row.Email,
		DisplayName: row.DisplayName, EmailVerified: row.EmailVerifiedAt != nil,
		TotpEnabled: row.TotpEnabled, CreatedAt: row.CreatedAt,
	})
}

// UpdateCurrentUser implements PATCH /user.
func (s *Server) UpdateCurrentUser(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req UpdateCurrentUserJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r.Context())
	if req.DisplayName == nil {
		problemValidation(w, r, "nothing to update")
		return
	}
	name := strings.TrimSpace(*req.DisplayName)
	if name == "" || len(name) > 120 {
		problemValidation(w, r, "displayName must be 1-120 characters")
		return
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.UpdateUserDisplayName(r.Context(), storegen.UpdateUserDisplayNameParams{ID: p.UserID, DisplayName: name}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserUpdate)
		e.TargetKind, e.TargetID = "user", p.UserID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("user update", "err", err)
		problemInternal(w, r)
		return
	}
	s.GetCurrentUser(w, r)
}

// GetUserProfile implements GET /users/{handle} (public).
func (s *Server) GetUserProfile(w http.ResponseWriter, r *http.Request, handle Handle) {
	if !s.authorize(w, r, auth.ActPublicRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	row, err := s.q().GetUserByHandle(r.Context(), handle)
	if err != nil || row.State != "active" {
		problemNotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, PublicUser{Handle: row.Handle, DisplayName: row.DisplayName})
}

// ListTokens implements GET /user/tokens.
func (s *Server) ListTokens(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserTokensRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	rows, err := s.q().ListPATs(r.Context(), p.UserID)
	if err != nil {
		s.log.Error("list tokens", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]Pat, 0, len(rows))
	for _, row := range rows {
		out = append(out, patToAPI(row))
	}
	writeJSON(w, http.StatusOK, out)
}

func patToAPI(row storegen.ListPATsRow) Pat {
	scopes := make([]Scope, 0, len(row.Scopes))
	for _, sc := range row.Scopes {
		scopes = append(scopes, Scope(sc))
	}
	p := Pat{
		Id: row.ID, Name: row.Name, Prefix: row.TokenPrefix,
		Scopes: scopes, ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
	}
	if row.LastUsedAt != nil {
		p.LastUsedAt = row.LastUsedAt
	}
	if row.OrgHandle != nil {
		p.OrgHandle = row.OrgHandle
	}
	return p
}

// CreateToken implements POST /user/tokens (session-only, D-22).
func (s *Server) CreateToken(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserTokensManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req CreateTokenRequest
	if !readJSON(w, r, &req) {
		return
	}

	var fields []FieldError
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 120 {
		fields = append(fields, FieldError{Field: "name", Message: "must be 1-120 characters"})
	}
	if len(req.Scopes) == 0 {
		fields = append(fields, FieldError{Field: "scopes", Message: "at least one scope required"})
	}
	scopes := make([]string, 0, len(req.Scopes))
	for _, sc := range req.Scopes {
		if !auth.ValidScope(auth.Scope(sc)) {
			fields = append(fields, FieldError{Field: "scopes", Message: "unknown scope " + string(sc)})
			continue
		}
		scopes = append(scopes, string(sc))
	}
	maxExpiry := time.Now().Add(s.cfg.Auth.PATMaxTTL)
	expiresAt := maxExpiry
	if req.ExpiresAt != nil {
		if req.ExpiresAt.After(maxExpiry) {
			fields = append(fields, FieldError{Field: "expiresAt", Message: "exceeds maximum token lifetime"})
		} else if req.ExpiresAt.Before(time.Now()) {
			fields = append(fields, FieldError{Field: "expiresAt", Message: "already expired"})
		} else {
			expiresAt = *req.ExpiresAt
		}
	}
	if len(fields) > 0 {
		problemValidation(w, r, "token rejected", fields...)
		return
	}

	token, err := auth.NewToken(auth.PATPrefix)
	if err != nil {
		problemInternal(w, r)
		return
	}
	p := principalFrom(r.Context())
	var created storegen.Pat
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		pat, err := q.CreatePAT(r.Context(), storegen.CreatePATParams{
			ID: newUUID(), UserID: p.UserID, Name: name,
			TokenSha256: auth.HashToken(token), TokenPrefix: auth.DisplayPrefix(token),
			Scopes: scopes, ExpiresAt: expiresAt,
		})
		if err != nil {
			return err
		}
		created = pat
		e := auditEvent(r, audit.ActionPATCreate)
		e.TargetKind, e.TargetID = "pat", pat.ID
		e.Detail = map[string]any{"name": name, "scopes": scopes}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("create token", "err", err)
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

// RevokeToken implements DELETE /user/tokens/{tokenId} (session-only).
func (s *Server) RevokeToken(w http.ResponseWriter, r *http.Request, tokenID openapi_types.UUID) {
	if !s.authorize(w, r, auth.ActUserTokensManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	var rows int64
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.RevokePAT(r.Context(), storegen.RevokePATParams{ID: tokenID, UserID: p.UserID})
		if err != nil {
			return err
		}
		rows = n
		if n == 0 {
			return nil
		}
		e := auditEvent(r, audit.ActionPATRevoke)
		e.TargetKind, e.TargetID = "pat", tokenID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("revoke token", "err", err)
		problemInternal(w, r)
		return
	}
	if rows == 0 {
		problemNotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
