package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
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
	u := User{
		Id: row.ID, Handle: row.Handle, Email: row.Email,
		DisplayName: row.DisplayName, EmailVerified: row.EmailVerifiedAt != nil,
		TotpEnabled: row.TotpEnabled, CreatedAt: row.CreatedAt,
		PlatformStaff: &row.PlatformStaff,
		CookieAckAt:   row.CookieAckAt,
	}
	if ms, err := s.q().ListUserMembershipsWithHandles(r.Context(), p.UserID); err == nil {
		type orgRow = struct {
			Handle string           `json:"handle"`
			Role   string           `json:"role"`
			State  *MembershipState `json:"state,omitempty"`
		}
		orgs := make([]orgRow, 0, len(ms))
		for _, m := range ms {
			state := MembershipState(m.State)
			orgs = append(orgs, orgRow{Handle: m.Handle, Role: m.Role, State: &state})
		}
		u.Orgs = &orgs
	}
	u.PendingOrg = s.pendingOrgOf(r.Context(), p.UserID)
	writeJSON(w, http.StatusOK, u)
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
	ackOnly := req.CookieAck != nil && *req.CookieAck
	if req.DisplayName == nil && !ackOnly {
		problemValidation(w, r, "Nothing to update. Send displayName, cookieAck, or both.")
		return
	}
	var name string
	if req.DisplayName != nil {
		name = strings.TrimSpace(*req.DisplayName)
		if name == "" || len(name) > 120 {
			problemValidation(w, r, "The displayName field must be 1-120 characters.")
			return
		}
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if req.DisplayName != nil {
			if _, err := q.UpdateUserDisplayName(r.Context(), storegen.UpdateUserDisplayNameParams{ID: p.UserID, DisplayName: name}); err != nil {
				return err
			}
		}
		if ackOnly {
			if err := q.SetUserCookieAck(r.Context(), p.UserID); err != nil {
				return err
			}
		}
		e := auditEvent(r, audit.ActionUserUpdate)
		e.TargetKind, e.TargetID = "user", p.UserID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "user update", "err", err)
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
	row, ok := s.userOrNotFound(w, r, handle)
	if !ok {
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
		s.log.ErrorContext(r.Context(), "list tokens", "err", err)
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
	scopes := append([]ScopeGranted(nil), row.Scopes...)
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
		fields = append(fields, FieldError{Field: "name", Message: "Must be 1-120 characters."})
	}
	if len(req.Scopes) == 0 {
		fields = append(fields, FieldError{Field: "scopes", Message: "Name at least one scope."})
	}
	scopes := make([]string, 0, len(req.Scopes))
	for _, sc := range req.Scopes {
		if !auth.ValidScope(auth.Scope(sc)) {
			fields = append(fields, FieldError{Field: "scopes", Message: "Unknown scope " + string(sc) + "."})
			continue
		}
		scopes = append(scopes, string(sc))
	}
	p := principalFrom(r.Context())

	// Org binding (§12.4): a token bound to an org may be minted only from an
	// SSO-fresh session for that org, and is capped at the org-bound max TTL
	// (90 days). It is the only kind of PAT accepted against an enforced-SSO
	// org's resources.
	var orgID *uuid.UUID
	maxTTL := s.cfg.Auth.PATMaxTTL
	if req.OrgHandle != nil && *req.OrgHandle != "" {
		orgRow, ok := s.orgOrNotFound(w, r, *req.OrgHandle)
		if !ok {
			return
		}
		if !p.SSOSatisfied(orgRow.ID, s.cfg.Auth.SSOMaxAge) {
			problemForbidden(w, r, "Org-bound tokens require a fresh SSO session for that organization. Sign in through SSO again.")
			return
		}
		orgID = &orgRow.ID
		maxTTL = s.cfg.Auth.PATOrgBoundMaxTTL
	}

	maxExpiry := time.Now().Add(maxTTL)
	expiresAt := maxExpiry
	if req.ExpiresAt != nil {
		if req.ExpiresAt.After(maxExpiry) {
			fields = append(fields, FieldError{Field: "expiresAt", Message: "Must be within the maximum token lifetime."})
		} else if req.ExpiresAt.Before(time.Now()) {
			fields = append(fields, FieldError{Field: "expiresAt", Message: "Must be in the future."})
		} else {
			expiresAt = *req.ExpiresAt
		}
	}
	if len(fields) > 0 {
		problemValidation(w, r, "The registry rejected the token. Each field error says what to fix.", fields...)
		return
	}

	token, err := auth.NewToken(auth.PATPrefix)
	if err != nil {
		problemInternal(w, r)
		return
	}
	var created storegen.Pat
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		pat, err := q.CreatePAT(r.Context(), storegen.CreatePATParams{
			ID: newUUID(), UserID: p.UserID, Name: name,
			TokenSha256: auth.HashToken(token), TokenPrefix: auth.DisplayPrefix(token),
			Scopes: scopes, ExpiresAt: expiresAt, OrgID: orgID,
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
		s.log.ErrorContext(r.Context(), "create token", "err", err)
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
		s.log.ErrorContext(r.Context(), "revoke token", "err", err)
		problemInternal(w, r)
		return
	}
	if rows == 0 {
		problemNotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
