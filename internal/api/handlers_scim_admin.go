package api

import (
	"net/http"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// scimTokenPrefix identifies SCIM bearer tokens in logs/scanners.
const scimTokenPrefix = "agyscim_"

// ListScimTokens implements GET /orgs/{org}/scim/tokens (admin, §12.5).
func (s *Server) ListScimTokens(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgSettingsManage, orgRow.ID) {
		return
	}
	rows, err := s.q().ListSCIMTokens(r.Context(), orgRow.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]ScimToken, 0, len(rows))
	for _, t := range rows {
		st := ScimToken{Id: t.ID, CreatedAt: t.CreatedAt}
		if t.ExpiresAt != nil {
			st.ExpiresAt = t.ExpiresAt
		}
		out = append(out, st)
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateScimToken implements POST /orgs/{org}/scim/tokens (admin, §12.5).
func (s *Server) CreateScimToken(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgSettingsManage, orgRow.ID) {
		return
	}
	var req CreateScimTokenJSONBody
	_ = readJSONOptional(r, &req)

	var expiresAt *time.Time
	if req.ExpiresInDays != nil {
		if *req.ExpiresInDays < 1 || *req.ExpiresInDays > 730 {
			problemValidation(w, r, "Set expiresInDays to 1-730 days.")
			return
		}
		t := time.Now().Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &t
	}
	token, err := auth.NewToken(scimTokenPrefix)
	if err != nil {
		problemInternal(w, r)
		return
	}
	id := newUUID()
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.CreateSCIMToken(r.Context(), storegen.CreateSCIMTokenParams{
			ID: id, OrgID: orgRow.ID, TokenSha256: auth.HashToken(token), ExpiresAt: expiresAt,
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionSCIMTokenCreate)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "scim_token", id
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "create scim token", "err", err)
		problemInternal(w, r)
		return
	}
	out := ScimTokenCreated{Id: id, Token: token}
	if expiresAt != nil {
		out.ExpiresAt = expiresAt
	}
	writeJSON(w, http.StatusCreated, out)
}

// RevokeScimToken implements DELETE /orgs/{org}/scim/tokens/{tokenId}.
func (s *Server) RevokeScimToken(w http.ResponseWriter, r *http.Request, org OrgHandle, tokenID openapi_types.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgSettingsManage, orgRow.ID) {
		return
	}
	var n int64
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		rows, err := q.RevokeSCIMToken(r.Context(), storegen.RevokeSCIMTokenParams{ID: tokenID, OrgID: orgRow.ID})
		if err != nil {
			return err
		}
		n = rows
		if n == 0 {
			return nil
		}
		e := auditEvent(r, audit.ActionSCIMTokenRevoke)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "scim_token", tokenID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		problemInternal(w, r)
		return
	}
	if n == 0 {
		problemNotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
