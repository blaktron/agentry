package api

// SSH keys for the git transport (§6.1 Q7, agentry#70): registered here,
// looked up by fingerprint by the git SSH server. Session-only to add or
// remove — a PAT must not be able to mint a longer-lived credential than
// itself (the D-22 rule that governs tokens). Adding one is a feature the
// subscription may not include (Features.SSHKeys, agentry#820); listing,
// removing and using a key already held are not gated.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// ListSshKeys implements GET /user/ssh-keys.
func (s *Server) ListSshKeys(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserTokensRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	rows, err := s.q().ListSSHKeys(r.Context(), p.UserID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "list ssh keys", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]SshKey, 0, len(rows))
	for _, row := range rows {
		out = append(out, sshKeyToAPI(row))
	}
	writeJSON(w, http.StatusOK, out)
}

func sshKeyToAPI(row storegen.UserSshKey) SshKey {
	k := SshKey{Id: row.ID, Title: row.Title, KeyType: row.KeyType, Fingerprint: row.Fingerprint, CreatedAt: row.CreatedAt}
	if row.LastUsedAt != nil {
		k.LastUsedAt = row.LastUsedAt
	}
	return k
}

// AddSshKey implements POST /user/ssh-keys (session-only).
func (s *Server) AddSshKey(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserTokensManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req AddSshKeyRequest
	if !readJSON(w, r, &req) {
		return
	}
	var fields []FieldError
	title := strings.TrimSpace(req.Title)
	if title == "" || len(title) > 120 {
		fields = append(fields, FieldError{Field: "title", Message: "Must be 1-120 characters."})
	}
	keyType, canonical, fp, err := auth.ParseSSHPublicKey(req.PublicKey)
	if err != nil {
		fields = append(fields, FieldError{Field: "publicKey", Message: "Must be an OpenSSH public key line."})
	} else if keyType == "ssh-dss" {
		fields = append(fields, FieldError{Field: "publicKey", Message: "This server does not accept DSA keys."})
	}
	if len(fields) > 0 {
		problemValidation(w, r, "The registry rejected the SSH key. Each field error says what to fix.", fields...)
		return
	}
	p := principalFrom(r.Context())
	// The subscription decides whether this person may add a key at all.
	// Unknown refuses: an entitlement outage must not be a way to mint a
	// git credential.
	f, err := s.entitlements().Features(r.Context(), entitlements.ForUser(p.UserID))
	if err != nil {
		s.log.ErrorContext(r.Context(), "ssh key entitlements", "err", err)
		problemInternal(w, r)
		return
	}
	if !f.SSHKeys {
		problemFeatureNotIncluded(w, r, "Adding an SSH key is not included in your subscription. Clone and push over HTTPS with a personal access token instead; keys you already hold keep working.")
		return
	}
	id := newUUID()
	var row storegen.UserSshKey
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		var err error
		row, err = q.CreateSSHKey(r.Context(), storegen.CreateSSHKeyParams{
			ID: id, UserID: p.UserID, Title: title, KeyType: keyType, PublicKey: canonical, Fingerprint: fp,
		})
		if err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionSSHKeyAdd)
		e.TargetKind, e.TargetID = "ssh_key", id
		e.Detail = map[string]any{"fingerprint": fp, "keyType": keyType}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			problemValidation(w, r, "The registry rejected the SSH key. Each field error says what to fix.", FieldError{Field: "publicKey", Message: "This key is already registered."})
			return
		}
		s.log.ErrorContext(r.Context(), "add ssh key", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, sshKeyToAPI(row))
}

// RemoveSshKey implements DELETE /user/ssh-keys/{keyId} (session-only).
func (s *Server) RemoveSshKey(w http.ResponseWriter, r *http.Request, keyID openapi_types.UUID) {
	if !s.authorize(w, r, auth.ActUserTokensManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	var rows int64
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.RevokeSSHKey(r.Context(), storegen.RevokeSSHKeyParams{ID: keyID, UserID: p.UserID})
		if err != nil {
			return err
		}
		rows = n
		if n == 0 {
			return nil
		}
		e := auditEvent(r, audit.ActionSSHKeyRemove)
		e.TargetKind, e.TargetID = "ssh_key", keyID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "remove ssh key", "err", err)
		problemInternal(w, r)
		return
	}
	if rows == 0 {
		problemNotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
