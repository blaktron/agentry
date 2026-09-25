package api

// Knowledge packs (plan knowledge.md §4.3, §4.4; agentry#593): an account's
// packs kept in the registry, sealed under data keys of their own, scanned
// on arrival. Every route is the caller's own: a pack is looked up by its
// owner, so another account's pack — a fellow member's included — is one
// that does not exist, and platform staff see names and sizes through
// their own route and nothing else.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/knowledge"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/packseal"
)

// knowledgeDigestHeader carries a tree's digest beside its bytes.
const knowledgeDigestHeader = "X-Agentry-Knowledge-Digest"

// SetKeyWrapper replaces the knowledge store's key wrapper: an extension's
// (pkg/extension WrapsKeys) in place of the deployment key.
func (s *Server) SetKeyWrapper(w knowledge.KeyWrapper) {
	if s.knowledge != nil && w != nil {
		s.knowledge.SetWrapper(w)
	}
}

// Knowledge is the knowledge store, for an extension that builds on it.
func (s *Server) Knowledge() *knowledge.Service { return s.knowledge }

// knowledgeOwner is the caller as a pack's owner.
func knowledgeOwner(r *http.Request) knowledge.Owner {
	return knowledge.User(principalFrom(r.Context()).UserID)
}

// knowledgeProblem answers a store error in the store's words.
func (s *Server) knowledgeProblem(w http.ResponseWriter, r *http.Request, err error, what string) {
	var alloc *knowledge.AllocationError
	switch {
	case errors.Is(err, knowledge.ErrUnconfigured):
		writeProblem(w, r, http.StatusServiceUnavailable, "knowledge-unconfigured", "Knowledge store off",
			"This registry keeps no knowledge packs: it has no knowledge sealing key and no extension that wraps keys.")
	case errors.Is(err, knowledge.ErrNotFound):
		problemNotFound(w, r)
	case errors.As(err, &alloc):
		writeProblemWith(w, r, http.StatusRequestEntityTooLarge, "knowledge-allocation", "Knowledge allocation reached",
			"This pack would take the knowledge kept here past the account's allocation. Delete a pack, or keep this one on this machine.",
			map[string]any{"bytes": alloc.Bytes, "max": alloc.Max})
	case errors.Is(err, knowledge.ErrTooLarge):
		writeProblem(w, r, http.StatusRequestEntityTooLarge, "knowledge-too-large", "Knowledge pack too large",
			"A knowledge pack is at most 10 MB and 2000 files.")
	case errors.Is(err, knowledge.ErrDigest):
		writeProblem(w, r, http.StatusUnprocessableEntity, "knowledge-digest-mismatch", "Tree does not match its digest",
			"The tree inside the upload is not the digest its header names; nothing was stored.")
	case errors.Is(err, knowledge.ErrTree), errors.Is(err, packseal.ErrFormat), errors.Is(err, packseal.ErrOpen):
		writeProblem(w, r, http.StatusUnprocessableEntity, "knowledge-tree-invalid", "Not this pack's sealed tree",
			"The upload is not a knowledge pack's tree sealed under this pack's data key; nothing was stored.")
	case errors.Is(err, knowledge.ErrNameTaken):
		writeProblem(w, r, http.StatusConflict, "knowledge-name-taken", "Pack name taken",
			"This account already keeps a knowledge pack of this name here.")
	case errors.Is(err, knowledge.ErrName):
		problemValidation(w, r, "The registry refused the pack.", FieldError{Field: "name", Message: "Must be 1-64 lowercase letters, digits, '.', '-' or '_', starting with a letter or a digit."})
	case errors.Is(err, knowledge.ErrNotOwner), errors.Is(err, packseal.ErrKey):
		writeProblem(w, r, http.StatusNotFound, "knowledge-key-not-found", "Wrapped key not found",
			"This wrapped key does not open for this account.")
	default:
		s.log.ErrorContext(r.Context(), what, "err", err)
		problemInternal(w, r)
	}
}

func knowledgePackToAPI(p storegen.KnowledgePack) (KnowledgePack, error) {
	out := KnowledgePack{
		Id: p.ID, Name: p.Name, State: KnowledgePackState(p.State),
		Bytes: p.Bytes, Files: int(p.Files), Pages: int(p.Pages), Digest: p.Digest,
		WrappedKey: KnowledgeWrappedKey{Kind: p.WrapperKind, Recipient: p.WrapperRecipient, Key: p.WrappedKey},
		ScannedAt:  p.ScannedAt, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
	if len(p.ScanReport) > 0 {
		var rep KnowledgeScanReport
		if err := json.Unmarshal(p.ScanReport, &rep); err != nil {
			return out, err
		}
		out.Scan = &rep
	}
	return out, nil
}

func (s *Server) writeKnowledgePack(w http.ResponseWriter, r *http.Request, status int, p storegen.KnowledgePack) {
	out, err := knowledgePackToAPI(p)
	if err != nil {
		s.knowledgeProblem(w, r, err, "knowledge pack report")
		return
	}
	writeJSON(w, status, out)
}

// ListKnowledgePacks implements GET /knowledge/packs.
func (s *Server) ListKnowledgePacks(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		return
	}
	rows, err := s.knowledge.List(r.Context(), knowledgeOwner(r))
	if err != nil {
		s.knowledgeProblem(w, r, err, "list knowledge packs")
		return
	}
	out := make([]KnowledgePack, 0, len(rows))
	for _, p := range rows {
		k, err := knowledgePackToAPI(p)
		if err != nil {
			s.knowledgeProblem(w, r, err, "knowledge pack report")
			return
		}
		out = append(out, k)
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateKnowledgePack implements POST /knowledge/packs.
func (s *Server) CreateKnowledgePack(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActKnowledgeWrite, uuid.Nil) {
		return
	}
	var req CreateKnowledgePackRequest
	if !readJSON(w, r, &req) {
		return
	}
	p, err := s.knowledge.Create(r.Context(), knowledgeOwner(r), req.Name, knowledge.WrappedKey{
		Kind: req.WrappedKey.Kind, Recipient: req.WrappedKey.Recipient, Blob: req.WrappedKey.Key,
	})
	if err != nil {
		s.knowledgeProblem(w, r, err, "create knowledge pack")
		return
	}
	s.writeKnowledgePack(w, r, http.StatusCreated, p)
}

// GetKnowledgePack implements GET /knowledge/packs/{packId}.
func (s *Server) GetKnowledgePack(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if !s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		return
	}
	p, err := s.knowledge.Get(r.Context(), knowledgeOwner(r), packID)
	if err != nil {
		s.knowledgeProblem(w, r, err, "get knowledge pack")
		return
	}
	s.writeKnowledgePack(w, r, http.StatusOK, p)
}

// DeleteKnowledgePack implements DELETE /knowledge/packs/{packId}.
func (s *Server) DeleteKnowledgePack(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if !s.authorize(w, r, auth.ActKnowledgeWrite, uuid.Nil) {
		return
	}
	if err := s.knowledge.Delete(r.Context(), knowledgeOwner(r), packID); err != nil {
		s.knowledgeProblem(w, r, err, "delete knowledge pack")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UploadKnowledgeTree implements PUT /knowledge/packs/{packId}/tree: one
// body, at most a sealed 10 MB pack.
func (s *Server) UploadKnowledgeTree(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if !s.authorize(w, r, auth.ActKnowledgeWrite, uuid.Nil) {
		return
	}
	if !s.knowledge.Configured() {
		s.knowledgeProblem(w, r, knowledge.ErrUnconfigured, "upload knowledge tree")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, knowledge.MaxUpload))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			problemUploadTooLarge(w, r, "A sealed knowledge pack is at most a 10 MB pack; this upload is larger.")
			return
		}
		problemBadRequest(w, r, "The upload could not be read.")
		return
	}
	p, err := s.knowledge.Upload(r.Context(), knowledgeOwner(r), packID, body)
	if err != nil {
		s.knowledgeProblem(w, r, err, "upload knowledge tree")
		return
	}
	s.writeKnowledgePack(w, r, http.StatusAccepted, p)
}

// DownloadKnowledgeTree implements GET /knowledge/packs/{packId}/tree: the
// sealed tree as stored.
func (s *Server) DownloadKnowledgeTree(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if !s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		return
	}
	p, rc, err := s.knowledge.SealedTree(r.Context(), knowledgeOwner(r), packID)
	if err != nil {
		s.knowledgeProblem(w, r, err, "download knowledge tree")
		return
	}
	defer func() { _ = rc.Close() }()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(knowledgeDigestHeader, p.Digest)
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, rc); err != nil {
		s.log.WarnContext(r.Context(), "knowledge tree download", "pack", p.ID, "err", err)
	}
}

// ExportKnowledgePack implements GET /knowledge/packs/{packId}/export: the
// tree decrypted, to its owner alone.
func (s *Server) ExportKnowledgePack(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if !s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		return
	}
	p, tree, err := s.knowledge.Export(r.Context(), knowledgeOwner(r), packID)
	if err != nil {
		s.knowledgeProblem(w, r, err, "export knowledge pack")
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+p.Name+`.tar"`)
	w.Header().Set(knowledgeDigestHeader, p.Digest)
	w.WriteHeader(http.StatusOK)
	if err := knowledge.WriteTree(w, tree.Files); err != nil {
		s.log.WarnContext(r.Context(), "knowledge export", "pack", p.ID, "err", err)
	}
}

// WrapKnowledgeKey implements POST /knowledge/keys/wrap.
func (s *Server) WrapKnowledgeKey(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActKnowledgeWrite, uuid.Nil) {
		return
	}
	var req KnowledgeDataKey
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Key) != packseal.KeySize {
		problemValidation(w, r, "The registry refused the key.", FieldError{Field: "key", Message: "Must be a 32-byte data key, base64."})
		return
	}
	wk, err := s.knowledge.Wrap(r.Context(), knowledgeOwner(r), req.Key)
	if err != nil {
		s.knowledgeProblem(w, r, err, "wrap knowledge key")
		return
	}
	writeJSON(w, http.StatusOK, KnowledgeWrappedKey{Kind: wk.Kind, Recipient: wk.Recipient, Key: wk.Blob})
}

// UnwrapKnowledgeKey implements POST /knowledge/keys/unwrap: the data key,
// to the owner it was wrapped for and no one else.
func (s *Server) UnwrapKnowledgeKey(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		return
	}
	var req KnowledgeWrappedKey
	if !readJSON(w, r, &req) {
		return
	}
	key, err := s.knowledge.Unwrap(r.Context(), knowledgeOwner(r), knowledge.WrappedKey{Kind: req.Kind, Recipient: req.Recipient, Blob: req.Key})
	if err != nil {
		s.knowledgeProblem(w, r, err, "unwrap knowledge key")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, KnowledgeDataKey{Key: key})
}

// GetKnowledgeUsage implements GET /knowledge/usage.
func (s *Server) GetKnowledgeUsage(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		return
	}
	u, err := s.knowledge.Usage(r.Context(), knowledgeOwner(r))
	if err != nil {
		s.knowledgeProblem(w, r, err, "knowledge usage")
		return
	}
	writeJSON(w, http.StatusOK, KnowledgeUsage{Bytes: u.Bytes, Max: u.Max, Packs: u.Packs})
}

// ListKnowledgePackSizes implements GET /platform/knowledge (staff): an
// account's packs by name and size, for support, and nothing of their
// content. A staff token needs knowledge:read for it.
func (s *Server) ListKnowledgePackSizes(w http.ResponseWriter, r *http.Request, params ListKnowledgePackSizesParams) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireStaff(w, r) {
		return
	}
	if p := principalFrom(r.Context()); p.Via == "pat" && !auth.HasScope(p.Scopes, auth.ScopeKnowledgeRead) {
		problemForbidden(w, r, "This token does not carry the knowledge:read scope.")
		return
	}
	u, err := s.q().GetUserByHandle(r.Context(), params.Owner)
	if errors.Is(err, pgx.ErrNoRows) {
		problemNotFound(w, r)
		return
	}
	if err != nil {
		s.knowledgeProblem(w, r, err, "knowledge sizes: owner")
		return
	}
	rows, err := s.knowledge.Sizes(r.Context(), knowledge.User(u.ID))
	if err != nil {
		s.knowledgeProblem(w, r, err, "knowledge sizes")
		return
	}
	out := make([]KnowledgePackSize, 0, len(rows))
	for _, row := range rows {
		out = append(out, KnowledgePackSize{Id: row.ID, Name: row.Name, State: row.State, Bytes: row.Bytes, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}
