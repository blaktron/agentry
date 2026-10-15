package api

// Knowledge packs: an account's
// packs kept in the registry, sealed under data keys of their own, scanned
// on arrival. Every route under /knowledge/ is the caller's own: a pack is
// looked up by its owner, so another account's pack — a fellow member's
// included — is one that does not exist, and platform staff see names and
// sizes through their own route and nothing else. An organization's shared
// packs are the routes of handlers_knowledge_org.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/registry"
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
			"This pack would take the knowledge kept here past the allocation it draws on. Delete a pack, or keep this one on this machine.",
			map[string]any{"bytes": alloc.Bytes, "max": alloc.Max})
	case errors.Is(err, knowledge.ErrTooLarge):
		writeProblem(w, r, http.StatusRequestEntityTooLarge, "knowledge-too-large", "Knowledge pack too large",
			fmt.Sprintf("A knowledge pack is at most %d MB and %d files.", knowledge.MaxBytes>>20, knowledge.MaxFiles))
	case errors.Is(err, knowledge.ErrNotExportable):
		writeProblem(w, r, http.StatusForbidden, "knowledge-not-exportable", "Pack not exportable",
			"Only the organization's admins export this pack unencrypted. An admin can mark it exportable.")
	case errors.Is(err, knowledge.ErrScanning):
		writeProblem(w, r, http.StatusConflict, "knowledge-scanning", "Pack being scanned",
			"This pack's tree is being scanned; it can be read once the scan ends.")
	case errors.Is(err, knowledge.ErrDigest):
		writeProblem(w, r, http.StatusUnprocessableEntity, "knowledge-digest-mismatch", "Tree does not match its digest",
			"The tree inside the upload is not the digest its header names; nothing was stored.")
	case errors.Is(err, knowledge.ErrTree), errors.Is(err, packseal.ErrFormat), errors.Is(err, packseal.ErrOpen):
		writeProblem(w, r, http.StatusUnprocessableEntity, "knowledge-tree-invalid", "Not this pack's sealed tree",
			"The upload is not a knowledge pack's tree sealed under this pack's data key; nothing was stored.")
	case errors.Is(err, knowledge.ErrNameTaken):
		writeProblem(w, r, http.StatusConflict, "knowledge-name-taken", "Pack name taken",
			"A knowledge pack of this name is already kept here by the same owner.")
	case errors.Is(err, knowledge.ErrName):
		problemValidation(w, r, "The registry refused the pack.", FieldError{Field: "name", Message: "Must be 1-64 lowercase letters, digits, '.', '-' or '_', starting with a letter or a digit."})
	case errors.Is(err, knowledge.ErrNotOwner), errors.Is(err, packseal.ErrKey):
		writeProblem(w, r, http.StatusNotFound, "knowledge-key-not-found", "Wrapped key not found",
			"This wrapped key does not open for this owner.")
	default:
		s.log.ErrorContext(r.Context(), what, "err", err)
		problemInternal(w, r)
	}
}

func wrappedKeyToAPI(k knowledge.WrappedKey) KnowledgeWrappedKey {
	return KnowledgeWrappedKey{Kind: k.Kind, Recipient: k.Recipient, Key: k.Blob}
}

func wrappedKeyFromAPI(k KnowledgeWrappedKey) knowledge.WrappedKey {
	return knowledge.WrappedKey{Kind: k.Kind, Recipient: k.Recipient, Blob: k.Key}
}

// knowledgePackToAPI is a pack as the API shows it; org is the owning
// organization's handle for a shared pack, "" for the caller's own.
func knowledgePackToAPI(p storegen.KnowledgePack, org string) (KnowledgePack, error) {
	out := KnowledgePack{
		Id: p.ID, Name: p.Name, State: KnowledgePackState(p.State),
		Bytes: p.Bytes, Files: int(p.Files), Pages: int(p.Pages), Digest: p.Digest,
		WrappedKey: wrappedKeyToAPI(knowledge.WrappedKeyOf(p)),
		ScannedAt:  p.ScannedAt, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
	if p.OwnerKind == string(knowledge.OwnerOrg) {
		exportable := p.Exportable
		out.Shared, out.Org, out.Exportable = true, &org, &exportable
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

func (s *Server) writeKnowledgePack(w http.ResponseWriter, r *http.Request, status int, p storegen.KnowledgePack, org string) {
	out, err := knowledgePackToAPI(p, org)
	if err != nil {
		s.knowledgeProblem(w, r, err, "knowledge pack report")
		return
	}
	writeJSON(w, status, out)
}

// The bodies below serve both doors: a person's own packs under
// /knowledge/ and an organization's shared packs under
// /orgs/{org}/knowledge/, the caller authorized by the route before either
// is called. org is the organization's handle for a shared pack, "" for
// the caller's own.

func (s *Server) listKnowledgePacks(w http.ResponseWriter, r *http.Request, owner knowledge.Owner, org string) {
	rows, err := s.knowledge.List(r.Context(), owner)
	if err != nil {
		s.knowledgeProblem(w, r, err, "list knowledge packs")
		return
	}
	out := make([]KnowledgePack, 0, len(rows))
	for _, p := range rows {
		k, err := knowledgePackToAPI(p, org)
		if err != nil {
			s.knowledgeProblem(w, r, err, "knowledge pack report")
			return
		}
		out = append(out, k)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createKnowledgePack(w http.ResponseWriter, r *http.Request, owner knowledge.Owner, org string, also knowledge.Also) {
	var req CreateKnowledgePackRequest
	if !readJSON(w, r, &req) {
		return
	}
	p, err := s.knowledge.Create(r.Context(), owner, req.Name, wrappedKeyFromAPI(req.WrappedKey), also)
	if err != nil {
		s.knowledgeProblem(w, r, err, "create knowledge pack")
		return
	}
	s.writeKnowledgePack(w, r, http.StatusCreated, p, org)
}

func (s *Server) getKnowledgePack(w http.ResponseWriter, r *http.Request, owner knowledge.Owner, org string, packID uuid.UUID) {
	p, err := s.knowledge.Get(r.Context(), owner, packID)
	if err != nil {
		s.knowledgeProblem(w, r, err, "get knowledge pack")
		return
	}
	s.writeKnowledgePack(w, r, http.StatusOK, p, org)
}

func (s *Server) deleteKnowledgePack(w http.ResponseWriter, r *http.Request, owner knowledge.Owner, packID uuid.UUID, also knowledge.Also) {
	if err := s.knowledge.Delete(r.Context(), owner, packID, also); err != nil {
		s.knowledgeProblem(w, r, err, "delete knowledge pack")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// uploadKnowledgeTree takes one body, at most a sealed 10 MB pack.
func (s *Server) uploadKnowledgeTree(w http.ResponseWriter, r *http.Request, owner knowledge.Owner, org string, packID uuid.UUID) {
	if !s.knowledge.Configured() {
		s.knowledgeProblem(w, r, knowledge.ErrUnconfigured, "upload knowledge tree")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, knowledge.MaxUpload()))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			problemUploadTooLarge(w, r, fmt.Sprintf("A sealed knowledge pack holds at most a %d MB pack; this upload is larger.", knowledge.MaxBytes>>20))
			return
		}
		problemBadRequest(w, r, "The upload could not be read.")
		return
	}
	p, err := s.knowledge.UploadAdmitted(r.Context(), owner, packID, body, s.admitKnowledgeUpload)
	var refused *knowledgeRefused
	var unavailable *knowledgeAdmissionUnavailable
	switch {
	case errors.As(err, &refused):
		problemAdmissionRefused(w, r, refused.refusal)
		return
	case errors.As(err, &unavailable):
		s.log.ErrorContext(r.Context(), "knowledge: admission unavailable", "err", unavailable.err)
		writeProblem(w, r, http.StatusServiceUnavailable, "admission-unavailable", "Upload not admitted",
			"The registry could not check whether this account may have the pack scanned. Nothing was stored; retry shortly.")
		return
	case err != nil:
		s.knowledgeProblem(w, r, err, "upload knowledge tree")
		return
	}
	s.writeKnowledgePack(w, r, http.StatusAccepted, p, org)
}

// KnowledgeAdmission is an upload of a pack's tree that will queue a scan,
// as an extension admits it: the account uploading, the pack's owner (the
// account, or an organization) and the tree's size. The payer is the
// extension's to decide.
type KnowledgeAdmission struct {
	User      uuid.UUID
	OwnerKind string // "user" or "org"
	OwnerID   uuid.UUID
	Pack      uuid.UUID
	Bytes     int64
	Files     int
}

// KnowledgeAdmitter is the seam through which an extension admits the scan
// an upload of a pack's tree queues, and may charge for it (pkg/extension
// AdmitsKnowledge). It is asked once per upload, after the core has read
// the tree and before anything is stored: an upload the core refuses (it
// does not read, it is too large, or it is past the allocation as the
// allocation stands) is never asked about, and one of the
// tree the pack already holds queues no scan and is not asked about either.
// A pack the extension builds and stores itself is not admitted here. The
// core has none, and admits every upload.
type KnowledgeAdmitter interface {
	// AdmitKnowledge returns a ticket, or a Refusal the route answers in its
	// own status and words. An error is "unknown": the route fails closed
	// with 503 and stores nothing.
	AdmitKnowledge(ctx context.Context, a KnowledgeAdmission) (registry.Ticket, *registry.Refusal, error)
	// VoidKnowledge cancels a ticket for an upload the core then did not
	// store (the account's allocation, a lost race). It must be idempotent.
	VoidKnowledge(ctx context.Context, t registry.Ticket) error
}

type knowledgeAdmission struct {
	mu       sync.RWMutex
	admitter KnowledgeAdmitter
}

// SetKnowledgeAdmitter sets the extension that admits an upload's scan.
func (s *Server) SetKnowledgeAdmitter(a KnowledgeAdmitter) {
	s.knowledgeAdmit.mu.Lock()
	defer s.knowledgeAdmit.mu.Unlock()
	s.knowledgeAdmit.admitter = a
}

func (s *Server) knowledgeAdmitter() KnowledgeAdmitter {
	s.knowledgeAdmit.mu.RLock()
	defer s.knowledgeAdmit.mu.RUnlock()
	return s.knowledgeAdmit.admitter
}

type knowledgeRefused struct{ refusal registry.Refusal }

func (e *knowledgeRefused) Error() string { return "knowledge: upload refused: " + e.refusal.Detail }

type knowledgeAdmissionUnavailable struct{ err error }

func (e *knowledgeAdmissionUnavailable) Error() string {
	return "knowledge: admission unavailable: " + e.err.Error()
}

// admitKnowledgeUpload asks the extension, if any, to admit an upload's
// scan, and voids its ticket when the upload is then not stored.
func (s *Server) admitKnowledgeUpload(ctx context.Context, a knowledge.UploadAdmission) (func(stored bool), error) {
	adm := s.knowledgeAdmitter()
	if adm == nil {
		return func(bool) {}, nil
	}
	t, refusal, err := adm.AdmitKnowledge(ctx, KnowledgeAdmission{
		User: principalFrom(ctx).UserID, OwnerKind: string(a.Owner.Kind), OwnerID: a.Owner.ID,
		Pack: a.Pack, Bytes: a.Bytes, Files: a.Files,
	})
	switch {
	case err != nil:
		return nil, &knowledgeAdmissionUnavailable{err: err}
	case refusal != nil:
		return nil, &knowledgeRefused{refusal: *refusal}
	}
	return func(stored bool) {
		if stored || t.ID == "" {
			return
		}
		if err := adm.VoidKnowledge(context.WithoutCancel(ctx), t); err != nil {
			s.log.ErrorContext(ctx, "knowledge: void an admission", "ticket", t.ID, "err", err)
		}
	}, nil
}

// downloadKnowledgeTree answers the sealed tree as stored.
func (s *Server) downloadKnowledgeTree(w http.ResponseWriter, r *http.Request, owner knowledge.Owner, packID uuid.UUID) {
	p, rc, err := s.knowledge.SealedTree(r.Context(), owner, packID)
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

// exportKnowledgePack answers the tree decrypted, when allow (nil: always)
// permits it for the pack as the export read it; also, when given, is
// recorded before a byte is written, and its failure writes nothing.
func (s *Server) exportKnowledgePack(w http.ResponseWriter, r *http.Request, owner knowledge.Owner, packID uuid.UUID, allow func(storegen.KnowledgePack) error, also knowledge.Also) {
	p, tree, err := s.knowledge.ExportIf(r.Context(), owner, packID, allow)
	if err != nil {
		s.knowledgeProblem(w, r, err, "export knowledge pack")
		return
	}
	if also != nil {
		if err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error { return also(q, p) }); err != nil {
			s.knowledgeProblem(w, r, err, "export knowledge pack: record")
			return
		}
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

func (s *Server) wrapKnowledgeKey(w http.ResponseWriter, r *http.Request, owner knowledge.Owner) {
	var req KnowledgeDataKey
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Key) != packseal.KeySize {
		problemValidation(w, r, "The registry refused the key.", FieldError{Field: "key", Message: "Must be a 32-byte data key, base64."})
		return
	}
	wk, err := s.knowledge.Wrap(r.Context(), owner, req.Key)
	if err != nil {
		s.knowledgeProblem(w, r, err, "wrap knowledge key")
		return
	}
	writeJSON(w, http.StatusOK, wrappedKeyToAPI(wk))
}

// unwrapKnowledgeKey answers the data key, to the owner it was wrapped for
// (for a shared pack, to whoever the route found an active member) and no
// one else.
func (s *Server) unwrapKnowledgeKey(w http.ResponseWriter, r *http.Request, owner knowledge.Owner) {
	var req KnowledgeWrappedKey
	if !readJSON(w, r, &req) {
		return
	}
	key, err := s.knowledge.Unwrap(r.Context(), owner, wrappedKeyFromAPI(req))
	if err != nil {
		s.knowledgeProblem(w, r, err, "unwrap knowledge key")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, KnowledgeDataKey{Key: key})
}

func (s *Server) knowledgeUsage(w http.ResponseWriter, r *http.Request, owner knowledge.Owner) {
	u, err := s.knowledge.Usage(r.Context(), owner)
	if err != nil {
		s.knowledgeProblem(w, r, err, "knowledge usage")
		return
	}
	writeJSON(w, http.StatusOK, KnowledgeUsage{Bytes: u.Bytes, Packs: u.Packs, Used: u.Used, Max: u.Max, Pooled: u.Pooled})
}

// ListKnowledgePacks implements GET /knowledge/packs.
func (s *Server) ListKnowledgePacks(w http.ResponseWriter, r *http.Request) {
	if s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		s.listKnowledgePacks(w, r, knowledgeOwner(r), "")
	}
}

// CreateKnowledgePack implements POST /knowledge/packs.
func (s *Server) CreateKnowledgePack(w http.ResponseWriter, r *http.Request) {
	if s.authorize(w, r, auth.ActKnowledgeWrite, uuid.Nil) {
		s.createKnowledgePack(w, r, knowledgeOwner(r), "", nil)
	}
}

// GetKnowledgePack implements GET /knowledge/packs/{packId}.
func (s *Server) GetKnowledgePack(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		s.getKnowledgePack(w, r, knowledgeOwner(r), "", packID)
	}
}

// DeleteKnowledgePack implements DELETE /knowledge/packs/{packId}.
func (s *Server) DeleteKnowledgePack(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if s.authorize(w, r, auth.ActKnowledgeWrite, uuid.Nil) {
		s.deleteKnowledgePack(w, r, knowledgeOwner(r), packID, nil)
	}
}

// UploadKnowledgeTree implements PUT /knowledge/packs/{packId}/tree.
func (s *Server) UploadKnowledgeTree(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if s.authorize(w, r, auth.ActKnowledgeWrite, uuid.Nil) {
		s.uploadKnowledgeTree(w, r, knowledgeOwner(r), "", packID)
	}
}

// DownloadKnowledgeTree implements GET /knowledge/packs/{packId}/tree: the
// sealed tree as stored.
func (s *Server) DownloadKnowledgeTree(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		s.downloadKnowledgeTree(w, r, knowledgeOwner(r), packID)
	}
}

// ExportKnowledgePack implements GET /knowledge/packs/{packId}/export: the
// tree decrypted, to its owner alone.
func (s *Server) ExportKnowledgePack(w http.ResponseWriter, r *http.Request, packID openapi_types.UUID) {
	if s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		s.exportKnowledgePack(w, r, knowledgeOwner(r), packID, nil, nil)
	}
}

// WrapKnowledgeKey implements POST /knowledge/keys/wrap.
func (s *Server) WrapKnowledgeKey(w http.ResponseWriter, r *http.Request) {
	if s.authorize(w, r, auth.ActKnowledgeWrite, uuid.Nil) {
		s.wrapKnowledgeKey(w, r, knowledgeOwner(r))
	}
}

// UnwrapKnowledgeKey implements POST /knowledge/keys/unwrap: the data key,
// to the owner it was wrapped for and no one else.
func (s *Server) UnwrapKnowledgeKey(w http.ResponseWriter, r *http.Request) {
	if s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		s.unwrapKnowledgeKey(w, r, knowledgeOwner(r))
	}
}

// GetKnowledgeUsage implements GET /knowledge/usage.
func (s *Server) GetKnowledgeUsage(w http.ResponseWriter, r *http.Request) {
	if s.authorize(w, r, auth.ActKnowledgeRead, uuid.Nil) {
		s.knowledgeUsage(w, r, knowledgeOwner(r))
	}
}

// ListKnowledgePackSizes implements GET /platform/knowledge (staff): an
// account's or an organization's packs by name and size, for support, and
// nothing of their content. A staff token needs knowledge:read for it.
func (s *Server) ListKnowledgePackSizes(w http.ResponseWriter, r *http.Request, params ListKnowledgePackSizesParams) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireStaff(w, r) {
		return
	}
	if p := principalFrom(r.Context()); p.ScopeBound() && !auth.HasScope(p.Scopes, auth.ScopeKnowledgeRead) {
		problemForbidden(w, r, "This token does not carry the knowledge:read scope.")
		return
	}
	owner, err := s.knowledgeOwnerByHandle(r.Context(), params.Owner)
	if errors.Is(err, pgx.ErrNoRows) {
		problemNotFound(w, r)
		return
	}
	if err != nil {
		s.knowledgeProblem(w, r, err, "knowledge sizes: owner")
		return
	}
	rows, err := s.knowledge.Sizes(r.Context(), owner)
	if err != nil {
		s.knowledgeProblem(w, r, err, "knowledge sizes")
		return
	}
	out := make([]KnowledgePackSize, 0, len(rows))
	for _, row := range rows {
		out = append(out, KnowledgePackSize{Id: row.ID, Name: row.Name, State: KnowledgePackState(row.State), Bytes: row.Bytes, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// knowledgeOwnerByHandle is the owner a handle names: a person's account,
// else an organization; pgx.ErrNoRows for neither.
func (s *Server) knowledgeOwnerByHandle(ctx context.Context, handle string) (knowledge.Owner, error) {
	u, err := s.q().GetUserByHandle(ctx, handle)
	if err == nil {
		return knowledge.User(u.ID), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return knowledge.Owner{}, err
	}
	o, err := s.q().GetOrgByHandle(ctx, handle)
	if err != nil {
		return knowledge.Owner{}, err
	}
	return knowledge.Org(o.ID), nil
}
