package api

// An organization's shared knowledge (plan knowledge.md §4.7, D13, D26;
// agentry#646): packs the organization owns, their data keys wrapped for
// the organization — under the deployment's knowledge sealing key on a
// core registry, to the organization's own key on an extension's wrapper —
// written by its admins and read by its active members. Membership is
// checked at every call: the chokepoint reads the roles this request
// resolved, active memberships only, so a member who is removed is refused
// the next unwrap and a sealed copy on their machine stays sealed. A caller
// who is not an active member is answered 404, as for another account's
// pack. The bodies are handlers_knowledge.go's, shared with a person's own.

import (
	"net/http"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/knowledge"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// orgKnowledge resolves {org} for a shared-knowledge route and authorizes
// act there: a caller who is signed in but not an active member of the
// organization — another organization's member, platform staff, a pending
// member — is 404 before the chokepoint, so the routes say nothing of what
// an organization keeps to anyone outside it. It answers the organization
// as a pack's owner.
func (s *Server) orgKnowledge(w http.ResponseWriter, r *http.Request, org string, act auth.Action) (storegen.GetOrgByHandleRow, knowledge.Owner, bool) {
	if !s.requireDB(w, r) {
		return storegen.GetOrgByHandleRow{}, knowledge.Owner{}, false
	}
	row, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return row, knowledge.Owner{}, false
	}
	if p := principalFrom(r.Context()); !p.Anonymous && p.Role(row.ID) == auth.RoleNone {
		problemNotFound(w, r)
		return row, knowledge.Owner{}, false
	}
	if !s.authorize(w, r, act, row.ID) {
		return row, knowledge.Owner{}, false
	}
	return row, knowledge.Org(row.ID), true
}

// orgKnowledgeAudit records act on one of the organization's packs in the
// organization's audit log, in the transaction of the change it records.
func (s *Server) orgKnowledgeAudit(r *http.Request, orgID uuid.UUID, act audit.Action, detail func(storegen.KnowledgePack) map[string]any) knowledge.Also {
	return func(q *storegen.Queries, p storegen.KnowledgePack) error {
		e := auditEvent(r, act)
		e.OrgID = orgID
		e.TargetKind, e.TargetID = "knowledge_pack", p.ID
		e.Detail = map[string]any{"name": p.Name}
		if detail != nil {
			for k, v := range detail(p) {
				e.Detail[k] = v
			}
		}
		return s.auditW.Write(r.Context(), q, e)
	}
}

// ListOrgKnowledgePacks implements GET /orgs/{org}/knowledge/packs.
func (s *Server) ListOrgKnowledgePacks(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if _, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeRead); ok {
		s.listKnowledgePacks(w, r, owner, org)
	}
}

// CreateOrgKnowledgePack implements POST /orgs/{org}/knowledge/packs.
func (s *Server) CreateOrgKnowledgePack(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if row, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeWrite); ok {
		s.createKnowledgePack(w, r, owner, org, s.orgKnowledgeAudit(r, row.ID, audit.ActionOrgKnowledgeCreate, nil))
	}
}

// GetOrgKnowledgePack implements GET /orgs/{org}/knowledge/packs/{packId}.
func (s *Server) GetOrgKnowledgePack(w http.ResponseWriter, r *http.Request, org OrgHandle, packID openapi_types.UUID) {
	if _, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeRead); ok {
		s.getKnowledgePack(w, r, owner, org, packID)
	}
}

// UpdateOrgKnowledgePack implements PATCH /orgs/{org}/knowledge/packs/{packId}:
// whether the organization's members may export the pack (D26).
func (s *Server) UpdateOrgKnowledgePack(w http.ResponseWriter, r *http.Request, org OrgHandle, packID openapi_types.UUID) {
	row, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeWrite)
	if !ok {
		return
	}
	var req UpdateKnowledgePackRequest
	if !readJSON(w, r, &req) {
		return
	}
	p, err := s.knowledge.SetExportable(r.Context(), owner, packID, req.Exportable,
		s.orgKnowledgeAudit(r, row.ID, audit.ActionOrgKnowledgeUpdate, func(p storegen.KnowledgePack) map[string]any {
			return map[string]any{"exportable": p.Exportable}
		}))
	if err != nil {
		s.knowledgeProblem(w, r, err, "mark knowledge pack")
		return
	}
	s.writeKnowledgePack(w, r, http.StatusOK, p, org)
}

// DeleteOrgKnowledgePack implements DELETE /orgs/{org}/knowledge/packs/{packId}.
func (s *Server) DeleteOrgKnowledgePack(w http.ResponseWriter, r *http.Request, org OrgHandle, packID openapi_types.UUID) {
	if row, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeWrite); ok {
		s.deleteKnowledgePack(w, r, owner, packID, s.orgKnowledgeAudit(r, row.ID, audit.ActionOrgKnowledgeDelete, nil))
	}
}

// UploadOrgKnowledgeTree implements PUT /orgs/{org}/knowledge/packs/{packId}/tree.
func (s *Server) UploadOrgKnowledgeTree(w http.ResponseWriter, r *http.Request, org OrgHandle, packID openapi_types.UUID) {
	if _, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeWrite); ok {
		s.uploadKnowledgeTree(w, r, owner, org, packID)
	}
}

// DownloadOrgKnowledgeTree implements GET /orgs/{org}/knowledge/packs/{packId}/tree.
func (s *Server) DownloadOrgKnowledgeTree(w http.ResponseWriter, r *http.Request, org OrgHandle, packID openapi_types.UUID) {
	if _, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeRead); ok {
		s.downloadKnowledgeTree(w, r, owner, packID)
	}
}

// ExportOrgKnowledgePack implements GET /orgs/{org}/knowledge/packs/{packId}/export:
// an admin's always, a member's once the pack is marked exportable (D26).
func (s *Server) ExportOrgKnowledgePack(w http.ResponseWriter, r *http.Request, org OrgHandle, packID openapi_types.UUID) {
	row, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeRead)
	if !ok {
		return
	}
	// Export is a read: the role decides, not whether this token may write.
	var allow func(storegen.KnowledgePack) error
	if principalFrom(r.Context()).Role(row.ID) != auth.RoleAdmin {
		allow = func(p storegen.KnowledgePack) error {
			if !p.Exportable {
				return knowledge.ErrNotExportable
			}
			return nil
		}
	}
	s.exportKnowledgePack(w, r, owner, packID, allow, s.orgKnowledgeAudit(r, row.ID, audit.ActionOrgKnowledgeExport, nil))
}

// WrapOrgKnowledgeKey implements POST /orgs/{org}/knowledge/keys/wrap.
func (s *Server) WrapOrgKnowledgeKey(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if _, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeWrite); ok {
		s.wrapKnowledgeKey(w, r, owner)
	}
}

// UnwrapOrgKnowledgeKey implements POST /orgs/{org}/knowledge/keys/unwrap:
// the data key, to an active member of the organization it was wrapped for.
func (s *Server) UnwrapOrgKnowledgeKey(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if _, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeRead); ok {
		s.unwrapKnowledgeKey(w, r, owner)
	}
}

// GetOrgKnowledgeUsage implements GET /orgs/{org}/knowledge/usage.
func (s *Server) GetOrgKnowledgeUsage(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if _, owner, ok := s.orgKnowledge(w, r, org, auth.ActOrgKnowledgeRead); ok {
		s.knowledgeUsage(w, r, owner)
	}
}
