package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// ListUserSubmissions implements GET /user/submissions: every version the
// caller submitted, newest first, in whatever state it is now. A version of
// a QuickAgent the caller can no longer read (they left the organization
// that owns it, say) is left out: having submitted it once is not a read
// grant. The cursor follows the stored rows, so a page that leaves some out
// is shorter, never a gap in the walk.
func (s *Server) ListUserSubmissions(w http.ResponseWriter, r *http.Request, params ListUserSubmissionsParams) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	limit := clampLimit(params.Limit, activityDefaultLimit, activityMaxLimit)
	before, beforeID, ok := cursorParams(w, r, params.Cursor)
	if !ok {
		return
	}
	var status *string
	if params.Status != nil {
		if !params.Status.Valid() {
			problemValidation(w, r, "Unknown status "+string(*params.Status)+".")
			return
		}
		st := string(*params.Status)
		status = &st
	}
	rows, err := s.q().ListUserSubmissions(r.Context(), storegen.ListUserSubmissionsParams{
		SubmittedBy: p.UserID, Status: status, BeforeTime: before, BeforeID: beforeID, Lim: int32(limit),
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "user submissions", "err", err)
		problemInternal(w, r)
		return
	}
	type access struct {
		read, manage bool
	}
	seen := map[uuid.UUID]access{}
	handles := map[uuid.UUID]string{}
	out := make([]Submission, 0, len(rows))
	for _, row := range rows {
		v := row.AgentVersion
		acc, known := seen[v.AgentID]
		if !known {
			a, role, aerr := s.agentForAction(r.Context(), p, row.Namespace, row.AgentName, auth.ActAgentRead)
			if aerr == nil {
				acc = access{read: true, manage: canManageAgent(r, a, role)}
			}
			seen[v.AgentID] = acc
		}
		if !acc.read {
			continue
		}
		sub := Submission{Namespace: row.Namespace, Name: row.AgentName, Version: s.versionForCaller(r, v, acc.manage, handles)}
		if row.InReviewSince != nil {
			t := *row.InReviewSince
			sub.InReviewSince = &t
		}
		out = append(out, sub)
	}
	page := SubmissionPage{Submissions: out}
	if len(rows) == limit {
		last := rows[len(rows)-1].AgentVersion
		cur := encodeCursor(last.CreatedAt, last.ID)
		page.NextCursor = &cur
		setNextLink(w, r, cur)
	}
	writeJSON(w, http.StatusOK, page)
}

// WithdrawVersion implements POST .../versions/{version}/withdraw: a
// publisher takes back a version waiting in human review. The review item
// closes and the version becomes withdrawn in one transaction; the number
// stays used.
func (s *Server) WithdrawVersion(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	a, v, ok := s.versionOrNotFound(w, r, ns, name, version, auth.ActAgentPublish)
	if !ok {
		return
	}
	var req WithdrawVersionJSONRequestBody
	if err := readJSONOptional(r, &req); err != nil {
		problemBadRequest(w, r, "Could not decode the request body: "+err.Error())
		return
	}
	reason := ""
	if req.Reason != nil {
		reason = strings.TrimSpace(*req.Reason)
	}
	if len(reason) > 500 {
		problemValidation(w, r, "The reason must be at most 500 characters.")
		return
	}
	e := auditEvent(r, audit.ActionVersionWithdraw)
	if a.NamespaceKind == "org" {
		e.OrgID = a.NamespaceID
	}
	if err := s.reg.Withdraw(r.Context(), v.ID, principalFrom(r.Context()).UserID, reason, e); err != nil {
		if errors.Is(err, registry.ErrNotInReview) {
			problemConflict(w, r, withdrawRefusal(registry.Status(v.Status)))
			return
		}
		s.log.ErrorContext(r.Context(), "withdraw", "version", v.ID, "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// withdrawRefusal says why a version cannot be withdrawn, from the state it
// was in when the request arrived.
func withdrawRefusal(st registry.Status) string {
	switch st {
	case registry.StatusSubmitted, registry.StatusScanning:
		return "This version is still being scanned. Only a version held for review can be withdrawn; wait for the scan's verdict."
	case registry.StatusPublished, registry.StatusQuarantined:
		return "This version is published. Yank it instead (POST .../yank)."
	case registry.StatusWithdrawn:
		return "This version is already withdrawn."
	case registry.StatusNeedsReview:
		return "A reviewer already decided this version, so it can no longer be withdrawn."
	default:
		return "Only a version waiting in review can be withdrawn; this one is " + string(st) + "."
	}
}
