package api

// The agent endpoints beyond CRUD: deletion (outright, or as a
// tombstone), retire and restore, the activity feed, and tag
// browsing.

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

const (
	activityDefaultLimit = 30
	activityMaxLimit     = 100
	tagDefaultLimit      = 25
	tagMaxLimit          = 100
)

// publicActivityActions is the subset of the audit catalog safe to show to
// anyone who can see a public agent: the facts a consumer needs to judge the
// package — when versions were published and when they were pulled. Settings
// changes, grant changes, and submissions describe how the owning team works
// and stay behind a read grant.
var publicActivityActions = []string{
	string(audit.ActionVersionTransition),
	string(audit.ActionVersionYank),
	string(audit.ActionAgentQuarantine),
	string(audit.ActionAgentBlock),
	string(audit.ActionAgentReinstate),
	string(audit.ActionAdvisoryPublish),
}

// ownActivityActions are the actions that target a QuickAgent but describe
// a person's own choice rather than the QuickAgent's history: an account
// install and its removal. They stay on the person's own
// activity (GET /user/activity) and off the QuickAgent's feed at every
// role — a star is public approval, an install a private acceptance.
var ownActivityActions = map[string]bool{
	string(audit.ActionAgentInstall):   true,
	string(audit.ActionAgentUninstall): true,
}

// publicTransitionStates limits the public view of version.transition to the
// edges a consumer can already observe from the version list.
var publicTransitionStates = map[string]bool{
	"published": true, "yanked": true, "quarantined": true, "blocked": true,
}

// DeleteAgent implements DELETE /agents/{ns}/{name},
// for the namespace's administrators (ActAgentManage: a token's
// agent:manage or org:admin).
//
// The database forbids deleting agent_version rows outright — yanked hides, blocked
// disables, but the row and its digest survive so installed copies keep
// verifying. An agent with no version row at all is deleted outright, with
// its repository. One with version history is deleted as a tombstone
// (registry.Tombstone): its versions yanked, the row kept and hidden from
// every read by name, the name held. A submitted row still holds a foreign
// key to the agent, and a version in the pipeline or in review would be
// decided onto a deleted agent, so both wait for the verdict. Advisories,
// abuse reports and a quarantine or block are trust & safety records: they
// outlive the publisher's wish to remove the agent.
func (s *Server) DeleteAgent(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, params DeleteAgentParams) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentManage)
	if !ok {
		return
	}
	blockers, err := s.q().CountAgentDeleteBlockers(r.Context(), a.ID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "agent delete blockers", "err", err)
		problemInternal(w, r)
		return
	}
	switch {
	// An advisory reaches its readers through the public feed, which a
	// tombstone (private) leaves: deleting a flagged agent would take the
	// warning from everyone who installed it.
	case blockers.Advisories > 0 || blockers.AbuseReports > 0 || (blockers.Versions > 0 && a.QuarantineState != "none"):
		problemConflict(w, r,
			"This QuickAgent carries trust & safety records, so it cannot be deleted.")
		return
	case blockers.VersionsInFlight > 0:
		problemDeleteInFlight(w, r)
		return
	case blockers.Versions > 0:
		if params.Confirm == nil || *params.Confirm != a.Name {
			writeProblem(w, r, http.StatusUnprocessableEntity, "confirm-name", "Confirm the name to delete",
				"This QuickAgent has version history. Deleting it yanks every version and cannot be undone, and its name stays held: send confirm="+a.Name+" to go ahead.")
			return
		}
		if err := s.reg.Tombstone(r.Context(), a, auditEvent(r, audit.ActionAgentDelete)); err != nil {
			if errors.Is(err, registry.ErrVersionsInFlight) {
				problemDeleteInFlight(w, r)
				return
			}
			s.log.ErrorContext(r.Context(), "tombstone agent", "err", err)
			problemInternal(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	repoID := a.RepoID
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		// Audit BEFORE the row disappears: the event references the agent id,
		// and it must commit with the deletion or not at all.
		e := auditEvent(r, audit.ActionAgentDelete)
		if a.NamespaceKind == "org" {
			e.OrgID = a.NamespaceID
		}
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{"namespace": a.Namespace, "name": a.Name}
		if err := s.auditW.Write(r.Context(), q, e); err != nil {
			return err
		}
		if _, err := q.DeleteAgentByID(r.Context(), a.ID); err != nil {
			return err
		}
		return q.DeleteRepoByID(r.Context(), repoID)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "delete agent", "err", err)
		problemInternal(w, r)
		return
	}

	// Repo directory cleanup is best-effort and deliberately outside the
	// transaction: bytes left on disk are garbage, but a rolled-back deletion
	// because a directory was busy would be a bug (paths derive from the
	// repo uuid, so an orphan is inert).
	s.removeRepoDir(repoID.String())
	w.WriteHeader(http.StatusNoContent)
}

// problemDeleteInFlight refuses a delete while a version awaits its
// verdict, from the handler's check or the tombstone's own under the lock.
func problemDeleteInFlight(w http.ResponseWriter, r *http.Request) {
	problemConflict(w, r,
		"A version of this QuickAgent is still being scanned or reviewed. Delete it once that version has its verdict.")
}

// RetireAgent implements POST /agents/{ns}/{name}/retire.
// The namespace's administrators: it changes who can see the agent.
func (s *Server) RetireAgent(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentManage)
	if !ok {
		return
	}
	if err := s.reg.Retire(r.Context(), a, auditEvent(r, audit.ActionAgentRetire)); err != nil {
		s.log.ErrorContext(r.Context(), "retire agent", "err", err)
		problemInternal(w, r)
		return
	}
	s.writeAgentAfterChange(w, r, ns, name)
}

// RestoreAgent implements POST /agents/{ns}/{name}/restore.
func (s *Server) RestoreAgent(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentManage)
	if !ok {
		return
	}
	err := s.reg.Restore(r.Context(), a, auditEvent(r, audit.ActionAgentRestore))
	var unscanned *registry.UnscannedStandingError
	switch {
	case err == nil:
		s.writeAgentAfterChange(w, r, ns, name)
	case errors.Is(err, registry.ErrNotRetired):
		writeProblem(w, r, http.StatusConflict, "agent-not-retired", "Not retired",
			"This QuickAgent is not retired, so there is nothing to restore.")
	case errors.Is(err, registry.ErrPipelineSkipOnRestore):
		// The state PATCH refuses when it makes a flagged agent public,
		// answered the same way.
		writeProblem(w, r, http.StatusConflict, "agent-unscanned", "Unscanned versions cannot be made public",
			"This QuickAgent was public when it was retired and is off the pipeline now: clear pipeline: skip, then restore it.")
	case errors.As(err, &unscanned):
		problemAgentUnscanned(w, r, unscanned.N)
	case errors.Is(err, registry.ErrPrivateAgentCap):
		problemPrivateAgentCap(w, r)
	default:
		s.log.ErrorContext(r.Context(), "restore agent", "err", err)
		problemInternal(w, r)
	}
}

// writeAgentAfterChange answers a lifecycle change with the agent as it now
// is, maintainer fields included: only the namespace's administrators get
// here.
func (s *Server) writeAgentAfterChange(w http.ResponseWriter, r *http.Request, ns, name string) {
	updated, err := s.reg.Resolve(r.Context(), ns, name)
	if err != nil {
		s.log.ErrorContext(r.Context(), "agent after change", "agent", ns+"/"+name, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.agentToAPI(updated, true))
}

// removeRepoDir deletes the bare repository backing a deleted agent. Failures
// are logged, never surfaced: the registry row is already gone.
func (s *Server) removeRepoDir(repoID string) {
	dir := strings.TrimSpace(s.cfg.Git.DataDir)
	if dir == "" || len(repoID) < 2 {
		return
	}
	path := filepath.Join(dir, repoID[:2], repoID+".git")
	if err := os.RemoveAll(path); err != nil {
		s.log.Warn("repo dir cleanup", "repo", repoID, "path", path, "err", err)
	}
}

// ListAgentActivity implements GET /agents/{ns}/{name}/activity.
func (s *Server) ListAgentActivity(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, params ListAgentActivityParams) {
	if !s.requireDB(w, r) {
		return
	}
	a, role, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return
	}
	// "Read grant" here means an effective agent role, not the anonymous
	// read that a public agent grants everyone.
	full := role != auth.AgentRoleNone

	limit := clampLimit(params.Limit, activityDefaultLimit, activityMaxLimit)
	before, beforeID, ok := cursorParams(w, r, params.Cursor)
	if !ok {
		return
	}
	qp := storegen.ListAgentActivityParams{
		Limit: int32(limit), AgentID: &a.ID, BeforeTime: before, BeforeID: beforeID,
		PublicActions: []string{},
	}
	if !full {
		qp.PublicActions = publicActivityActions
	}
	rows, err := s.q().ListAgentActivity(r.Context(), qp)
	if err != nil {
		s.log.ErrorContext(r.Context(), "agent activity", "err", err)
		problemInternal(w, r)
		return
	}

	events := make([]ActivityEvent, 0, len(rows))
	for _, row := range rows {
		if ownActivityActions[row.Action] {
			continue
		}
		var detail map[string]interface{}
		if len(row.Detail) > 0 {
			_ = json.Unmarshal(row.Detail, &detail)
		}
		if !full && row.Action == string(audit.ActionVersionTransition) {
			// Public callers see only the transitions the version list
			// already reveals — not "this went to needs_review".
			to, _ := detail["to"].(string)
			if !publicTransitionStates[to] {
				continue
			}
		}
		ev := ActivityEvent{Id: row.ID, OccurredAt: row.OccurredAt, Action: row.Action}
		if row.Version != nil {
			ev.Version = row.Version
		} else if detail != nil {
			if v, ok := detail["version"].(string); ok && v != "" {
				ev.Version = &v
			}
		}
		if full {
			ev.ActorHandle = row.ActorHandle
			if detail != nil {
				ev.Detail = &detail
			}
		}
		events = append(events, ev)
	}

	page := ActivityPage{Events: events}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		cur := encodeCursor(last.OccurredAt, last.ID)
		page.NextCursor = &cur
		setNextLink(w, r, cur)
	}
	writeJSON(w, http.StatusOK, page)
}

// ListAgentsByTag implements GET /tags/{tag}: public agents whose
// latest published manifest carries the tag.
func (s *Server) ListAgentsByTag(w http.ResponseWriter, r *http.Request, tag string, params ListAgentsByTagParams) {
	if !s.authorize(w, r, auth.ActPublicRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	normalized := strings.ToLower(strings.TrimSpace(tag))
	limit := clampLimit(params.Limit, tagDefaultLimit, tagMaxLimit)
	before, beforeID, ok := cursorParams(w, r, params.Cursor)
	if !ok {
		return
	}
	rows, err := s.q().ListAgentsByTag(r.Context(), storegen.ListAgentsByTagParams{
		Tag: normalized, Limit: int32(limit), BeforeTime: before, BeforeID: beforeID,
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "tag listing", "err", err)
		problemInternal(w, r)
		return
	}
	hits := make([]SearchHit, 0, len(rows))
	for _, row := range rows {
		installs := int(row.Installs)
		qs := SearchHitQuarantineState(row.QuarantineState)
		hits = append(hits, SearchHit{
			Namespace: row.Namespace, Name: row.Name, Modes: apiModes(row.Modes),
			Summary: row.Summary, Installs30d: &installs, QuarantineState: &qs, Builtin: row.Builtin,
		})
	}
	page := TagPage{Tag: normalized, Results: hits}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		cur := encodeCursor(last.CreatedAt, last.ID)
		page.NextCursor = &cur
		setNextLink(w, r, cur)
	}
	writeJSON(w, http.StatusOK, page)
}
