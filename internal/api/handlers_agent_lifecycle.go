package api

// The §9.2 agent endpoints beyond CRUD: deletion of never-published agents,
// the activity feed, and tag browsing.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
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

// publicTransitionStates limits the public view of version.transition to the
// edges a consumer can already observe from the version list.
var publicTransitionStates = map[string]bool{
	"published": true, "yanked": true, "quarantined": true, "blocked": true,
}

// DeleteAgent implements DELETE /agents/{ns}/{name} (§9.2 "only if never
// published"). Requires agent maintain.
//
// §4.3 forbids deleting agent_version rows outright — yanked hides, blocked
// disables, but the row and its digest survive so installed copies keep
// verifying. That makes "no versions past submitted" and "no version rows at
// all" the same rule in practice: a submitted row still holds a foreign key
// to the agent and cannot be removed to make way. The two counts are
// separated only so the refusal can say which case it is.
func (s *Server) DeleteAgent(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentMaintain)
	if !ok {
		return
	}
	blockers, err := s.q().CountAgentDeleteBlockers(r.Context(), a.ID)
	if err != nil {
		s.log.Error("agent delete blockers", "err", err)
		problemInternal(w, r)
		return
	}
	switch {
	case blockers.VersionsPastSubmitted > 0:
		problemConflict(w, r,
			"this agent has version history and cannot be deleted — yank the versions instead (§5.5)")
		return
	case blockers.Versions > 0:
		problemConflict(w, r,
			"a version submission is still in flight; delete is possible only before the first submission")
		return
	case blockers.Advisories > 0 || blockers.AbuseReports > 0:
		problemConflict(w, r,
			"this agent has trust & safety records attached and cannot be deleted")
		return
	}

	repoID := a.RepoID
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		// Audit BEFORE the row disappears: the event references the agent id,
		// and it must commit with the deletion or not at all (§12.6).
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
		s.log.Error("delete agent", "err", err)
		problemInternal(w, r)
		return
	}

	// Repo directory cleanup is best-effort and deliberately outside the
	// transaction: bytes left on disk are garbage, but a rolled-back deletion
	// because a directory was busy would be a bug (D-19 paths derive from the
	// repo uuid, so an orphan is inert).
	s.removeRepoDir(repoID.String())
	w.WriteHeader(http.StatusNoContent)
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

// ListAgentActivity implements GET /agents/{ns}/{name}/activity (§9.2).
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
		s.log.Error("agent activity", "err", err)
		problemInternal(w, r)
		return
	}

	events := make([]ActivityEvent, 0, len(rows))
	for _, row := range rows {
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

// ListAgentsByTag implements GET /tags/{tag} (§9.2): public agents whose
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
		s.log.Error("tag listing", "err", err)
		problemInternal(w, r)
		return
	}
	hits := make([]SearchHit, 0, len(rows))
	for _, row := range rows {
		installs := int(row.Installs)
		qs := SearchHitQuarantineState(row.QuarantineState)
		hits = append(hits, SearchHit{
			Namespace: row.Namespace, Name: row.Name, Kind: AgentKind(row.Kind),
			Summary: row.Summary, Installs30d: &installs, QuarantineState: &qs,
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
