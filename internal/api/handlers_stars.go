package api

// Stars and per-agent counters (§9.2 "Stars & counts").

import (
	"net/http"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// StarAgent implements PUT /user/stars/{ns}/{name}.
//
// Idempotent in both directions: PUT on an already-starred agent is 204, and
// so is DELETE on an unstarred one. A star is a bookmark, not a transaction —
// a client retrying after a dropped connection should not see an error.
// Read permission is required so starring cannot be used to probe for the
// existence of private agents.
func (s *Server) StarAgent(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "")
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.StarAgent(r.Context(), storegen.StarAgentParams{UserID: p.UserID, AgentID: a.ID}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionAgentStar)
		e.TargetKind, e.TargetID = "agent", a.ID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("star agent", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UnstarAgent implements DELETE /user/stars/{ns}/{name}.
func (s *Server) UnstarAgent(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "")
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.UnstarAgent(r.Context(), storegen.UnstarAgentParams{UserID: p.UserID, AgentID: a.ID})
		if err != nil {
			return err
		}
		if n == 0 {
			return nil // nothing removed: no event to record
		}
		e := auditEvent(r, audit.ActionAgentUnstar)
		e.TargetKind, e.TargetID = "agent", a.ID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("unstar agent", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetAgentStats implements GET /agents/{ns}/{name}/stats: star count plus
// lifetime and trailing-30-day installs from the download_stats rollup
// (§4.2). Public for public agents; private ones need read like every other
// agent-scoped route.
func (s *Server) GetAgentStats(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return
	}
	stars, err := s.q().CountAgentStars(r.Context(), a.ID)
	if err != nil {
		s.log.Error("agent stars", "err", err)
		problemInternal(w, r)
		return
	}
	counts, err := s.q().GetAgentInstallCounts(r.Context(), a.ID)
	if err != nil {
		s.log.Error("agent installs", "err", err)
		problemInternal(w, r)
		return
	}
	out := AgentStats{
		Stars:         stars,
		InstallsTotal: counts.InstallsTotal,
		Installs30d:   counts.Installs30d,
	}
	if p := principalFrom(r.Context()); !p.Anonymous {
		if starred, err := s.q().IsAgentStarred(r.Context(), storegen.IsAgentStarredParams{
			UserID: p.UserID, AgentID: a.ID,
		}); err == nil {
			out.Starred = &starred
		}
	}
	writeJSON(w, http.StatusOK, out)
}
