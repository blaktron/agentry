package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
)

// ForkAgent implements POST /agents/{ns}/{name}/fork: a
// private copy of a public agent in a namespace the caller may create in.
// The handler records it; a worker copies the repository and submits the
// first version (registry.Fork, registry.CopyFork).
func (s *Server) ForkAgent(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.authorize(w, r, auth.ActAgentCreate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req ForkAgentJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r.Context())
	// The origin as the caller may read it: a private agent the caller
	// cannot open is the missing name's 404, as on every route by name.
	src, err := s.agentByNameForRead(w, r, p, ns, name)
	if err != nil {
		return
	}
	target := strings.TrimSpace(req.Namespace)
	forkName := ""
	if req.Name != nil {
		forkName = strings.TrimSpace(*req.Name)
	}
	f, err := s.reg.Fork(r.Context(), p, src, registry.ForkInput{Namespace: target, Name: forkName}, auditEvent(r, audit.ActionAgentFork))
	if err != nil {
		switch {
		case errors.Is(err, registry.ErrForkSourceNotForkable):
			writeProblem(w, r, http.StatusConflict, "fork-source", "This QuickAgent cannot be forked",
				"Only a public QuickAgent that Agentry has not quarantined or blocked can be forked.")
		case errors.Is(err, registry.ErrNothingToFork):
			writeProblem(w, r, http.StatusConflict, "nothing-to-fork", "Nothing to fork yet",
				"This QuickAgent has no published version, and a fork starts from one.")
		case errors.Is(err, registry.ErrNameTaken):
			writeProblem(w, r, http.StatusConflict, "name-taken", "That name is taken",
				target+" already has a QuickAgent of that name. Choose another name for the fork.")
		case errors.Is(err, registry.ErrNameHeld):
			writeProblem(w, r, http.StatusConflict, "name-held", "That name is held",
				"A QuickAgent of that name was deleted from "+target+", and a deleted QuickAgent's name is never used again. Choose another name for the fork.")
		case errors.Is(err, registry.ErrNotFound):
			writeProblem(w, r, http.StatusNotFound, "not-found", "No such namespace", "There is no namespace called "+target+".")
		case errors.Is(err, auth.ErrForbidden):
			problemForbidden(w, r, "Forking into "+target+" needs the namespace's owner, or active membership of the organization.")
		case errors.Is(err, auth.ErrUnauthorized):
			problemUnauthorized(w, r, "This request carried no valid session or token. Sign in and retry.")
		case errors.Is(err, registry.ErrPrivateAgentCap):
			problemPrivateAgentCap(w, r)
		case s.orgGateProblem(w, r, target, err):
		case errors.Is(err, registry.ErrDenied):
			problemValidation(w, r, sentence(err.Error()))
		default:
			s.log.ErrorContext(r.Context(), "fork agent", "origin", ns+"/"+name, "err", err)
			problemInternal(w, r)
		}
		return
	}
	out := s.agentToAPI(f, true)
	s.addLineage(r.Context(), &out, f)
	writeJSON(w, http.StatusAccepted, out)
}

// agentByNameForRead resolves ns/name for p to read and answers the
// problem itself when it cannot (the error is then non-nil).
func (s *Server) agentByNameForRead(w http.ResponseWriter, r *http.Request, p *auth.Principal, ns, name string) (registry.Agent, error) {
	a, _, err := s.agentForAction(r.Context(), p, ns, name, auth.ActAgentRead)
	switch {
	case err == nil:
		return a, nil
	case errors.Is(err, registry.ErrNotFound):
		problemNotFound(w, r)
	case s.orgGateProblem(w, r, ns, err):
	default:
		s.log.ErrorContext(r.Context(), "fork: resolve origin", "agent", ns+"/"+name, "err", err)
		problemInternal(w, r)
	}
	return registry.Agent{}, err
}

// addLineage fills what an agent's read says of forks: on a
// fork, its origin and its copy's state; on a public agent, how many forks
// it has, a count only (no read names a fork to the origin's publisher).
// A lineage read that fails leaves the fields out rather than failing the
// read: they say less, never something untrue.
func (s *Server) addLineage(ctx context.Context, out *Agent, a registry.Agent) {
	if a.ForkState != nil {
		st := AgentForkState(*a.ForkState)
		out.ForkState = &st
		if *a.ForkState == registry.ForkFailed && a.ForkDetail != "" {
			d := a.ForkDetail
			out.ForkDetail = &d
		}
		o, err := s.q().GetForkOrigin(ctx, a.ID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.log.ErrorContext(ctx, "fork origin", "agent", a.ID, "err", err)
		}
		if err == nil {
			out.ForkedFrom = &ForkOrigin{Namespace: o.OriginNamespace, Name: o.OriginName, Version: o.OriginVersion, Available: o.OriginPublic}
		}
	}
	if a.Visibility == "public" {
		n, err := s.q().CountForks(ctx, a.ID)
		if err != nil {
			s.log.ErrorContext(ctx, "fork count", "agent", a.ID, "err", err)
			return
		}
		c := int(n)
		out.ForkCount = &c
	}
}
