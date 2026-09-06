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
	"github.com/blaktron/agentry/internal/webhook"
)

// agentToAPI maps a resolved agent row to the wire shape. maintain toggles
// maintainer-only fields.
// gitSSHURL is the SSH clone URL when the deployment serves the SSH
// transport (§6.1 Q7, agentry#70); "" otherwise.
func (s *Server) gitSSHURL(ns, name string) string {
	base := strings.TrimSuffix(s.cfg.Git.SSHPublicURL, "/")
	if base == "" {
		return ""
	}
	return base + "/" + ns + "/" + name + ".git"
}

func (s *Server) agentToAPI(a registry.Agent, maintain bool) Agent {
	base := strings.TrimSuffix(s.cfg.BaseURL, "/")
	out := Agent{
		Id:              a.ID,
		Namespace:       a.Namespace,
		Name:            a.Name,
		Modes:           apiModes(a.Modes),
		Visibility:      AgentVisibility(a.Visibility),
		Summary:         a.Summary,
		DefaultBranch:   a.DefaultBranch,
		GitHttpUrl:      base + "/" + a.Namespace + "/" + a.Name + ".git",
		QuarantineState: AgentQuarantineState(a.QuarantineState),
		CreatedAt:       a.CreatedAt,
	}
	if u := s.gitSSHURL(a.Namespace, a.Name); u != "" {
		out.GitSshUrl = &u
	}
	if maintain {
		ap := a.AutoPublishTags
		out.AutoPublishTags = &ap
		fp := a.AllowForcePush
		out.AllowForcePush = &fp
	}
	return out
}

// resolveAgentForAction loads the agent and authorizes act against the
// caller's effective role. Private agents 404 for read-denied callers
// (existence privacy, §6.4).
func (s *Server) resolveAgentForAction(w http.ResponseWriter, r *http.Request, ns, name string, act auth.Action) (registry.Agent, auth.AgentRole, bool) {
	a, err := s.reg.Resolve(r.Context(), ns, name)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			problemNotFound(w, r)
		} else {
			s.log.Error("agent resolve", "err", err)
			problemInternal(w, r)
		}
		return registry.Agent{}, auth.AgentRoleNone, false
	}
	p := principalFrom(r.Context())
	role, err := s.reg.EffectiveRole(r.Context(), p, a)
	if err != nil {
		s.log.Error("agent role", "err", err)
		problemInternal(w, r)
		return registry.Agent{}, auth.AgentRoleNone, false
	}
	res := auth.AgentResource{Public: a.Visibility == "public", EffectiveRole: role}
	if err := auth.CheckAgent(p, res, act); err != nil {
		switch {
		case errors.Is(err, auth.ErrUnauthorized):
			problemUnauthorized(w, r, "")
		case act == auth.ActAgentRead || auth.CheckAgent(p, res, auth.ActAgentRead) != nil:
			// Caller cannot even read the agent: hide its existence.
			problemNotFound(w, r)
		default:
			problemForbidden(w, r, "")
		}
		return registry.Agent{}, auth.AgentRoleNone, false
	}
	return a, role, true
}

// CreateAgent implements POST /agents (§9.2).
func (s *Server) CreateAgent(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActAgentCreate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req CreateAgentRequest
	if !readJSON(w, r, &req) {
		return
	}
	visibility := "private"
	if req.Visibility != nil {
		visibility = string(*req.Visibility)
	}
	summary := ""
	if req.Summary != nil {
		summary = strings.TrimSpace(*req.Summary)
	}
	p := principalFrom(r.Context())
	modes := make([]string, 0, len(req.Modes))
	for _, m := range req.Modes {
		modes = append(modes, string(m))
	}
	a, err := s.reg.CreateAgent(r.Context(), p, registry.CreateAgentInput{
		Namespace:  req.Namespace,
		Name:       req.Name,
		Visibility: visibility,
		Summary:    summary,
		Modes:      modes,
	}, auditEvent(r, audit.ActionAgentCreate))
	if err != nil {
		switch {
		case errors.Is(err, registry.ErrNotFound):
			problemNotFound(w, r)
		case errors.Is(err, auth.ErrForbidden):
			problemForbidden(w, r, "namespace access denied")
		case errors.Is(err, auth.ErrUnauthorized):
			problemUnauthorized(w, r, "")
		case errors.Is(err, registry.ErrDenied):
			problemValidation(w, r, err.Error())
		case isUniqueViolation(err):
			problemConflict(w, r, "agent name already exists in namespace")
		default:
			s.log.Error("create agent", "err", err)
			problemInternal(w, r)
		}
		return
	}
	// §9.3 catalog (agentry#56); org namespaces only — personal namespaces
	// have no webhook endpoints.
	s.emitAgentEvent(r.Context(), a.ID, webhook.EventAgentCreated, map[string]any{
		"namespace": a.Namespace, "name": a.Name, "modes": a.Modes, "visibility": a.Visibility,
	})
	writeJSON(w, http.StatusCreated, s.agentToAPI(a, true))
}

// ListAgents implements GET /agents?namespace= (public listing).
func (s *Server) ListAgents(w http.ResponseWriter, r *http.Request, params ListAgentsParams) {
	if !s.authorize(w, r, auth.ActPublicRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	// Private agents appear only for namespace insiders; per-agent grant
	// visibility in listings lands with search (M5) — conservative for now.
	includePrivate := false
	if !p.Anonymous {
		if h, err := s.q().GetHandle(r.Context(), params.Namespace); err == nil {
			switch h.Kind {
			case "user":
				includePrivate = h.ID == p.UserID
			case "org":
				includePrivate = p.Role(h.ID) != auth.RoleNone
			}
		}
	}
	rows, err := s.q().ListAgentsByNamespace(r.Context(), storegen.ListAgentsByNamespaceParams{
		Handle: params.Namespace, IncludePrivate: includePrivate,
	})
	if err != nil {
		s.log.Error("list agents", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]Agent, 0, len(rows))
	base := strings.TrimSuffix(s.cfg.BaseURL, "/")
	for _, row := range rows {
		out = append(out, Agent{
			Id: row.ID, Namespace: row.Namespace, Name: row.Name,
			Modes: apiModes(row.Modes), Visibility: AgentVisibility(row.Visibility),
			Summary: row.Summary, DefaultBranch: "main",
			GitHttpUrl:      base + "/" + row.Namespace + "/" + row.Name + ".git",
			QuarantineState: AgentQuarantineState(row.QuarantineState),
			CreatedAt:       row.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// GetAgent implements GET /agents/{ns}/{name}.
func (s *Server) GetAgent(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	a, role, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return
	}
	maintain := auth.CheckAgent(principalFrom(r.Context()), auth.AgentResource{Public: a.Visibility == "public", EffectiveRole: role}, auth.ActAgentMaintain) == nil
	out := s.agentToAPI(a, maintain)
	// Open dependency alerts (agentry#177): public on the page, because a
	// consumer deciding whether to install needs them as much as the author.
	alerts := s.dependencyAlertsForAgent(r, a.ID, a.Namespace+"/"+a.Name)
	out.DependencyAlerts = &alerts
	writeJSON(w, http.StatusOK, out)
}

// UpdateAgent implements PATCH /agents/{ns}/{name} (maintain).
func (s *Server) UpdateAgent(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentMaintain)
	if !ok {
		return
	}
	var req UpdateAgentJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	params := storegen.UpdateAgentSettingsParams{ID: a.ID}
	detail := map[string]any{}
	if req.Summary != nil {
		v := strings.TrimSpace(*req.Summary)
		if len(v) > 140 {
			problemValidation(w, r, "summary must be at most 140 characters")
			return
		}
		params.Summary = &v
		detail["summary"] = true
	}
	if req.Visibility != nil {
		v := string(*req.Visibility)
		params.Visibility = &v
		detail["visibility"] = v
	}
	if req.AutoPublishTags != nil {
		params.AutoPublishTags = req.AutoPublishTags
		detail["autoPublishTags"] = *req.AutoPublishTags
	}
	if req.AllowForcePush != nil {
		params.AllowForcePush = req.AllowForcePush
		detail["allowForcePush"] = *req.AllowForcePush
	}
	if len(detail) == 0 {
		problemValidation(w, r, "nothing to update")
		return
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.UpdateAgentSettings(r.Context(), params); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionAgentUpdate)
		if a.NamespaceKind == "org" {
			e.OrgID = a.NamespaceID
		}
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = detail
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("update agent", "err", err)
		problemInternal(w, r)
		return
	}
	updated, err := s.reg.Resolve(r.Context(), ns, name)
	if err != nil {
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.agentToAPI(updated, true))
}

// ListAgentGrants implements GET /agents/{ns}/{name}/grants (maintain).
func (s *Server) ListAgentGrants(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentMaintain)
	if !ok {
		return
	}
	rows, err := s.q().ListAgentGrants(r.Context(), a.ID)
	if err != nil {
		s.log.Error("list grants", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]AgentGrant, 0, len(rows))
	for _, g := range rows {
		out = append(out, AgentGrant{Kind: AgentGrantKind(g.Kind), Grantee: g.Grantee, Role: AgentRole(g.Role)})
	}
	writeJSON(w, http.StatusOK, out)
}

// SetAgentUserGrant implements PUT /agents/{ns}/{name}/grants/user/{handle}.
func (s *Server) SetAgentUserGrant(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, handle Handle) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentMaintain)
	if !ok {
		return
	}
	var req SetAgentUserGrantJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	if !auth.ValidAgentRole(auth.AgentRole(req.Role)) {
		problemValidation(w, r, "invalid role")
		return
	}
	target, ok := s.userOrNotFound(w, r, handle)
	if !ok {
		return
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.UpsertAgentUserGrant(r.Context(), storegen.UpsertAgentUserGrantParams{
			AgentID: a.ID, UserID: target.ID, Role: string(req.Role),
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionAgentGrantSet)
		if a.NamespaceKind == "org" {
			e.OrgID = a.NamespaceID
		}
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{"grantee": handle, "granteeKind": "user", "role": string(req.Role)}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("set user grant", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RemoveAgentUserGrant implements DELETE /agents/{ns}/{name}/grants/user/{handle}.
func (s *Server) RemoveAgentUserGrant(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, handle Handle) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentMaintain)
	if !ok {
		return
	}
	target, ok := s.userOrNotFound(w, r, handle)
	if !ok {
		return
	}
	var rows int64
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.DeleteAgentUserGrant(r.Context(), storegen.DeleteAgentUserGrantParams{AgentID: a.ID, UserID: target.ID})
		if err != nil {
			return err
		}
		rows = n
		if n == 0 {
			return nil
		}
		e := auditEvent(r, audit.ActionAgentGrantRemove)
		if a.NamespaceKind == "org" {
			e.OrgID = a.NamespaceID
		}
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{"grantee": handle, "granteeKind": "user"}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("remove user grant", "err", err)
		problemInternal(w, r)
		return
	}
	if rows == 0 {
		problemNotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetAgentTeamGrant implements PUT /agents/{ns}/{name}/grants/team/{team}.
// Team grants only make sense for org-namespace agents; the team must
// belong to the agent's org.
func (s *Server) SetAgentTeamGrant(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, team TeamSlug) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentMaintain)
	if !ok {
		return
	}
	if a.NamespaceKind != "org" {
		problemValidation(w, r, "team grants apply to org agents only")
		return
	}
	var req SetAgentTeamGrantJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	if !auth.ValidAgentRole(auth.AgentRole(req.Role)) {
		problemValidation(w, r, "invalid role")
		return
	}
	teamRow, err := s.q().GetTeam(r.Context(), storegen.GetTeamParams{OrgID: a.NamespaceID, Slug: team})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.UpsertAgentTeamGrant(r.Context(), storegen.UpsertAgentTeamGrantParams{
			AgentID: a.ID, TeamID: teamRow.ID, Role: string(req.Role),
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionAgentGrantSet)
		e.OrgID = a.NamespaceID
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{"grantee": team, "granteeKind": "team", "role": string(req.Role)}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("set team grant", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RemoveAgentTeamGrant implements DELETE /agents/{ns}/{name}/grants/team/{team}.
func (s *Server) RemoveAgentTeamGrant(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, team TeamSlug) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentMaintain)
	if !ok {
		return
	}
	if a.NamespaceKind != "org" {
		problemValidation(w, r, "team grants apply to org agents only")
		return
	}
	teamRow, err := s.q().GetTeam(r.Context(), storegen.GetTeamParams{OrgID: a.NamespaceID, Slug: team})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	var rows int64
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.DeleteAgentTeamGrant(r.Context(), storegen.DeleteAgentTeamGrantParams{AgentID: a.ID, TeamID: teamRow.ID})
		if err != nil {
			return err
		}
		rows = n
		if n == 0 {
			return nil
		}
		e := auditEvent(r, audit.ActionAgentGrantRemove)
		e.OrgID = a.NamespaceID
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{"grantee": team, "granteeKind": "team"}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("remove team grant", "err", err)
		problemInternal(w, r)
		return
	}
	if rows == 0 {
		problemNotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiModes converts a row's modes to the contract's enum values.
func apiModes(modes []string) []AgentMode {
	out := make([]AgentMode, 0, len(modes))
	for _, m := range modes {
		out = append(out, AgentMode(m))
	}
	return out
}
