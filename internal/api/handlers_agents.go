package api

import (
	"context"
	"errors"
	"fmt"
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
		Builtin:         a.Builtin,
		CreatedAt:       a.CreatedAt,
		RetiredAt:       a.RetiredAt,
	}
	if u := s.gitSSHURL(a.Namespace, a.Name); u != "" {
		out.GitSshUrl = &u
	}
	if maintain {
		ap := a.AutoPublishTags
		out.AutoPublishTags = &ap
		fp := a.AllowForcePush
		out.AllowForcePush = &fp
		ps := a.PipelineSkip
		out.PipelineSkip = &ps
	}
	return out
}

// agentForAction resolves ns/name and authorizes act for p — the one path
// every agent route takes, and the extensions' read seam (AgentReadable,
// agentry#381). registry.ErrNotFound for an agent that does not exist or
// that p may not read: a caller without read on a private agent —
// anonymous, or signed in without a role on it — gets the answer a
// missing name gets, before any 401 (which would itself say the name
// exists), so a private agent's existence is not discoverable by probing
// (§6.4; agentry#313, operator rule 2026-09-13). auth.ErrUnauthorized or
// auth.ErrForbidden for a reader the act refuses; a *registry.OrgGateError
// for the owning organization's state (suspended: absent to everyone; in
// its decommission hold: read-only), the agent beside it so the caller
// can name its namespace; anything else an internal error — an
// organization handle with no organization row included, which is a
// fault to log, not an absence.
func (s *Server) agentForAction(ctx context.Context, p *auth.Principal, ns, name string, act auth.Action) (registry.Agent, auth.AgentRole, error) {
	a, err := s.reg.Resolve(ctx, ns, name)
	if err != nil {
		return registry.Agent{}, auth.AgentRoleNone, err
	}
	role, err := s.reg.EffectiveRole(ctx, p, a)
	if err != nil {
		return registry.Agent{}, auth.AgentRoleNone, err
	}
	res := auth.AgentResource{Public: a.Visibility == "public", EffectiveRole: role}
	if err := auth.CheckAgent(p, res, act); err != nil {
		if act == auth.ActAgentRead || auth.CheckAgent(p, res, auth.ActAgentRead) != nil {
			return registry.Agent{}, auth.AgentRoleNone, registry.ErrNotFound
		}
		return registry.Agent{}, auth.AgentRoleNone, err
	}
	if err := s.reg.OrgGateFor(ctx, a, act); err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return a, role, fmt.Errorf("org gate: no organization row for the %s namespace: %v", a.Namespace, err)
		}
		return a, role, err
	}
	return a, role, nil
}

// resolveAgentForAction is agentForAction for a handler: the agent and the
// caller's role, or the problem written and false.
func (s *Server) resolveAgentForAction(w http.ResponseWriter, r *http.Request, ns, name string, act auth.Action) (registry.Agent, auth.AgentRole, bool) {
	a, role, err := s.agentForAction(r.Context(), principalFrom(r.Context()), ns, name, act)
	switch {
	case err == nil:
		return a, role, true
	case errors.Is(err, registry.ErrNotFound):
		problemNotFound(w, r)
	case errors.Is(err, auth.ErrUnauthorized):
		problemUnauthorized(w, r, "This request carried no valid session or token. Sign in and retry.")
	case errors.Is(err, auth.ErrForbidden):
		problemForbidden(w, r, "This credential does not carry the role or scope this action needs.")
	case s.orgGateProblem(w, r, a.Namespace, err):
		// The owning organization's state (agentry#363), written.
	default:
		s.log.ErrorContext(r.Context(), "agent access", "agent", ns+"/"+name, "err", err)
		problemInternal(w, r)
	}
	return registry.Agent{}, auth.AgentRoleNone, false
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
			problemForbidden(w, r, "Creating a QuickAgent here needs the namespace's owner, or active membership of the organization.")
		case errors.Is(err, auth.ErrUnauthorized):
			problemUnauthorized(w, r, "This request carried no valid session or token. Sign in and retry.")
		case errors.Is(err, registry.ErrPrivateAgentCap):
			problemPrivateAgentCap(w, r)
		case s.orgGateProblem(w, r, req.Namespace, err):
		case errors.Is(err, registry.ErrDenied):
			problemValidation(w, r, sentence(err.Error()))
		case isUniqueViolation(err) && s.nameHeld(r.Context(), req.Namespace, req.Name):
			writeProblem(w, r, http.StatusConflict, "name-held", "That name is held",
				"A QuickAgent of that name was deleted from this namespace, and a deleted QuickAgent's name is never used again, so no one who installed it can be handed something else under it. Choose another name.")
		case isUniqueViolation(err):
			problemConflict(w, r, "This namespace already has a QuickAgent with that name.")
		default:
			s.log.ErrorContext(r.Context(), "create agent", "err", err)
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
	// Private agents appear only for callers the by-name route would let
	// read them by namespace alone — the owning user, or an active member
	// of the owning org, who since agentry#362 holds publish on its agents
	// — so a listing never names an agent its reader could not open
	// (agentry#313). A pending member holds nothing and sees nothing. Per-
	// agent grant holders are not in the listing either: conservative.
	includePrivate := false
	if h, err := s.q().GetHandle(r.Context(), params.Namespace); err == nil {
		// A suspended or erased organization's namespace is absent to
		// everyone (agentry#363); the query says the same on its own.
		if h.Kind == "org" {
			if err := s.reg.OrgGate(r.Context(), h.ID, auth.ActPublicRead); err != nil {
				if !s.orgGateProblem(w, r, params.Namespace, err) {
					s.log.ErrorContext(r.Context(), "org gate", "org", h.ID, "err", err)
					problemInternal(w, r)
				}
				return
			}
		}
		if !p.Anonymous {
			includePrivate = auth.NamespaceDerivedAgentRole(p, h.Kind, h.ID, p.Role(h.ID)) != auth.AgentRoleNone
		}
	}
	lp := storegen.ListAgentsByNamespaceParams{Handle: params.Namespace, IncludePrivate: includePrivate}
	if params.Q != nil {
		q := strings.TrimSpace(*params.Q)
		if len(q) > 200 {
			problemValidation(w, r, "The search term must be at most 200 characters.")
			return
		}
		// ILIKE's own wildcards are matched literally: the term is a
		// substring, not a pattern.
		lp.Query = strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q)
	}
	if params.State != nil {
		lp.State = string(*params.State)
	}
	if params.Sort != nil && *params.Sort != ListAgentsParamsSortName {
		lp.Sort = string(*params.Sort)
	}
	rows, err := s.q().ListAgentsByNamespace(r.Context(), lp)
	if err != nil {
		s.log.ErrorContext(r.Context(), "list agents", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]Agent, 0, len(rows))
	base := strings.TrimSuffix(s.cfg.BaseURL, "/")
	for _, row := range rows {
		installs := int(row.Installs)
		out = append(out, Agent{
			Id: row.ID, Namespace: row.Namespace, Name: row.Name,
			Modes: apiModes(row.Modes), Visibility: AgentVisibility(row.Visibility),
			Summary: row.Summary, DefaultBranch: "main",
			GitHttpUrl:      base + "/" + row.Namespace + "/" + row.Name + ".git",
			QuarantineState: AgentQuarantineState(row.QuarantineState),
			Builtin:         row.Builtin,
			CreatedAt:       row.CreatedAt,
			RetiredAt:       row.RetiredAt,
			Installs30d:     &installs,
			LastSubmittedAt: row.LastSubmittedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// nameHeld reports whether ns/name is a deleted agent's tombstone, whose
// name is never used again (agentry#942, D4) — what a create that collided
// on the name collided with. A lookup that fails says nothing is held, and
// the create's own conflict answers.
func (s *Server) nameHeld(ctx context.Context, ns, name string) bool {
	a, err := s.reg.ResolveIncludingDeleted(ctx, ns, name)
	return err == nil && a.DeletedAt != nil
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
	p := principalFrom(r.Context())
	res := auth.AgentResource{Public: a.Visibility == "public", EffectiveRole: role}
	maintain := auth.CheckAgent(p, res, auth.ActAgentMaintain) == nil
	out := s.agentToAPI(a, maintain)
	// Whether the caller may add a version (agentry#875): the desktop's
	// sign-in token carries agent:publish and never org:admin, so it reads
	// this where the site reads the maintainer's settings to offer Edit.
	if auth.CheckAgent(p, res, auth.ActAgentPublish) == nil {
		yes := true
		out.CanPublish = &yes
	}
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
	a, role, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentMaintain)
	if !ok {
		return
	}
	var req UpdateAgentJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	// Two fields in this body are not settings. Changing who can see an
	// agent, and allowing its history to be rewritten, are the
	// namespace's administrators' to decide — not everyone who may
	// release it (D19, agentry#362). An organization's members hold
	// publish, and the line the admin/member split draws is that a member
	// adds to the organization's agents while the acts that expose or
	// destroy what is already there stay with the admins. (Yanking a
	// release is neither: it is the publisher's own safety valve, and the
	// version stays on the record marked yanked.) The rest of this body
	// is settings, which maintain covers.
	administers := func() bool {
		return auth.CheckAgent(principalFrom(r.Context()),
			auth.AgentResource{Public: a.Visibility == "public", EffectiveRole: role},
			auth.ActAgentAdminister) == nil
	}
	if req.Visibility != nil && string(*req.Visibility) != a.Visibility && !administers() {
		problemForbidden(w, r, "Changing this QuickAgent's visibility needs the "+a.Namespace+" namespace's administrators.")
		return
	}
	// A retired agent comes back by Restore, which puts back the
	// visibility it had (agentry#942); making it public here would leave
	// it public and retired at once. Decided again under the row lock.
	if req.Visibility != nil && string(*req.Visibility) == "public" && a.RetiredAt != nil {
		problemAgentRetired(w, r)
		return
	}
	if req.AllowForcePush != nil && *req.AllowForcePush != a.AllowForcePush && !administers() {
		problemForbidden(w, r, "Allowing force pushes rewrites history everyone else is working from, so it needs the "+a.Namespace+" namespace's administrators.")
		return
	}
	// Taking the agent off the pipeline (M21, D16) is the administrators'
	// too; whether the agent may be — private, an organization's, the tier
	// including it — and whether it may become public are decided below,
	// under the agent's row lock, beside the write.
	if req.PipelineSkip != nil && *req.PipelineSkip != a.PipelineSkip && !administers() {
		problemForbidden(w, r, "Taking this QuickAgent off the pipeline needs the "+a.Namespace+" namespace's administrators.")
		return
	}
	// Built-in (agentry#737, DEV-174) is the platform's to say, not the
	// namespace's: it labels the agent as part of the application, so no
	// author, and no administrator of the namespace, may set or clear it —
	// only platform staff, and marking it only in a first-party
	// organization, where the built-ins are published (agentry-cli#470,
	// DR-50). Anyone else's value is never written, even when it matches
	// the row as read here: under a staff change landing between this read
	// and the write it would undo that change.
	staff := principalFrom(r.Context()).PlatformStaff
	if req.Builtin != nil && *req.Builtin != a.Builtin && !staff {
		problemForbidden(w, r, "Marking or unmarking a QuickAgent as built-in is open to platform staff only.")
		return
	}
	if req.Builtin != nil && *req.Builtin && !a.Builtin && (a.NamespaceKind != "org" || !firstPartyOrg(a.Namespace)) {
		writeProblem(w, r, http.StatusConflict, "builtin-first-party", "Only the platform's own namespace holds built-in QuickAgents", "Built-in QuickAgents are the packages the Agentry CLI embeds, published under the platform's own organization; "+a.Namespace+" is not one of its namespaces.")
		return
	}
	if req.PipelineSkip != nil && *req.PipelineSkip && a.NamespaceKind != "org" {
		writeProblem(w, r, http.StatusConflict, "pipeline-skip-personal", "Only an organization's QuickAgent can skip the pipeline", "pipeline: skip is set by an organization's administrators on the organization's own private QuickAgents; a personal namespace stays on the pipeline.")
		return
	}
	if req.PipelineSkip != nil && *req.PipelineSkip && !a.PipelineSkip {
		f, err := s.orgFeatures(r.Context(), a.NamespaceID)
		if err != nil {
			s.log.ErrorContext(r.Context(), "update agent: features", "org", a.NamespaceID, "err", err)
			problemInternal(w, r)
			return
		}
		if !f.UnscannedAgents {
			problemFeatureNotIncluded(w, r, "Unscanned private QuickAgents are not included in this organization's subscription.")
			return
		}
	}
	params := storegen.UpdateAgentSettingsParams{ID: a.ID}
	detail := map[string]any{}
	if req.Summary != nil {
		v := strings.TrimSpace(*req.Summary)
		if len(v) > 140 {
			problemValidation(w, r, "The summary must be at most 140 characters.")
			return
		}
		params.Summary = &v
		detail["summary"] = true
	}
	if req.Visibility != nil {
		v := string(*req.Visibility)
		// Turning an agent private holds one more private agent, which the
		// namespace's tier may cap (plan subscription-tiers §5.3): counted
		// inside the transaction below, under the namespace's lock
		// (agentry#411).
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
	if req.PipelineSkip != nil {
		params.PipelineSkip = req.PipelineSkip
		detail["pipelineSkip"] = *req.PipelineSkip
	}
	if req.Builtin != nil && staff {
		params.Builtin = req.Builtin
		detail["builtin"] = *req.Builtin
	}
	if len(detail) == 0 {
		problemValidation(w, r, "Send at least one field to update.")
		return
	}
	// The two states DEV-115 rules out — the flag on a public agent, and
	// a public agent holding a version admitted unscanned — are decided
	// on the row as it is under the lock, not as it was read above, so
	// two requests cannot each pass on a stale row; the table's CHECK is
	// the wall behind the first.
	var refuse func()
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		locked, err := q.GetAgentForUpdate(r.Context(), a.ID)
		if err != nil {
			return err
		}
		if req.Visibility != nil && string(*req.Visibility) == "private" && locked.Visibility != "private" {
			if err := s.reg.CheckPrivateAgentCapInTx(r.Context(), q, a); err != nil {
				if errors.Is(err, registry.ErrPrivateAgentCap) {
					refuse = func() { problemPrivateAgentCap(w, r) }
					return errRefused
				}
				return err
			}
		}
		if req.Visibility != nil && string(*req.Visibility) == "public" && locked.RetiredAt != nil {
			refuse = func() { problemAgentRetired(w, r) }
			return errRefused
		}
		visibility, skip := locked.Visibility, locked.PipelineSkip
		if req.Visibility != nil {
			visibility = string(*req.Visibility)
		}
		if req.PipelineSkip != nil {
			skip = *req.PipelineSkip
		}
		if skip && visibility == "public" {
			if req.PipelineSkip != nil && *req.PipelineSkip {
				// The request sets the flag on an agent that is, or
				// becomes, public.
				refuse = func() {
					writeProblem(w, r, http.StatusConflict, "pipeline-skip-public", "A public QuickAgent is always scanned", "pipeline: skip is for a private QuickAgent of an organization's. Make it private first, or leave it on the pipeline.")
				}
			} else {
				// The request makes public an agent whose flag is set.
				refuse = func() {
					writeProblem(w, r, http.StatusConflict, "agent-unscanned", "Unscanned versions cannot be made public", "This QuickAgent is off the pipeline: clear pipeline: skip before making it public.")
				}
			}
			return errRefused
		}
		if visibility == "public" && locked.Visibility != "public" {
			n, err := q.CountUnscannedVersionsStanding(r.Context(), a.ID)
			if err != nil {
				return err
			}
			if n > 0 {
				refuse = func() { problemAgentUnscanned(w, r, n) }
				return errRefused
			}
		}
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
	if errors.Is(err, errRefused) {
		refuse()
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "update agent", "err", err)
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
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentAdminister)
	if !ok {
		return
	}
	rows, err := s.q().ListAgentGrants(r.Context(), a.ID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "list grants", "err", err)
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
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentAdminister)
	if !ok {
		return
	}
	var req SetAgentUserGrantJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	if !auth.ValidAgentRole(auth.AgentRole(req.Role)) {
		problemValidation(w, r, "The role must be read, write, maintain, or publish.")
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
		s.log.ErrorContext(r.Context(), "set user grant", "err", err)
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
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentAdminister)
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
		s.log.ErrorContext(r.Context(), "remove user grant", "err", err)
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
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentAdminister)
	if !ok {
		return
	}
	if a.NamespaceKind != "org" {
		problemValidation(w, r, "Team grants apply only to QuickAgents in an org namespace.")
		return
	}
	var req SetAgentTeamGrantJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	if !auth.ValidAgentRole(auth.AgentRole(req.Role)) {
		problemValidation(w, r, "The role must be read, write, maintain, or publish.")
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
		s.log.ErrorContext(r.Context(), "set team grant", "err", err)
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
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentAdminister)
	if !ok {
		return
	}
	if a.NamespaceKind != "org" {
		problemValidation(w, r, "Team grants apply only to QuickAgents in an org namespace.")
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
		s.log.ErrorContext(r.Context(), "remove team grant", "err", err)
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

// errRefused is a decision taken inside a transaction that the handler
// answers with the problem the closure holds, once the transaction has
// rolled back.
var errRefused = errors.New("api: refused under the lock")
