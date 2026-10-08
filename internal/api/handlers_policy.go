package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/blaktron/agentry/internal/webhook"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// GetPlatformPolicy implements GET /platform/policy (public, read-only §8.6).
func (s *Server) GetPlatformPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActPublicRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	if row, err := s.q().GetBaselinePolicy(r.Context()); err == nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(row.Document)
		return
	}
	// Fall back to the compiled-in default baseline.
	doc, _ := json.Marshal(scan.DefaultBaseline())
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(doc)
}

// GetOrgPolicy implements GET /orgs/{org}/policy (admin+).
func (s *Server) GetOrgPolicy(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	row, err := s.q().GetPolicyForOrg(r.Context(), &orgRow.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(row.Document)
}

// SetOrgPolicy implements PUT /orgs/{org}/policy (admin; tighten-only §8.6).
func (s *Server) SetOrgPolicy(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgSettingsManage, orgRow.ID) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		problemBadRequest(w, r, "Could not read the policy document; it may be too large.")
		return
	}
	orgPolicy, err := scan.ParsePolicy(body)
	if err != nil {
		problemValidation(w, r, sentence(err.Error()))
		return
	}

	// Tighten-only guard (§8.6): the merged policy must equal the org
	// overlay merged onto baseline — a document that tries to loosen is
	// silently clamped by Merge, but we reject an attempt to set
	// maxAutoPublishSeverity looser than baseline so the author gets a clear
	// error rather than a surprise.
	baseline := s.baselinePolicy(r)
	if scan.LoosensBaseline(baseline, orgPolicy) {
		problemValidation(w, r, "An organization's policy may only tighten the platform baseline.")
		return
	}

	e := auditEvent(r, audit.ActionPolicyUpdate)
	e.OrgID = orgRow.ID
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.UpsertOrgPolicy(r.Context(), storegen.UpsertOrgPolicyParams{
			ID: newUUID(), OrgID: &orgRow.ID, Document: body,
		}); err != nil {
			return err
		}
		e.TargetKind, e.TargetID = "org", orgRow.ID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "set org policy", "err", err)
		problemInternal(w, r)
		return
	}
	merged := scan.Merge(baseline, orgPolicy)
	// §9.3 catalog (agentry#56): the org's policy changed; the payload names
	// the knobs present, never the whole document (it may be large).
	if s.webhooks != nil {
		keys := []string{}
		var doc map[string]any
		if json.Unmarshal(body, &doc) == nil {
			for k := range doc {
				keys = append(keys, k)
			}
			sort.Strings(keys)
		}
		s.emitOrgEvent(r.Context(), orgRow.ID, webhook.EventPolicyUpdated, map[string]any{"org": orgRow.Handle, "keys": keys})
	}
	writeJSON(w, http.StatusOK, merged)
}

func (s *Server) baselinePolicy(r *http.Request) scan.Policy {
	if row, err := s.q().GetBaselinePolicy(r.Context()); err == nil {
		if p, err := scan.ParsePolicy(row.Document); err == nil {
			return p
		}
	}
	return scan.DefaultBaseline()
}

// PlatformAgentAction implements POST /platform/agents/{ns}/{name}/{action}
// (§7 T&S actions: quarantine, block, reinstate). Platform staff only.
func (s *Server) PlatformAgentAction(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, actionParam PlatformAgentActionParamsAction) {
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		problemUnauthorized(w, r, "This request carried no valid session or token. Sign in and retry.")
		return
	}
	if !p.PlatformStaff {
		problemForbidden(w, r, "Trust & safety actions are open to platform staff only.")
		return
	}
	// A deleted agent's tombstone stays within trust & safety's reach
	// (agentry#942): whoever installed it before its publisher deleted it
	// still holds a copy.
	a, err := s.reg.ResolveIncludingDeleted(r.Context(), ns, name)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	var req PlatformAgentActionJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}

	action := string(actionParam)
	var auditAction audit.Action
	var quarantineState string
	switch action {
	case "quarantine":
		auditAction, quarantineState = audit.ActionAgentQuarantine, "quarantined"
	case "block":
		auditAction, quarantineState = audit.ActionAgentBlock, "blocked"
	case "reinstate":
		auditAction, quarantineState = audit.ActionAgentReinstate, "none"
	default:
		problemValidation(w, r, "The action must be quarantine, block, or reinstate.")
		return
	}

	// How many forks the action leaves as they are (agentry#943, D11): a
	// fork went through its own pipeline and may have changed, so it is not
	// quarantined or blocked with its origin, and staff see how many there
	// are on the record of the act. A count only, never which.
	// A count that cannot be read is left out of the record, never in
	// the way of the act.
	e := auditEvent(r, auditAction)
	e.TargetKind, e.TargetID = "agent", a.ID
	e.Detail = map[string]any{"reason": req.Reason}
	forks, ferr := s.q().CountForks(r.Context(), a.ID)
	if ferr != nil {
		s.log.ErrorContext(r.Context(), "platform action: fork count", "agent", a.ID, "err", ferr)
	} else {
		e.Detail["forks"] = forks
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.SetAgentQuarantineState(r.Context(), storegen.SetAgentQuarantineStateParams{
			ID: a.ID, QuarantineState: quarantineState,
		}); err != nil {
			return err
		}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "platform action", "err", err)
		problemInternal(w, r)
		return
	}

	// The agent flag alone changes nothing a consumer can observe: downloads
	// and resolution read the VERSION state machine (§7). Every T&S action
	// therefore has to walk the agent's versions too — without this, a
	// "blocked" agent kept serving 200s and the download handler's 410 branch
	// was unreachable code.
	sysEvent := audit.Event{ActorKind: audit.ActorSystem}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "trust & safety " + action
	}
	var moved int
	switch action {
	case "quarantine":
		if a.LatestPublishedVersionID != nil {
			if qerr := s.pipeline.Quarantine(r.Context(), *a.LatestPublishedVersionID, reason, sysEvent); qerr != nil {
				s.log.ErrorContext(r.Context(), "platform quarantine", "agent", a.ID, "err", qerr)
			} else {
				moved = 1
			}
		}
	case "block":
		moved, err = s.pipeline.Block(r.Context(), a.ID, reason, sysEvent)
	case "reinstate":
		moved, err = s.pipeline.Reinstate(r.Context(), a.ID, reason, sysEvent)
	}
	if err != nil {
		// The agent flag committed; the version walk did not finish. Report
		// it rather than returning 204 for a half-applied T&S action.
		s.log.ErrorContext(r.Context(), "platform action version walk", "action", action, "agent", a.ID, "err", err)
		problemInternal(w, r)
		return
	}
	s.log.InfoContext(r.Context(), "platform trust & safety action", "action", action,
		"agent", ns+"/"+name, "versions", moved, "forks", forks)
	w.WriteHeader(http.StatusNoContent)
}

// ListAdvisories implements GET /advisories?affecting=ns/name[&digest=] (§8.7,
// public; a holder's door to a private agent's, agentry#949).
func (s *Server) ListAdvisories(w http.ResponseWriter, r *http.Request, params ListAdvisoriesParams) {
	if !s.authorize(w, r, auth.ActPublicRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	if params.Affecting == nil || *params.Affecting == "" {
		s.listAdvisoryFeed(w, r, params)
		return
	}
	ref, err := registry.ParseRef(*params.Affecting)
	if err != nil {
		problemValidation(w, r, sentence(err.Error()))
		return
	}
	// The same read gate as the agent page: a private agent's advisories
	// are its readers' (agentry#313) and its holders' (agentry#949); anyone
	// else gets a missing name's 404.
	a, err := s.advisoryAgentFor(r.Context(), principalFrom(r.Context()), ref.Namespace, ref.Name, params.Digest)
	if !s.agentAccess(w, r, ref.Namespace, ref.Name, a, err) {
		return
	}
	rows, err := s.q().ListAdvisoriesForAgent(r.Context(), a.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]Advisory, 0, len(rows))
	for _, adv := range rows {
		item := Advisory{
			Id: adv.ID, AffectedVersions: adv.AffectedVersions,
			Severity: adv.Severity, Summary: adv.Summary,
		}
		if adv.Detail != nil {
			item.Detail = adv.Detail
		}
		if adv.PublishedAt != nil {
			item.PublishedAt = adv.PublishedAt
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

// advisoryAgentFor is agentForAction for the advisories of ns/name, with
// one door more (agentry#949): a caller who cannot read the agent but holds
// a release of it still gets it, so an advisory published after the agent
// went private, was retired or was deleted reaches the people who installed
// it. The owning organization's gate still answers first (agentry#363).
func (s *Server) advisoryAgentFor(ctx context.Context, p *auth.Principal, ns, name string, digest *string) (registry.Agent, error) {
	a, _, err := s.agentForAction(ctx, p, ns, name, auth.ActAgentRead)
	if !errors.Is(err, registry.ErrNotFound) {
		return a, err
	}
	notFound := err
	held, err := s.reg.ResolveIncludingDeleted(ctx, ns, name)
	if errors.Is(err, registry.ErrNotFound) {
		return registry.Agent{}, notFound
	}
	if err != nil {
		return registry.Agent{}, fmt.Errorf("advisory holder: %w", err)
	}
	arg := storegen.HoldsReleaseParams{AgentID: held.ID, Digest: digest}
	// An install counts only for a credential that may read the account's
	// own records, as GET /user/installs needs.
	if !p.Anonymous && auth.Check(p, auth.Resource{}, auth.ActUserSelfRead) == nil {
		arg.UserID = &p.UserID
	}
	if arg.UserID == nil && (digest == nil || *digest == "") {
		return registry.Agent{}, notFound
	}
	holds, err := s.q().HoldsRelease(ctx, arg)
	if err != nil {
		return registry.Agent{}, fmt.Errorf("advisory holder %s/%s: %w", ns, name, err)
	}
	if !holds {
		return registry.Agent{}, notFound
	}
	if err := s.reg.OrgGateFor(ctx, held, auth.ActAgentRead); err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return held, fmt.Errorf("org gate: no organization row for the %s namespace: %v", held.Namespace, err)
		}
		return held, err
	}
	return held, nil
}

const (
	advisoryFeedDefaultLimit = 25
	advisoryFeedMaxLimit     = 100
)

// listAdvisoryFeed is GET /advisories without `affecting` (agentry#24,
// DEV-038): the global feed over public agents, newest first, keyset-paged
// with a Link: rel="next" header. During a quarantine wave this is the page
// that shows the wave as a wave.
func (s *Server) listAdvisoryFeed(w http.ResponseWriter, r *http.Request, params ListAdvisoriesParams) {
	limit := clampLimit(params.Limit, advisoryFeedDefaultLimit, advisoryFeedMaxLimit)
	before, beforeID, ok := cursorParams(w, r, params.Cursor)
	if !ok {
		return
	}
	rows, err := s.q().ListAdvisoriesFeed(r.Context(), storegen.ListAdvisoriesFeedParams{
		Limit: int32(limit), BeforeTime: before, BeforeID: beforeID,
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "advisory feed", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]Advisory, 0, len(rows))
	for _, row := range rows {
		out = append(out, advisoryWithAgent(row.ID, row.AffectedVersions, row.Severity, row.Summary, row.Detail, row.PublishedAt, row.Namespace, row.AgentName))
	}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		setNextLink(w, r, encodeCursor(*last.PublishedAt, last.ID))
	}
	writeJSON(w, http.StatusOK, out)
}

// GetAdvisory implements GET /advisories/{advisoryId}: the permalink. Only
// advisories against public agents resolve; anything else is a 404 so the
// existence of a private agent's advisory is not discoverable by id.
func (s *Server) GetAdvisory(w http.ResponseWriter, r *http.Request, advisoryID openapi_types.UUID) {
	if !s.authorize(w, r, auth.ActPublicRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	row, err := s.q().GetAdvisoryPublic(r.Context(), advisoryID)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, advisoryWithAgent(row.ID, row.AffectedVersions, row.Severity, row.Summary, row.Detail, row.PublishedAt, row.Namespace, row.AgentName))
}

func advisoryWithAgent(id uuid.UUID, affected, severity, summary string, detail *string, publishedAt *time.Time, namespace, name string) Advisory {
	item := Advisory{Id: id, AffectedVersions: affected, Severity: severity, Summary: summary}
	if detail != nil {
		item.Detail = detail
	}
	if publishedAt != nil {
		item.PublishedAt = publishedAt
	}
	ref := namespace + "/" + name
	item.Agent = &ref
	return item
}
