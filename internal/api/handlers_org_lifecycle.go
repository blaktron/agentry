package api

// The organization's lifecycle. An admin — or platform staff, or the
// hosted product's pending-payment sweep through pkg/extension.Deps.Orgs —
// decommissions the organization: it enters a read-only hold (members keep
// read and export; registry.OrgGate refuses every change), and when the
// hold ends the sweep below erases it. Platform staff may also suspend an
// organization, which makes it and everything under it absent until it is
// reinstated, and reinstate cancels a hold that has not yet run.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// JobOrgDecommissionSweep is the queue kind of the hourly sweep that
// erases organizations whose decommission hold has ended.
const JobOrgDecommissionSweep = "org.decommission_sweep"

// The events the lifecycle fires to extension hooks (api.Event kinds),
// beside org.created: when a hold starts, when the erasure has run, and
// when staff suspend or reinstate.
const (
	eventOrgDecommissioning = "org.decommissioning"
	eventOrgDecommissioned  = "org.decommissioned"
	eventOrgSuspended       = "org.suspended"
	eventOrgReinstated      = "org.reinstated"
)

// DecommissionOrg implements POST /orgs/{org}/decommission (admin, session
// only). The body repeats the handle: an organization goes on a decision,
// never on a slip.
func (s *Server) DecommissionOrg(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgDecommission, orgRow.ID) {
		return
	}
	var req DecommissionOrgJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Confirm) != orgRow.Handle {
		problemValidation(w, r, "Type the organization's handle, "+orgRow.Handle+", as confirm to decommission it.")
		return
	}
	reason := ""
	if req.Reason != nil {
		reason = strings.TrimSpace(*req.Reason)
	}
	did, err := s.decommissionOrg(r.Context(), orgRow.ID, reason, auditEvent(r, audit.ActionOrgDecommission))
	if err != nil {
		s.log.ErrorContext(r.Context(), "decommission org", "org", orgRow.ID, "err", err)
		problemInternal(w, r)
		return
	}
	if !did {
		problemConflict(w, r, "The "+orgRow.Handle+" organization is not active, so it cannot be decommissioned from here.")
		return
	}
	s.writeOrg(w, r, orgRow.Handle)
}

// decommissionOrg starts the hold and reports whether this call did:
// an organization that is not active is left alone. The extension's
// sweep and the API share it.
func (s *Server) decommissionOrg(ctx context.Context, orgID uuid.UUID, reason string, actor audit.Event) (bool, error) {
	until := time.Now().UTC().Add(s.cfg.Orgs.DecommissionHold)
	did := false
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		n, err := q.DecommissionOrg(ctx, storegen.DecommissionOrgParams{
			ID: orgID, DecommissionAt: &until, DecommissionReason: nullableString(reason),
		})
		if err != nil {
			return err
		}
		did = n > 0
		if !did {
			return nil
		}
		e := actor
		e.Action = audit.ActionOrgDecommission
		e.OrgID = orgID
		e.TargetKind, e.TargetID = "org", orgID
		e.Detail = map[string]any{"reason": reason, "decommissionAt": until.Format(time.RFC3339)}
		return s.auditW.Write(ctx, q, e)
	})
	if err != nil || !did {
		return false, err
	}
	s.fireEvent(ctx, Event{Kind: eventOrgDecommissioning, OrgID: orgID,
		Payload: map[string]any{"decommissionAt": until.Format(time.RFC3339), "reason": reason}})
	return true, nil
}

// DecommissionOrgByExtension is pkg/extension.Deps.Orgs.Decommission: the
// hosted product's pending-payment sweep ending an organization nobody
// paid for, through the same path an admin's request takes.
func (s *Server) DecommissionOrgByExtension(ctx context.Context, orgID uuid.UUID, reason string) (bool, error) {
	if s.st == nil {
		return false, errors.New("api: no database to decommission the organization in")
	}
	return s.decommissionOrg(ctx, orgID, reason, audit.Event{ActorKind: audit.ActorSystem})
}

// SuspendOrg implements POST /orgs/{org}/suspend (platform staff).
func (s *Server) SuspendOrg(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireStaff(w, r) {
		return
	}
	orgRow, err := s.q().GetOrgByHandle(r.Context(), org)
	if s.lookupFailed(w, r, "org", err) {
		return
	}
	var req SuspendOrgJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > 500 {
		problemValidation(w, r, "Give a reason of 1-500 characters; it is audited.")
		return
	}
	did := false
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.SuspendOrg(r.Context(), storegen.SuspendOrgParams{ID: orgRow.ID, DecommissionReason: &reason})
		if err != nil {
			return err
		}
		did = n > 0
		if !did {
			return nil
		}
		e := auditEvent(r, audit.ActionOrgSuspend)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "org", orgRow.ID
		e.Detail = map[string]any{"reason": reason}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "suspend org", "org", orgRow.ID, "err", err)
		problemInternal(w, r)
		return
	}
	if !did {
		problemConflict(w, r, "The "+orgRow.Handle+" organization is "+orgRow.State+", not active; only an active organization is suspended.")
		return
	}
	s.fireEvent(r.Context(), Event{Kind: eventOrgSuspended, OrgID: orgRow.ID, Payload: map[string]any{"org": orgRow.Handle, "reason": reason}})
	s.writeOrg(w, r, orgRow.Handle)
}

// ReinstateOrg implements POST /orgs/{org}/reinstate (platform staff): a
// suspended organization comes back, and a decommission hold that has
// not run is cancelled. An erasure that ran cannot be undone.
func (s *Server) ReinstateOrg(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireStaff(w, r) {
		return
	}
	orgRow, err := s.q().GetOrgByHandle(r.Context(), org)
	if s.lookupFailed(w, r, "org", err) {
		return
	}
	did := false
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.ReinstateOrg(r.Context(), orgRow.ID)
		if err != nil {
			return err
		}
		did = n > 0
		if !did {
			return nil
		}
		e := auditEvent(r, audit.ActionOrgReinstate)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "org", orgRow.ID
		e.Detail = map[string]any{"from": orgRow.State}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "reinstate org", "org", orgRow.ID, "err", err)
		problemInternal(w, r)
		return
	}
	if !did {
		switch orgRow.State {
		case registry.OrgStateDecommissioned:
			problemConflict(w, r, "The "+orgRow.Handle+" organization has been erased; a decommissioned organization cannot come back.")
		default:
			problemConflict(w, r, "The "+orgRow.Handle+" organization is already active.")
		}
		return
	}
	s.fireEvent(r.Context(), Event{Kind: eventOrgReinstated, OrgID: orgRow.ID, Payload: map[string]any{"org": orgRow.Handle, "from": orgRow.State}})
	s.writeOrg(w, r, orgRow.Handle)
}

// writeOrg answers with the organization as it now is, settings included
// (the callers are its admins or platform staff).
func (s *Server) writeOrg(w http.ResponseWriter, r *http.Request, handle string) {
	row, err := s.q().GetOrgByHandle(r.Context(), handle)
	if err != nil {
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, orgToAPI(row, true))
}

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// registerOrgLifecycle wires the sweep onto a queue worker; the worker
// role enqueues it hourly (pkg/extension/agentryd.go).
func (s *Server) registerOrgLifecycle(q queue.Client) {
	if q == nil {
		return
	}
	q.Register(JobOrgDecommissionSweep, s.runOrgDecommissionSweep)
}

func (s *Server) runOrgDecommissionSweep(ctx context.Context, _ queue.Job) error {
	_, err := s.RunOrgDecommissionSweep(ctx)
	return err
}

// errOrgErasureDeferred reports that an organization's erasure did not run
// this time: a version of its is still in the pipeline, staff reinstated
// it between the listing and the lock, or its hold is not over. The next
// sweep looks again.
var errOrgErasureDeferred = errors.New("api: organization erasure deferred")

// RunOrgDecommissionSweep erases every organization whose hold has ended
// and reports how many it erased, then resumes the second phase of any
// erasure an earlier sweep left unfinished. Exported for the tests and for
// an operator's hand-run. A failure is logged and retried by the next
// sweep; the first is returned so the job is retried too.
func (s *Server) RunOrgDecommissionSweep(ctx context.Context) (int, error) {
	if s.st == nil {
		return 0, nil
	}
	due, err := s.q().ListOrgsDueForErasure(ctx)
	if err != nil {
		return 0, err
	}
	erased := 0
	var first error
	for _, row := range due {
		switch err := s.eraseOrg(ctx, row.ID, row.Handle); {
		case err == nil:
			erased++
		case errors.Is(err, errOrgErasureDeferred):
			s.log.InfoContext(ctx, "org erasure deferred", "org", row.Handle)
		default:
			s.log.ErrorContext(ctx, "org erasure", "org", row.Handle, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	// An erasure interrupted after its point of no return: the row is
	// decommissioned and the handle released, and releases are still live
	// under the retired agents. Finish what is left.
	unfinished, err := s.q().ListDecommissionedOrgsWithLiveVersions(ctx)
	if err != nil {
		return erased, err
	}
	for _, row := range unfinished {
		if err := s.retireOrgContent(ctx, row.ID, row.Handle, nil); err != nil {
			s.log.ErrorContext(ctx, "org erasure resumed", "org", row.Handle, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return erased, first
}

// eraseOrg is the end of the hold, in two phases. The first, one
// transaction under the organization's row lock, is the point of no
// return: it checks the state and the hold again (a reinstatement that
// landed meanwhile stops it whole, before anything is touched), defers on
// a version still in the pipeline, deletes invitations, memberships, teams,
// webhooks, domain claims, the policy and the audit exports, revokes
// org-bound tokens, retires the agents private, scrubs the row as
// decommissioned, releases the handle and audits org.erase. The second phase, which the sweep resumes if it is
// interrupted, yanks every published or quarantined version and rejects
// every one under review (version rows are immutable and are never
// deleted), deletes the archives and the export objects from the blob
// store and removes the bare repositories. With no member left to derive
// a role, every grant gone and the handle retired, the agents are
// unreadable from the moment the first phase commits.
func (s *Server) eraseOrg(ctx context.Context, orgID uuid.UUID, handle string) error {
	var (
		agents        []storegen.ListOrgAgentsForErasureRow
		exportKeys    []*string
		knowledgeKeys []string
	)
	counts := map[string]any{"handle": handle}
	err := s.st.WithTx(ctx, func(tq *storegen.Queries) error {
		if err := tq.LockOrg(ctx, orgID); err != nil {
			return err
		}
		state, err := tq.GetOrgState(ctx, orgID)
		if err != nil {
			return err
		}
		if state.State != registry.OrgStateDecommissioning || state.DecommissionAt == nil || state.DecommissionAt.After(time.Now()) {
			return errOrgErasureDeferred
		}
		versions, err := tq.ListOrgVersionsForErasure(ctx, orgID)
		if err != nil {
			return err
		}
		for _, v := range versions {
			if v.Status == string(registry.StatusSubmitted) || v.Status == string(registry.StatusScanning) {
				return errOrgErasureDeferred
			}
		}
		if agents, err = tq.ListOrgAgentsForErasure(ctx, orgID); err != nil {
			return err
		}
		if exportKeys, err = tq.ListOrgAuditExportKeys(ctx, orgID); err != nil {
			return err
		}
		counts["versions"] = len(versions)
		counts["agents"] = len(agents)
		// The audit record counts what went, keyed by table.
		steps := []struct {
			name string
			run  func() (int64, error)
		}{
			{"org_invitations", func() (int64, error) { return tq.DeleteOrgInvitations(ctx, orgID) }},
			{"memberships", func() (int64, error) { return tq.DeleteOrgMemberships(ctx, orgID) }},
			{"fold_in_declines", func() (int64, error) { return tq.DeleteOrgFoldInDeclines(ctx, orgID) }},
			{"teams", func() (int64, error) { return tq.DeleteOrgTeams(ctx, orgID) }},
			{"webhook_endpoints", func() (int64, error) { return tq.DeleteOrgWebhookEndpoints(ctx, orgID) }},
			{"domain_claims", func() (int64, error) { return tq.DeleteOrgDomainClaims(ctx, orgID) }},
			{"policies", func() (int64, error) { return tq.DeleteOrgPolicy(ctx, &orgID) }},
			{"audit_exports", func() (int64, error) { return tq.DeleteOrgAuditExports(ctx, orgID) }},
			{"agent_user_grants", func() (int64, error) { return tq.DeleteOrgAgentUserGrants(ctx, orgID) }},
			{"stars", func() (int64, error) { return tq.DeleteOrgAgentStars(ctx, orgID) }},
			{"account_installs", func() (int64, error) { return tq.DeleteOrgAgentAccountInstalls(ctx, orgID) }},
			{"patsRevoked", func() (int64, error) { return tq.RevokeOrgBoundPATs(ctx, &orgID) }},
		}
		for _, st := range steps {
			n, err := st.run()
			if err != nil {
				return err
			}
			counts[st.name] = n
		}
		// The organization's knowledge packs go with it, and
		// the key that opens them once the transaction has committed.
		if knowledgeKeys, err = knowledge.EraseOwner(ctx, tq, knowledge.Org(orgID)); err != nil {
			return err
		}
		counts["knowledge_objects"] = len(knowledgeKeys)
		if _, err := tq.RetireOrgAgents(ctx, orgID); err != nil {
			return err
		}
		n, err := tq.ScrubDecommissionedOrg(ctx, orgID)
		if err != nil {
			return err
		}
		if n == 0 {
			return errOrgErasureDeferred
		}
		// The handle is released the way an erased account's is: renamed
		// to a reserved sentinel carrying the whole id, so the name is
		// free and the sentinel collides with nothing.
		retired := "del-" + strings.ReplaceAll(orgID.String(), "-", "")
		if err := tq.ReleaseHandle(ctx, storegen.ReleaseHandleParams{ID: orgID, Handle: retired}); err != nil {
			return err
		}
		// Erasing the staff organization ends its members' staff with it:
		// every flagged account is recomputed in this
		// transaction. For any other organization nothing changes.
		if s.reg != nil {
			if _, err := s.reg.ResyncStaffIn(ctx, tq, registry.StaffSyncMembership, audit.Event{}); err != nil {
				return err
			}
		}
		return s.auditW.Write(ctx, tq, audit.Event{Action: audit.ActionOrgErase, ActorKind: audit.ActorSystem, OrgID: orgID,
			TargetKind: "org", TargetID: orgID, Detail: counts})
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errOrgErasureDeferred
		}
		return err
	}
	s.knowledge.FinishErasure(ctx, knowledge.Org(orgID), knowledgeKeys)
	s.log.InfoContext(ctx, "org erased", "org", handle, "counts", counts)
	s.fireEvent(ctx, Event{Kind: eventOrgDecommissioned, OrgID: orgID, Payload: map[string]any{"org": handle}})
	return s.retireOrgContent(ctx, orgID, handle, exportKeys)
}

// retireOrgContent is the erasure's second phase: the releases, the bytes
// and the repositories of an organization whose row is already
// decommissioned. Idempotent — a yanked version has no edge back, a blob
// that is gone is not an error, a directory already removed is nothing —
// so a resumed run after an interruption finishes what is left.
func (s *Server) retireOrgContent(ctx context.Context, orgID uuid.UUID, handle string, exportKeys []*string) error {
	q := s.q()
	versions, err := q.ListOrgVersionsForErasure(ctx, orgID)
	if err != nil {
		return err
	}
	for _, v := range versions {
		var to registry.Status
		switch registry.Status(v.Status) {
		case registry.StatusPublished, registry.StatusQuarantined:
			to = registry.StatusYanked
		case registry.StatusNeedsReview:
			to = registry.StatusRejected
		default:
			// Terminal already, or still in the pipeline: the watchdog
			// ends a stuck scan and the next sweep's resume finishes it.
			continue
		}
		e := audit.Event{Action: audit.ActionVersionYank, ActorKind: audit.ActorSystem, OrgID: orgID,
			Detail: map[string]any{"reason": "organization decommissioned"}}
		if err := s.reg.Transition(ctx, v.ID, to, "organization decommissioned", e); err != nil {
			return err
		}
	}
	if s.blobs != nil {
		for _, v := range versions {
			if v.ArchiveKey != nil && *v.ArchiveKey != "" {
				if err := s.blobs.Delete(ctx, *v.ArchiveKey); err != nil {
					return err
				}
			}
		}
		for _, k := range exportKeys {
			if k != nil && *k != "" {
				if err := s.blobs.Delete(ctx, *k); err != nil {
					return err
				}
			}
		}
	}
	agents, err := q.ListOrgAgentsForErasure(ctx, orgID)
	if err != nil {
		return err
	}
	// Best-effort and outside any transaction, as DeleteAgent's is: an
	// orphaned directory is inert garbage.
	for _, a := range agents {
		s.removeRepoDir(a.RepoID.String())
	}
	s.log.InfoContext(ctx, "org content retired", "org", handle, "versions", len(versions), "agents", len(agents))
	return nil
}
