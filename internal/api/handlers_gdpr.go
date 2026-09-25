package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Account deletion (§12.7). PII is purged and the account row is
// pseudonymized so that audit events keep a stable opaque actor id and
// already-published immutable content keeps working for the people who
// installed it. Published public versions are NOT deleted: the caller
// chooses to yank them (default) or transfer the namespace's agents to an
// org, because deleting bytes consumers depend on would break installs and
// defeat the yank-not-delete semantics of §5.5.

// DeleteCurrentUser implements DELETE /user.
func (s *Server) DeleteCurrentUser(w http.ResponseWriter, r *http.Request, params DeleteCurrentUserParams) {
	if !s.authorize(w, r, auth.ActUserSecurityManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Via != "session" {
		problemForbidden(w, r, "Deleting an account requires a session, not a token.")
		return
	}

	q := s.q()
	user, err := q.GetUserByID(r.Context(), p.UserID)
	if err != nil {
		problemInternal(w, r)
		return
	}

	// The last admin stays (D14, agentry#363): an organization is never
	// left without someone who can act, and erasing its only admin would.
	// Promote another member first, or decommission the organization.
	if org, err := q.GetOrgWhereUserIsLastAdmin(r.Context(), p.UserID); err == nil {
		problemLastAdmin(w, r, org)
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.log.ErrorContext(r.Context(), "last-admin guard", "err", err)
		problemInternal(w, r)
		return
	}

	// Published content chooser (§12.7).
	publishedCount, err := q.CountPublishedVersionsByUser(r.Context(), p.UserID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	// The chooser is EXPLICIT when there is published content (§12.7). It
	// used to default to "yank", which made the guard below unreachable and
	// silently pulled a user's published packages out from under everyone who
	// had installed them. With nothing published there is nothing to choose,
	// so the parameter stays optional in that case.
	disposition := ""
	if params.PublishedContent != nil {
		disposition = string(*params.PublishedContent)
	}
	if publishedCount > 0 && disposition == "" {
		problemBadRequest(w, r,
			fmt.Sprintf("This account has %d published public version(s). Pass publishedContent=yank to yank them, or publishedContent=transfer with transferOrg to hand them to an organization this account administers.", publishedCount))
		return
	}
	if disposition == "" {
		disposition = "yank"
	}

	agents, err := q.ListPersonalNamespaceAgents(r.Context(), p.UserID)
	if err != nil {
		problemInternal(w, r)
		return
	}

	// transfer: hand the personal namespace's agents to an org the caller
	// administers, so published content keeps a maintainer instead of being
	// yanked out from under its consumers (§12.7 "transfer to an org or
	// yank-all"). Done before the erasure transaction: a transfer that fails
	// must leave the account intact rather than orphan the agents.
	var transferOrgID uuid.UUID
	if disposition == "transfer" {
		orgHandle := ""
		if params.TransferOrg != nil {
			orgHandle = strings.TrimSpace(*params.TransferOrg)
		}
		if orgHandle == "" {
			problemBadRequest(w, r, "Add transferOrg=<org handle>, an organization this account administers, to use publishedContent=transfer.")
			return
		}
		orgRow, ok := s.orgOrNotFound(w, r, orgHandle)
		if !ok {
			return
		}
		// Admin: transferring content into an org binds that org to
		// maintaining it, which is an administrative act, not a membership one.
		if p.Role(orgRow.ID) != auth.RoleAdmin {
			problemForbidden(w, r, "Transferring BriefAgents into "+orgRow.Handle+" requires the admin role there.")
			return
		}
		// Nothing moves into an organization in its decommission hold.
		if err := s.reg.OrgGate(r.Context(), orgRow.ID, auth.ActAgentCreate); err != nil {
			if !s.orgGateProblem(w, r, orgRow.Handle, err) {
				problemInternal(w, r)
			}
			return
		}
		// The private-agent cap (agentry#363): the transfer door is one
		// more way private agents enter a namespace, and it respects the
		// cap the other two do. Nothing is erased on a refusal.
		var private int64
		for _, a := range agents {
			if a.Visibility == "private" {
				private++
			}
		}
		if err := s.reg.CheckPrivateAgentCapFor(r.Context(), orgRow.ID, private); err != nil {
			if errors.Is(err, registry.ErrPrivateAgentCap) {
				problemPrivateAgentCap(w, r)
				return
			}
			s.log.ErrorContext(r.Context(), "gdpr transfer cap", "err", err)
			problemInternal(w, r)
			return
		}
		transferOrgID = orgRow.ID
		if err := s.transferAgents(r, agents, orgRow); err != nil {
			if isUniqueViolation(err) {
				problemConflict(w, r,
					"A BriefAgent of the same name already exists in "+orgRow.Handle+". Rename it and try again.")
				return
			}
			s.log.ErrorContext(r.Context(), "gdpr transfer", "err", err)
			problemInternal(w, r)
			return
		}
	}

	tombstone, err := json.Marshal(map[string]any{
		"emailHash": s.hashForTombstone(user.Email),
		"deletedAt": time.Now().UTC().Format(time.RFC3339),
		"reason":    "user-requested erasure",
	})
	if err != nil {
		problemInternal(w, r)
		return
	}
	scrubbedEmail := fmt.Sprintf("deleted+%s@invalid.invalid", p.UserID.String())
	// The retired handle carries the WHOLE user id, not a prefix of it. The
	// leading hex digits of a UUIDv7 are a millisecond timestamp, so any
	// truncation makes two accounts erased in the same window collide on the
	// handles unique index — and a collision here fails the erasure itself.
	// "del-" + 32 hex characters is 36, inside the 39-character handle limit.
	retiredHandle := "del-" + strings.ReplaceAll(p.UserID.String(), "-", "")

	// Yank outside the erasure transaction: each yank is its own audited
	// state-machine transition (§7) and must not be rolled back by a later
	// failure — a yanked version is safe, a half-erased account is not.
	// Transferred agents are deliberately skipped: their whole point is that
	// the content survives with a new maintainer.
	if disposition == "yank" {
		for _, a := range agents {
			if a.LatestPublishedVersionID == nil {
				continue
			}
			versions, err := q.ListVersions(r.Context(), a.ID)
			if err != nil {
				continue
			}
			for _, v := range versions {
				if v.Status != string(registry.StatusPublished) {
					continue
				}
				e := auditEvent(r, audit.ActionVersionYank)
				e.Detail = map[string]any{"reason": "author account deleted"}
				if err := s.reg.Transition(r.Context(), v.ID, registry.StatusYanked,
					"author account deleted", e); err != nil {
					s.log.WarnContext(r.Context(), "gdpr yank", "version", v.ID, "err", err)
				}
			}
		}
	}

	err = s.st.WithTx(r.Context(), func(tq *storegen.Queries) error {
		if err := tq.PseudonymizeUser(r.Context(), storegen.PseudonymizeUserParams{
			ID: p.UserID, Email: scrubbedEmail, DeletedTombstone: tombstone,
		}); err != nil {
			return err
		}
		if err := tq.ReleaseHandle(r.Context(), storegen.ReleaseHandleParams{
			ID: p.UserID, Handle: retiredHandle,
		}); err != nil {
			return err
		}
		if _, err := tq.RevokeUserSessions(r.Context(), p.UserID); err != nil {
			return err
		}
		// Deleted rather than revoked, unlike SCIM deactivation: the erased
		// account cannot sign in again — PseudonymizeUser above set
		// state='deleted' and nulled the password hash — so a surviving record
		// is inert as a credential. What it still holds is an address and a
		// user agent belonging to a person who asked to be deleted, and the
		// users row survives erasure only because audit events and immutable
		// published content need a stable actor id. Nothing needs that of a
		// browser credential, and that one was issued is already in the audit
		// log (agentry#461).
		if _, err := tq.DeleteTrustedDevicesForUser(r.Context(), p.UserID); err != nil {
			return err
		}
		// A desktop sign-in code another session minted moments before the
		// erasure would otherwise still exchange for a token afterwards
		// (agentry#502): ExchangeDesktopCode checks only the grant, not the
		// account's state. Consumed here, as clearing data does (agentry#498).
		desktopCodes, err := tq.ConsumeDesktopGrantsForUser(r.Context(), p.UserID)
		if err != nil {
			return err
		}
		// An erased account holds no seat anywhere (agentry#363): the
		// last-admin guard above has already passed, so nothing is left
		// headless by this.
		if _, err := tq.DeleteUserMemberships(r.Context(), p.UserID); err != nil {
			return err
		}
		// An erased account is not staff (agentry#556): the account is
		// deleted and belongs to no organization, so the rule answers no.
		if err := s.syncStaffIn(r.Context(), tq, p.UserID, registry.StaffSyncErasure, auditEvent(r, audit.ActionUserStaffSync)); err != nil {
			return err
		}
		// Every PAT dies with the account.
		pats, err := tq.ListPATs(r.Context(), p.UserID)
		if err != nil {
			return err
		}
		for _, pat := range pats {
			if _, err := tq.RevokePAT(r.Context(), storegen.RevokePATParams{ID: pat.ID, UserID: p.UserID}); err != nil {
				return err
			}
		}
		e := auditEvent(r, audit.ActionUserDelete)
		e.TargetKind, e.TargetID = "user", p.UserID
		e.Detail = map[string]any{
			"publishedContent":  disposition,
			"publishedVersions": publishedCount,
			"desktopCodes":      desktopCodes,
		}
		if transferOrgID != uuid.Nil {
			e.OrgID = transferOrgID
		}
		return s.auditW.Write(r.Context(), tq, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "gdpr delete", "err", err)
		problemInternal(w, r)
		return
	}

	// The other half (agentry#20): with credentials in the directory service
	// the person's sign-in account — email, display name, password hash —
	// outlives the registry erasure and can sign in again to JIT-create a
	// fresh account. Delete it there too. Deliberately AFTER the registry
	// transaction: a directory deletion that succeeded before a failed
	// registry erasure would lock the person out of an account whose data
	// still exists. A failure here is audited and logged, never hidden, and
	// does not undo the erasure that already happened: a failed attempt is
	// handed to a retrying job (agentry#499), and the response says where the
	// directory step stands so the site can tell the person.
	e := auditEvent(r, audit.ActionUserDirectoryErase)
	e.Actor, e.ActorKind = p.UserID, audit.ActorUser
	dir, derr := s.eraseDirectoryAccount(r.Context(), e, p.UserID, user.Email, 0)
	if derr != nil {
		dir = s.scheduleDirectoryErasure(r.Context(), p.UserID, user.Email, derr)
	}

	clearCookie(w, sessionCookieName, s.cfg.Auth.CookieSecure)
	// A header on the 204, not a body: the contract is additive-only (D-09).
	w.Header().Set(directoryErasureHeader, dir)
	w.WriteHeader(http.StatusNoContent)
}

// transferAgents moves every agent in a personal namespace to an org, in one
// transaction: a partial transfer would split an author's catalogue across
// two namespaces with no owner able to finish the job.
func (s *Server) transferAgents(r *http.Request, agents []storegen.ListPersonalNamespaceAgentsRow, orgRow storegen.GetOrgByHandleRow) error {
	if len(agents) == 0 {
		return nil
	}
	return s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		for _, a := range agents {
			if err := q.SetAgentNamespace(r.Context(), storegen.SetAgentNamespaceParams{
				ID: a.ID, NamespaceID: orgRow.ID,
			}); err != nil {
				return err
			}
			e := auditEvent(r, audit.ActionAgentTransfer)
			e.OrgID = orgRow.ID
			e.TargetKind, e.TargetID = "agent", a.ID
			e.Detail = map[string]any{
				"name": a.Name, "toNamespace": orgRow.Handle, "reason": "account erasure",
			}
			if err := s.auditW.Write(r.Context(), q, e); err != nil {
				return err
			}
		}
		return nil
	})
}

// hashForTombstone derives a keyed hash of an email for abuse-recurrence
// detection (§12.7). Keyed with the sealing key so the tombstone alone
// cannot be brute-forced back to an address by anyone reading the database.
func (s *Server) hashForTombstone(email string) string {
	key := []byte(s.cfg.Auth.SealingKey)
	if len(key) == 0 {
		key = []byte("agentry-dev-tombstone-key")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(email))
	return hex.EncodeToString(mac.Sum(nil))
}
