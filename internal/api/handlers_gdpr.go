package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

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
		// Owner or admin: transferring content into an org binds that org to
		// maintaining it, which is an administrative act, not a membership one.
		switch p.Role(orgRow.ID) {
		case auth.RoleOwner, auth.RoleAdmin:
		default:
			problemForbidden(w, r, "Transferring BriefAgents into "+orgRow.Handle+" requires the owner or admin role there.")
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
	// does not undo the erasure that already happened.
	s.eraseDirectoryAccount(r, p.UserID, user.Email)

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: s.cfg.Auth.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// eraseDirectoryAccount runs the directory half of erasure and records the
// outcome as a user.directory_erase audit event: deleted, not-found,
// not-configured, or failed (with the error).
func (s *Server) eraseDirectoryAccount(r *http.Request, userID uuid.UUID, email string) {
	outcome := "not-configured"
	detail := map[string]any{}
	if s.dirEraser != nil {
		deleted, err := s.dirEraser.EraseByEmail(r.Context(), email)
		switch {
		case err != nil:
			outcome = "failed"
			detail["error"] = err.Error()
			s.log.ErrorContext(r.Context(), "gdpr: directory erasure failed — finish by hand", "user", userID, "err", err)
		case deleted:
			outcome = "deleted"
		default:
			outcome = "not-found"
		}
	}
	detail["directoryErasure"] = outcome
	e := auditEvent(r, audit.ActionUserDirectoryErase)
	e.Actor, e.ActorKind = userID, audit.ActorUser
	e.TargetKind, e.TargetID = "user", userID
	e.Detail = detail
	if err := s.auditW.Write(r.Context(), s.q(), e); err != nil {
		s.log.ErrorContext(r.Context(), "gdpr: audit directory erasure", "err", err)
	}
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
