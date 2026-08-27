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

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
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
		problemForbidden(w, r, "account deletion requires a session, not a token")
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
	disposition := "yank"
	if params.PublishedContent != nil {
		disposition = string(*params.PublishedContent)
	}
	if publishedCount > 0 && disposition == "" {
		problemValidation(w, r,
			fmt.Sprintf("this account has %d published public version(s); pass publishedContent=yank or transfer", publishedCount))
		return
	}
	if disposition == "transfer" {
		// Transfer needs a destination org and org-owner consent; that flow
		// is a separate, deliberate action rather than a side effect of
		// deletion. Refuse clearly instead of guessing.
		problemValidation(w, r,
			"transfer the agents to an org first (PATCH the agent's namespace), then delete the account")
		return
	}

	// Yank every published version under the personal namespace, then
	// pseudonymize. All of it in one transaction so a partial erasure can
	// never leave PII behind with content already yanked.
	agents, err := q.ListPersonalNamespaceAgents(r.Context(), p.UserID)
	if err != nil {
		problemInternal(w, r)
		return
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
				s.log.Warn("gdpr yank", "version", v.ID, "err", err)
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
		e.Detail = map[string]any{"publishedVersionsYanked": publishedCount}
		return s.auditW.Write(r.Context(), tq, e)
	})
	if err != nil {
		s.log.Error("gdpr delete", "err", err)
		problemInternal(w, r)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: s.cfg.Auth.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
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
