package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/knowledge"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Activation (plan unactivated-accounts.md, agentry#861). A self-enrolled
// directory account reaches the registry before its address is confirmed:
// the directory writes it active and its token says email_verified false.
// The registry mails the link that confirms it, at the sign-in that creates
// the account and on request from the Dashboard, and following the link
// marks the address confirmed here. The directory reads it and then says
// email_verified true. Until then the account is read-only (unactivated.go).
const (
	// activationTTL is how long a link works (D7): a day, since nothing
	// waits on it any more.
	activationTTL = 24 * time.Hour
	// activationInterval is the least time between two links to one
	// account (D6), counted from the newest one made, whoever made it.
	activationInterval = 5 * time.Minute
	// activationsPerDay caps the links one account can be sent in a day,
	// on top of D6's interval: anyone can sign up with another person's
	// address, and without a cap the resend would let them mail that
	// person every five minutes for ever (DEV-197).
	activationsPerDay = 10
)

// errActivationTooSoon is issueActivation's refusal inside the interval.
type errActivationTooSoon struct{ after time.Time }

func (e errActivationTooSoon) Error() string { return "activation mail sent too recently" }

// issueActivation records a new activation link for an account and returns
// its token, inside the caller's transaction. With limit, it first takes the
// account's row lock and refuses inside activationInterval of the newest
// link, so replicas answering at once make one link, never two.
func issueActivation(ctx context.Context, q *storegen.Queries, userID uuid.UUID, limit bool) (string, time.Time, error) {
	now := time.Now()
	if limit {
		if _, err := q.LockUserRow(ctx, userID); err != nil {
			return "", time.Time{}, fmt.Errorf("lock the account: %w", err)
		}
		last, err := q.LatestEmailVerificationAt(ctx, userID)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("read the last activation link: %w", err)
		}
		if after := last.Add(activationInterval); now.Before(after) {
			return "", time.Time{}, errActivationTooSoon{after: after}
		}
		day, err := q.CountEmailVerificationsSince(ctx, storegen.CountEmailVerificationsSinceParams{UserID: userID, CreatedAt: now.Add(-24 * time.Hour)})
		if err != nil {
			return "", time.Time{}, fmt.Errorf("count the day's activation links: %w", err)
		}
		if day.Sent >= activationsPerDay {
			return "", time.Time{}, errActivationTooSoon{after: day.Oldest.Add(24 * time.Hour)}
		}
	}
	token, err := auth.NewToken(auth.VerificationPrefix)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint an activation link: %w", err)
	}
	if err := q.CreateEmailVerification(ctx, storegen.CreateEmailVerificationParams{
		TokenSha256: auth.HashToken(token),
		UserID:      userID,
		ExpiresAt:   now.Add(activationTTL),
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("record the activation link: %w", err)
	}
	return token, now.Add(activationInterval), nil
}

// mailActivation sends a link issueActivation made. A failure is logged and
// not returned: the link exists, and another can be asked for.
func (s *Server) mailActivation(ctx context.Context, email, handle, token string) {
	if err := s.notifier.EmailVerification(ctx, email, handle, token); err != nil {
		s.log.WarnContext(ctx, "activation mail", "err", err)
	}
}

// resendAfter is when an unconfirmed account may ask for another link, or
// nil when it may now (GET /user's emailVerificationResendAfter).
func (s *Server) resendAfter(ctx context.Context, row storegen.GetUserByIDRow) *time.Time {
	if !auth.Unactivated(row.EmailVerifiedAt, row.Email) {
		return nil
	}
	last, err := s.q().LatestEmailVerificationAt(ctx, row.ID)
	if err != nil {
		return nil
	}
	after := last.Add(activationInterval)
	if !time.Now().Before(after) {
		return nil
	}
	return &after
}

// SendEmailVerification implements POST /user/email-verification.
func (s *Server) SendEmailVerification(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	ctx := r.Context()
	p := principalFrom(ctx)
	row, err := s.q().GetUserByID(ctx, p.UserID)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	if row.EmailVerifiedAt != nil {
		writeProblem(w, r, http.StatusConflict, "already-activated", "Already activated",
			"This account's address is already confirmed. There is nothing to activate.")
		return
	}
	if auth.SyntheticAddress(row.Email) {
		writeProblem(w, r, http.StatusConflict, "no-address", "No address to send to",
			"This account has no email address a link can reach.")
		return
	}
	var token string
	var after time.Time
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		var err error
		token, after, err = issueActivation(ctx, q, row.ID, true)
		return err
	})
	var soon errActivationTooSoon
	if errors.As(err, &soon) {
		wait := time.Until(soon.after)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeProblemWith(w, r, http.StatusTooManyRequests, "activation-too-soon", "Too soon",
			fmt.Sprintf("An activation link went to this address recently. Check your inbox, or ask again after %s.",
				soon.after.UTC().Format("2 Jan 15:04 UTC")),
			map[string]any{"resendAfter": soon.after.UTC()})
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "activation: issue", "err", err)
		problemInternal(w, r)
		return
	}
	s.mailActivation(ctx, row.Email, row.Handle, token)
	writeJSON(w, http.StatusOK, EmailVerificationSent{SentTo: row.Email, ResendAfter: after.UTC()})
}

// signedInDirectoryLinks names the directory accounts the person signed in
// with, none for an account that never did (unlike directoryLinksFor, which
// falls back to the address for erasure).
func (s *Server) signedInDirectoryLinks(ctx context.Context, userID uuid.UUID, email string) ([]directoryLink, error) {
	rows, err := s.q().ListUserDirectoryLinks(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("read the account's directory links: %w", err)
	}
	links := make([]directoryLink, 0, len(rows))
	for _, r := range rows {
		links = append(links, directoryLink{AccountID: r.DirectoryAccountID, UID: r.DirectorySubject, Email: email})
	}
	return links, nil
}

// directoryPresence tells whether a directory account a link names still
// exists (D10).
type directoryPresence interface {
	// AccountGone reports that the account is no longer in the directory.
	// False when it cannot tell.
	AccountGone(ctx context.Context, link directoryLink) (bool, error)
}

// AccountGone implements directoryPresence. A recorded id that answers 404,
// or now holds an account with another uid, is gone; without an id, the
// uid found at no account at the address is gone. A link with neither says
// nothing, and is not gone.
func (a *authentikEraser) AccountGone(ctx context.Context, link directoryLink) (bool, error) {
	if link.AccountID > 0 {
		u, err := a.accountByID(ctx, link.AccountID)
		if err != nil {
			return false, err
		}
		return u == nil || (link.UID != "" && u.UID != link.UID), nil
	}
	if link.UID == "" || link.Email == "" {
		return false, nil
	}
	accounts, err := a.accountsAt(ctx, link.Email)
	if err != nil {
		return false, err
	}
	for _, u := range accounts {
		if u.UID == link.UID {
			return false, nil
		}
	}
	return true, nil
}

// unactivatedSuperseded reports that an unconfirmed registry account's
// every directory account is gone (D10): the directory removed it for a
// provider that proved the address. Only where unactivated accounts are
// read-only, so the account can have made nothing, and never an
// organization's last admin. An account with no directory sign-in, a
// directory that cannot be asked, or any doubt, is not superseded, and the
// caller keeps today's answer (link it explicitly).
func (s *Server) unactivatedSuperseded(ctx context.Context, userID uuid.UUID, email string) bool {
	pres, ok := s.dirEraser.(directoryPresence)
	if !ok || !s.unactivatedReadOnly {
		return false
	}
	if _, err := s.q().GetOrgWhereUserIsLastAdmin(ctx, userID); !errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	links, err := s.signedInDirectoryLinks(ctx, userID, email)
	if err != nil || len(links) == 0 {
		return false
	}
	for _, link := range links {
		gone, err := pres.AccountGone(ctx, link)
		if err != nil {
			s.log.WarnContext(ctx, "superseded check: directory", "err", err)
			return false
		}
		if !gone {
			return false
		}
	}
	return true
}

// eraseSuperseded erases an unactivated account D10 found superseded, as
// the system, so the verified sign-in in hand can take its address. The
// directory half is already gone.
func (s *Server) eraseSuperseded(r *http.Request, userID uuid.UUID, email, provider string) error {
	ctx := r.Context()
	var erased erasedRows
	staff := auditEvent(r, audit.ActionUserStaffSync)
	staff.ActorKind = audit.ActorSystem
	err := s.st.WithPgxTx(ctx, func(tx pgx.Tx, tq *storegen.Queries) error {
		var err error
		if erased, err = s.eraseAccountIn(ctx, tx, tq, userID, email, "unactivated account superseded by a verified sign-in", staff); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserDelete)
		e.ActorKind = audit.ActorSystem
		e.TargetKind, e.TargetID = "user", userID
		e.Detail = map[string]any{"reason": "unactivated-superseded", "provider": provider, "desktopCodes": erased.desktopCodes}
		if erased.extensions != nil {
			e.Detail["extensions"] = erased.extensions
		}
		return s.auditW.Write(ctx, tq, e)
	})
	if err != nil {
		return fmt.Errorf("erase the superseded account: %w", err)
	}
	s.knowledge.FinishErasure(ctx, knowledge.User(userID), erased.knowledgeKeys)
	return nil
}
