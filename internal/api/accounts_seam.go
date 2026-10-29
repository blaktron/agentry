package api

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
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// The core's door for platform staff acting on a person's account through
// an extension (pkg/extension.Deps.Accounts): what the account is and holds,
// and suspending, reinstating and signing it out. The extension decides
// whom and when; what each act does stays the core's. Every act re-checks
// its actor here, whatever the extension checked: the actor must be an
// active platform-staff account and not the account acted on, so a fault
// in an extension's own authorization cannot turn this door into one
// anybody may use.

// The refusals of the account door.
var (
	ErrActorNotStaff = errors.New("api: only an active platform-staff account acts on another person's account")
	ErrActorSession  = errors.New("api: a change to a person's account is made from a signed-in session, not with a token")
	ErrSelfAct       = errors.New("api: staff do not act on their own account through this door")
	ErrNoAccount     = errors.New("api: no such account")
	ErrAccountErased = errors.New("api: the account is erased")
	ErrReasonLength  = errors.New("api: a staff act's reason is at most 500 characters")
	// ErrLastAdmin is an erasure refused because the account is an
	// organization's last admin; LastAdminError names the organization.
	ErrLastAdmin = errors.New("api: the account is an organization's last admin")
	// The refusals of ResendActivation.
	ErrAlreadyActivated = errors.New("api: the account's address is already confirmed")
	ErrNoAddress        = errors.New("api: the account has no address a link can reach")
	ErrNotActive        = errors.New("api: the account is not active")
)

// LastAdminError is ErrLastAdmin with the organization the account must
// hand over first.
type LastAdminError struct{ Org string }

func (e LastAdminError) Error() string        { return ErrLastAdmin.Error() + ": " + e.Org }
func (e LastAdminError) Is(target error) bool { return target == ErrLastAdmin }

// ActivationTooSoonError is ResendActivation's refusal inside the interval
// or the daily cap between two links, with when another may go.
type ActivationTooSoonError struct{ After time.Time }

func (e ActivationTooSoonError) Error() string {
	return "api: an activation link went to this account recently; another may go at " + e.After.UTC().Format(time.RFC3339)
}

// AccountErasure is what EraseAccount did.
type AccountErasure struct {
	// PublishedVersions counts the account's published public versions,
	// each yanked.
	PublishedVersions int64
	// Directory is the directory half's outcome, as the person's own
	// erasure reports it (X-Agentry-Directory-Erasure); empty without a
	// directory.
	Directory string
	// Notified is true when the person was mailed at a confirmed address.
	Notified bool
}

// accountReasonMax bounds the reason a staff act is audited with.
const accountReasonMax = 500

// AccountFacts is what the registry holds of a person's account, for
// staff: its state and standing, its memberships, and the ways it can act
// now. Never a secret: sessions by client and time, tokens by name and
// scope.
type AccountFacts struct {
	Handle        string
	State         string
	EmailVerified bool
	PlatformStaff bool
	CreatedAt     time.Time
	Orgs          []AccountOrg
	Sessions      []AccountSession
	Tokens        []AccountToken
}

// AccountOrg is one of the account's memberships.
type AccountOrg struct {
	Handle string
	Role   string
	State  string
}

// AccountSession is one live browser session: when it began and was last
// used, and the client it was last used from.
type AccountSession struct {
	CreatedAt  time.Time
	LastSeenAt time.Time
	Client     string
}

// AccountToken is one live personal access token, named and scoped as its
// owner made it, never its value.
type AccountToken struct {
	Name       string
	Scopes     []string
	Org        string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  time.Time
}

// AccountChange is what an act did: whether the account's state moved,
// and how many of each credential it revoked.
type AccountChange struct {
	Changed            bool
	Sessions           int64
	Tokens             int64
	SSHKeys            int64
	RememberedBrowsers int64
	DesktopGrants      int64
}

// AccountFacts reads userID's account for the staff member actor, their
// own included. A token may read it, as staff's other reads allow.
func (s *Server) AccountFacts(ctx context.Context, actor *auth.Principal, userID uuid.UUID) (AccountFacts, error) {
	if s.st == nil {
		return AccountFacts{}, errors.New("api: no database to read accounts from")
	}
	q := s.q()
	if err := checkAccountActor(ctx, q, actor, userID, false); err != nil {
		return AccountFacts{}, err
	}
	u, err := q.GetUserByID(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return AccountFacts{}, ErrNoAccount
	}
	if err != nil {
		return AccountFacts{}, err
	}
	out := AccountFacts{
		Handle: u.Handle, State: u.State, EmailVerified: u.EmailVerifiedAt != nil, PlatformStaff: u.PlatformStaff, CreatedAt: u.CreatedAt,
		Orgs: []AccountOrg{}, Sessions: []AccountSession{}, Tokens: []AccountToken{},
	}
	orgs, err := q.ListUserMembershipsWithHandles(ctx, userID)
	if err != nil {
		return AccountFacts{}, err
	}
	for _, m := range orgs {
		out.Orgs = append(out.Orgs, AccountOrg{Handle: m.Handle, Role: m.Role, State: m.State})
	}
	sessions, err := q.ListActiveUserSessions(ctx, userID)
	if err != nil {
		return AccountFacts{}, err
	}
	for _, se := range sessions {
		client := ""
		if se.UserAgent != nil {
			client = *se.UserAgent
		}
		out.Sessions = append(out.Sessions, AccountSession{CreatedAt: se.CreatedAt, LastSeenAt: se.LastSeenAt, Client: client})
	}
	pats, err := q.ListPATs(ctx, userID)
	if err != nil {
		return AccountFacts{}, err
	}
	for _, p := range pats {
		t := AccountToken{Name: p.Name, Scopes: p.Scopes, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt, ExpiresAt: p.ExpiresAt}
		if p.OrgHandle != nil {
			t.Org = *p.OrgHandle
		}
		out.Tokens = append(out.Tokens, t)
	}
	return out, nil
}

// SuspendAccount suspends userID's account: nobody can sign in to it or
// act as it, every session, personal access token, SSH key, remembered
// browser and unused desktop sign-in code is revoked, and it stops being
// platform staff, in one transaction. A suspended account is refused at
// every door by its state alone; the revocation is what keeps a
// reinstatement from bringing any of it back. Suspending a suspended
// account changes nothing.
func (s *Server) SuspendAccount(ctx context.Context, ext string, actor *auth.Principal, userID uuid.UUID, reason string) (AccountChange, error) {
	return s.accountAct(ctx, ext, actor, userID, reason, audit.ActionUserSuspend, func(q *storegen.Queries, out *AccountChange) error {
		n, err := q.SetUserState(ctx, storegen.SetUserStateParams{ID: userID, FromState: "active", ToState: "suspended"})
		if err != nil || n == 0 {
			return err
		}
		out.Changed = true
		return revokeAccountCredentials(ctx, q, userID, out, true)
	}, notify.AccountSuspended)
}

// ReinstateAccount makes a suspended account active again. Nothing from
// before the suspension comes back: it revokes every credential again in
// the same transaction, because one being created at the instant of the
// suspension (a token whose insert waited on the person's row lock) can
// commit just after the suspension's revocation. The person signs in afresh
// and makes new tokens and keys. It is platform staff again only if the
// staff rule says so now. Reinstating an active account changes nothing.
func (s *Server) ReinstateAccount(ctx context.Context, ext string, actor *auth.Principal, userID uuid.UUID, reason string) (AccountChange, error) {
	return s.accountAct(ctx, ext, actor, userID, reason, audit.ActionUserReinstate, func(q *storegen.Queries, out *AccountChange) error {
		n, err := q.SetUserState(ctx, storegen.SetUserStateParams{ID: userID, FromState: "suspended", ToState: "active"})
		if err != nil || n == 0 {
			return err
		}
		out.Changed = true
		return revokeAccountCredentials(ctx, q, userID, out, true)
	}, notify.AccountReinstated)
}

// SignOutAccount ends every session of userID's account and forgets every
// browser it remembered, so the next sign-in asks for everything again.
// Its tokens and SSH keys keep working: they are revoked by suspending.
func (s *Server) SignOutAccount(ctx context.Context, ext string, actor *auth.Principal, userID uuid.UUID, reason string) (AccountChange, error) {
	return s.accountAct(ctx, ext, actor, userID, reason, audit.ActionUserSignOut, func(q *storegen.Queries, out *AccountChange) error {
		if err := revokeAccountCredentials(ctx, q, userID, out, false); err != nil {
			return err
		}
		out.Changed = out.Sessions+out.RememberedBrowsers+out.DesktopGrants > 0
		return nil
	}, notify.AccountSignedOut)
}

// TellSecondFactorsRemoved tells the person that platform staff removed
// removed of their second factors, an act an extension made at the
// person's directory and audits itself. The core holds no second factor,
// so it changes nothing here; it keeps the notice, which is a security
// notice like the other acts' and so goes out whatever the person's mail
// switches say, and only to a confirmed address. The actor is checked as
// for every change. It reports whether the notice was handed to the
// notifier: false with no error is an address that may not be written to.
func (s *Server) TellSecondFactorsRemoved(ctx context.Context, actor *auth.Principal, userID uuid.UUID, removed int) (bool, error) {
	if s.st == nil {
		return false, errors.New("api: no database to read accounts from")
	}
	if removed < 1 {
		return false, errors.New("api: a notice of removed second factors names at least one")
	}
	q := s.q()
	if err := checkAccountActor(ctx, q, actor, userID, true); err != nil {
		return false, err
	}
	u, err := q.GetUserByID(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNoAccount
	}
	if err != nil {
		return false, err
	}
	if u.State == "deleted" {
		return false, ErrAccountErased
	}
	if u.EmailVerifiedAt == nil || auth.SyntheticAddress(u.Email) {
		return false, nil
	}
	notice := notify.AccountNotice{ToEmail: u.Email, Handle: u.Handle, Change: notify.AccountSecondFactorsRemoved, Removed: removed}
	if err := s.notifier.AccountChanged(ctx, notice); err != nil {
		return false, err
	}
	return true, nil
}

// EraseAccount erases userID's account for the staff member actor: the
// person's own erasure (eraseAccountNow), with the account's published
// public versions yanked, because staff do not choose an organization to
// hand them to. The actor is checked as for every change, again inside
// the erasure's transaction under both row locks, and the reason is in
// the user.delete row. An organization's last admin is refused, as the
// person's own erasure refuses it. The person is mailed at a confirmed
// address, captured before the erasure scrubs it. r is the request the
// extension acts in, which the audit rows and the directory half read.
func (s *Server) EraseAccount(r *http.Request, ext string, actor *auth.Principal, userID uuid.UUID, reason string) (AccountErasure, error) {
	var out AccountErasure
	if s.st == nil {
		return out, errors.New("api: no database to erase accounts in")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return out, errors.New("api: a staff act on an account needs a reason")
	}
	if len([]rune(reason)) > accountReasonMax {
		return out, ErrReasonLength
	}
	ctx := r.Context()
	q := s.q()
	if err := checkAccountActor(ctx, q, actor, userID, true); err != nil {
		return out, err
	}
	u, err := q.GetUserByID(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNoAccount
	}
	if err != nil {
		return out, err
	}
	if u.State == "deleted" {
		return out, ErrAccountErased
	}
	if org, err := q.GetOrgWhereUserIsLastAdmin(ctx, userID); err == nil {
		return out, LastAdminError{Org: org}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if out.PublishedVersions, err = q.CountPublishedVersionsByUser(ctx, userID); err != nil {
		return out, err
	}
	agents, err := q.ListPersonalNamespaceAgents(ctx, userID)
	if err != nil {
		return out, err
	}
	by := &staffEraser{actor: actor.UserID, ext: ext, reason: reason, check: func(tq *storegen.Queries) error {
		first, second := actor.UserID, userID
		if strings.Compare(first.String(), second.String()) > 0 {
			first, second = second, first
		}
		for _, id := range []uuid.UUID{first, second} {
			if err := tq.LockUser(ctx, id); err != nil {
				return err
			}
		}
		if err := checkAccountActor(ctx, tq, actor, userID, true); err != nil {
			return err
		}
		again, err := tq.GetUserByID(ctx, userID)
		if err != nil {
			return err
		}
		if again.State == "deleted" {
			return ErrAccountErased
		}
		if org, err := tq.GetOrgWhereUserIsLastAdmin(ctx, userID); err == nil {
			return LastAdminError{Org: org}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return nil
	}}
	if out.Directory, err = s.eraseAccountNow(r, userID, u.Email, agents, "yank", out.PublishedVersions, uuid.Nil, by); err != nil {
		return AccountErasure{}, err
	}
	if u.EmailVerifiedAt != nil && !auth.SyntheticAddress(u.Email) {
		notice := notify.AccountNotice{ToEmail: u.Email, Handle: u.Handle, Change: notify.AccountErased}
		if err := s.notifier.AccountChanged(ctx, notice); err != nil {
			s.log.WarnContext(ctx, "notify: account notice", "change", string(notice.Change), "err", err)
		} else {
			out.Notified = true
		}
	}
	return out, nil
}

// ResendActivation sends an unactivated account a new activation link for
// the staff member actor, under the limits the person's own resend has
// (one link in five minutes, ten a day). An account already activated, one
// with no address a link can reach and one not active are refused. It is
// audited as user.activation_resend with the actor and the reason, and
// returns when another link may go.
func (s *Server) ResendActivation(ctx context.Context, ext string, actor *auth.Principal, userID uuid.UUID, reason string) (time.Time, error) {
	if s.st == nil {
		return time.Time{}, errors.New("api: no database to act on accounts in")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return time.Time{}, errors.New("api: a staff act on an account needs a reason")
	}
	if len([]rune(reason)) > accountReasonMax {
		return time.Time{}, ErrReasonLength
	}
	var (
		token, email, handle string
		after                time.Time
	)
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if err := checkAccountActor(ctx, q, actor, userID, true); err != nil {
			return err
		}
		u, err := q.GetUserByID(ctx, userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoAccount
		}
		if err != nil {
			return err
		}
		switch {
		case u.State == "deleted":
			return ErrAccountErased
		case u.State != "active":
			return ErrNotActive
		case u.EmailVerifiedAt != nil:
			return ErrAlreadyActivated
		case auth.SyntheticAddress(u.Email):
			return ErrNoAddress
		}
		token, after, err = issueActivation(ctx, q, userID, true)
		var soon errActivationTooSoon
		if errors.As(err, &soon) {
			return ActivationTooSoonError{After: soon.after}
		}
		if err != nil {
			return err
		}
		email, handle = u.Email, u.Handle
		return s.auditW.Write(ctx, q, audit.Event{
			Actor: actor.UserID, ActorKind: audit.ActorUser, Action: audit.ActionUserActivationResend, TargetKind: "user", TargetID: userID,
			Detail: map[string]any{"via": "extension", "extension": ext, "reason": reason},
		})
	})
	if err != nil {
		return time.Time{}, err
	}
	s.mailActivation(ctx, email, handle, token)
	return after, nil
}

// accountAct runs one staff act on userID under the person's row lock:
// the actor checked, the act, its audit row (only when something changed)
// and the staff rule recomputed, in one transaction; then the mail to the
// person. A reason is required, as it is for every staff act.
func (s *Server) accountAct(ctx context.Context, ext string, actor *auth.Principal, userID uuid.UUID, reason string, action audit.Action,
	act func(q *storegen.Queries, out *AccountChange) error, change notify.AccountNoticeKind) (AccountChange, error) {
	var out AccountChange
	if s.st == nil {
		return out, errors.New("api: no database to act on accounts in")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return out, errors.New("api: a staff act on an account needs a reason")
	}
	if len([]rune(reason)) > accountReasonMax {
		return out, ErrReasonLength
	}
	var notice notify.AccountNotice
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		out = AccountChange{}
		if actor == nil || actor.UserID == userID {
			return checkAccountActor(ctx, q, actor, userID, true)
		}
		// Both rows are locked, in id order so two staff acting on each
		// other at once cannot deadlock: the actor's, so a demotion or a
		// suspension of the actor cannot commit between the check and the
		// act, and the person's, against every other change to them.
		first, second := actor.UserID, userID
		if strings.Compare(first.String(), second.String()) > 0 {
			first, second = second, first
		}
		for _, id := range []uuid.UUID{first, second} {
			if err := q.LockUser(ctx, id); err != nil {
				return err
			}
		}
		if err := checkAccountActor(ctx, q, actor, userID, true); err != nil {
			return err
		}
		u, err := q.GetUserByID(ctx, userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoAccount
		}
		if err != nil {
			return err
		}
		if u.State == "deleted" {
			return ErrAccountErased
		}
		if err := act(q, &out); err != nil {
			return err
		}
		if !out.Changed {
			return nil
		}
		ev := audit.Event{
			Actor: actor.UserID, ActorKind: audit.ActorUser, Action: action, TargetKind: "user", TargetID: userID,
			Detail: map[string]any{
				"via": "extension", "extension": ext, "reason": reason,
				"revoked": map[string]any{
					"sessions": out.Sessions, "tokens": out.Tokens, "sshKeys": out.SSHKeys,
					"rememberedBrowsers": out.RememberedBrowsers, "desktopGrants": out.DesktopGrants,
				},
			},
		}
		if err := s.auditW.Write(ctx, q, ev); err != nil {
			return err
		}
		sync := ev
		sync.Action, sync.Detail = audit.ActionUserStaffSync, map[string]any{"via": "extension", "extension": ext}
		if err := s.syncStaffIn(ctx, q, userID, registry.StaffSyncState, sync); err != nil {
			return err
		}
		// Only to an address the person confirmed: an unconfirmed one may
		// be somebody else's.
		if u.EmailVerifiedAt != nil && !auth.SyntheticAddress(u.Email) {
			notice = notify.AccountNotice{ToEmail: u.Email, Handle: u.Handle, Change: change}
		}
		return nil
	})
	if err != nil {
		return AccountChange{}, err
	}
	if notice.ToEmail != "" {
		if err := s.notifier.AccountChanged(ctx, notice); err != nil {
			s.log.WarnContext(ctx, "notify: account notice", "change", string(change), "err", err)
		}
	}
	return out, nil
}

// revokeAccountCredentials revokes the account's sessions, remembered
// browsers and unused desktop sign-in codes and, with everything, its
// personal access tokens and SSH keys too, counting each into out.
func revokeAccountCredentials(ctx context.Context, q *storegen.Queries, userID uuid.UUID, out *AccountChange, everything bool) error {
	var err error
	if out.Sessions, err = q.RevokeUserSessions(ctx, userID); err != nil {
		return err
	}
	if out.RememberedBrowsers, err = q.RevokeTrustedDevicesForUser(ctx, userID); err != nil {
		return err
	}
	// A desktop sign-in code minted just before would otherwise still
	// exchange for a token: the exchange checks the grant, not the
	// account's state.
	if out.DesktopGrants, err = q.ConsumeDesktopGrantsForUser(ctx, userID); err != nil {
		return err
	}
	if !everything {
		return nil
	}
	if out.Tokens, err = q.RevokeAllPATsForUser(ctx, userID); err != nil {
		return err
	}
	out.SSHKeys, err = q.RevokeAllSSHKeysForUser(ctx, userID)
	return err
}

// checkAccountActor refuses an actor that is not an active platform-staff
// account with a credential (a "user" principal is one the core loaded for
// an account with no credential at all), or, for a change, one that acts
// on itself or is not a signed-in session. It reads the actor's account
// afresh rather than trusting the principal it was handed.
func checkAccountActor(ctx context.Context, q *storegen.Queries, actor *auth.Principal, target uuid.UUID, change bool) error {
	if actor == nil || actor.Anonymous || actor.UserID == uuid.Nil || actor.Via == "user" {
		return ErrActorNotStaff
	}
	if change && actor.Via != "session" {
		return ErrActorSession
	}
	if change && actor.UserID == target {
		return ErrSelfAct
	}
	a, err := q.GetUserByID(ctx, actor.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrActorNotStaff
	}
	if err != nil {
		return err
	}
	if a.State != "active" || !a.PlatformStaff {
		return ErrActorNotStaff
	}
	return nil
}
