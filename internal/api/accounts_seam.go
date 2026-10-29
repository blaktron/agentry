package api

import (
	"context"
	"errors"
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
)

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
