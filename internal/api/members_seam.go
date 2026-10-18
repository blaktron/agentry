package api

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// ProvisionedMember is a person an organization's identity provider
// provisioned, as a directory extension names them to the core: the
// address they are known at, the name the provider calls them by (a seed
// for a new account's handle) and a display name.
type ProvisionedMember struct {
	Email       string
	UserName    string
	DisplayName string
}

// The refusals of ProvisionMember. An organization that is unknown,
// suspended or being decommissioned has its membership frozen. An account
// that holds the address without having proved it may be someone else's
// claim on it, and a membership the organization meant for the address's
// owner must not land there.
var (
	ErrOrgNotProvisionable = errors.New("api: the organization is not active, so nobody is provisioned into it")
	ErrAddressUnproven     = errors.New("api: the account at this address has not proved it, so it is not provisioned")
)

// ProvisionMember makes the person a pending member of orgID on a
// directory extension's word (pkg/extension.Deps.Members): the account at
// their address when it has proved the address, or a new one with the
// address taken as verified on the extension's word. A pending
// membership holds no seat and confers nothing until an admin approves it,
// and an existing membership, pending or active, is left as it is. The
// staff organization admits only its own domain. The extension decides
// whom to provision; the core decides what provisioning is.
func (s *Server) ProvisionMember(ctx context.Context, ext string, orgID uuid.UUID, p ProvisionedMember) (uuid.UUID, error) {
	if s.st == nil {
		return uuid.Nil, errors.New("api: no database to provision members in")
	}
	email := strings.ToLower(strings.TrimSpace(p.Email))
	if strings.Count(email, "@") != 1 || strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") {
		return uuid.Nil, errors.New("api: a provisioned member needs an address")
	}
	org, err := s.q().GetOrgByID(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrOrgNotProvisionable
	}
	if err != nil {
		return uuid.Nil, err
	}
	if org.State != registry.OrgStateActive || org.DecommissionAt != nil {
		return uuid.Nil, ErrOrgNotProvisionable
	}
	if err := s.staffOrgAddressIn(ctx, s.q(), orgID, email); err != nil {
		return uuid.Nil, err
	}
	if u, err := s.q().GetUserByEmail(ctx, email); err == nil && u.EmailVerifiedAt == nil {
		return uuid.Nil, ErrAddressUnproven
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	userID, err := s.provisionPending(ctx, orgID, email, p.UserName, p.DisplayName, ext)
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.auditW.Write(ctx, s.q(), s.extensionMemberEvent(ext, orgID, audit.ActionSCIMUserProvision, userID)); err != nil {
		s.log.ErrorContext(ctx, "audit an extension's provisioning", "extension", ext, "err", err)
	}
	return userID, nil
}

// DeprovisionMember takes userID's membership of orgID away on a directory
// extension's word and revokes their org-bound tokens for orgID, every
// session and every remembered browser (pkg/extension.Deps.Members). The
// organization's last admin keeps the membership, so the organization keeps
// someone who can act, and those credentials are revoked all the same;
// kept reports it. Calling it again does nothing more. It runs in any state of
// the organization: taking access away is never frozen.
func (s *Server) DeprovisionMember(ctx context.Context, ext string, orgID, userID uuid.UUID) (kept bool, err error) {
	if s.st == nil {
		return false, errors.New("api: no database to deprovision members in")
	}
	return s.deprovisionMember(ctx, orgID, userID, s.extensionMemberEvent(ext, orgID, audit.ActionSCIMUserDeactivate, userID))
}

// extensionMemberEvent is the audit row of an extension's provisioning
// act: the system as the actor, the extension named, as its other acts
// through the core are.
func (s *Server) extensionMemberEvent(ext string, orgID uuid.UUID, action audit.Action, userID uuid.UUID) audit.Event {
	return audit.Event{
		Action: action, ActorKind: audit.ActorSystem, OrgID: orgID,
		TargetKind: "user", TargetID: userID,
		Detail: map[string]any{"via": "extension", "extension": ext},
	}
}

// provisionPending links an existing global user by email or JIT-creates
// one, then adds a **pending** org membership marked as provisioned
// (via_scim): the IdP says who exists, an admin says who is a member. A
// pending membership holds no seat and confers nothing, so a provisioning
// door still succeeds however
// many seats the organization has left; the wall is at the approval. A new
// account's handle is seeded from the IdP's userName (its local part when
// the userName is the address), the name the directory knows the person
// by, and its address is taken as verified, because the organization's
// identity provider vouches for it. An existing membership, pending or
// active, is left as it is. Every door that creates an account fires
// user.registered, with via naming the door.
func (s *Server) provisionPending(ctx context.Context, orgID uuid.UUID, email, userName, displayName, via string) (uuid.UUID, error) {
	if u, err := s.q().GetUserByEmail(ctx, email); err == nil {
		if err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
			_, err := q.UpsertPendingMembership(ctx, storegen.UpsertPendingMembershipParams{
				OrgID: orgID, UserID: u.ID, Role: string(auth.RoleMember), ViaScim: true,
			})
			return err
		}); err != nil {
			return uuid.Nil, err
		}
		return u.ID, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	userID := newUUID()
	handle, err := s.allocateHandle(ctx, userName, email, email)
	if err != nil {
		return uuid.Nil, err
	}
	dn := orDefault(displayName, handle)
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if err := q.CreateHandle(ctx, storegen.CreateHandleParams{ID: userID, Handle: handle, Kind: "user"}); err != nil {
			return err
		}
		if _, err := q.CreateUser(ctx, storegen.CreateUserParams{ID: userID, Email: email, DisplayName: dn}); err != nil {
			return err
		}
		// Provisioned on the directory extension's word: the organization's
		// identity provider vouches for the address.
		if err := q.MarkEmailVerified(ctx, userID); err != nil {
			return err
		}
		_, err := q.UpsertPendingMembership(ctx, storegen.UpsertPendingMembershipParams{
			OrgID: orgID, UserID: userID, Role: string(auth.RoleMember), ViaScim: true,
		})
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	s.fireEvent(ctx, Event{Kind: "user.registered", UserID: userID, OrgID: orgID, Payload: map[string]any{
		"handle": handle, "email": email, "emailVerified": true, "via": via,
	}})
	return userID, nil
}

// deprovisionMember takes userID's membership of orgID away and revokes
// their org-bound PATs for orgID, every session and every remembered
// browser, in one transaction, audited with ev. The last admin's
// membership is the one thing it cannot take: the membership stays (the
// organization keeps someone who can act), the credentials are revoked,
// and kept reports it. A person who is not a member loses their sessions
// and remembered browsers all the same.
func (s *Server) deprovisionMember(ctx context.Context, orgID, userID uuid.UUID, ev audit.Event) (kept bool, err error) {
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		kept = false
		if err := guardLastAdmin(ctx, q, orgID, userID); err != nil {
			if !errors.Is(err, errLastAdmin) {
				return err
			}
			kept = true
		}
		if !kept {
			if _, err := q.DeleteMembership(ctx, storegen.DeleteMembershipParams{OrgID: orgID, UserID: userID}); err != nil {
				return err
			}
		}
		if _, err := q.RevokeOrgBoundPATsForUser(ctx, storegen.RevokeOrgBoundPATsForUserParams{UserID: userID, OrgID: &orgID}); err != nil {
			return err
		}
		if _, err := q.RevokeUserSessions(ctx, userID); err != nil {
			return err
		}
		// A remembered browser is a way back in that outlives the sessions
		// killed just above, and deactivation leaves the account's password and
		// state untouched on purpose — the person may exist outside the
		// organization. Without this the deprovisioned user could sign in again
		// and be asked for *less* than before, the second factor skipped, which
		// is the opposite of what this function promises.
		if _, err := q.RevokeTrustedDevicesForUser(ctx, userID); err != nil {
			return err
		}
		row := ev
		if kept {
			row.Detail = map[string]any{"lastAdminKept": true}
			for k, v := range ev.Detail {
				row.Detail[k] = v
			}
		}
		if err := s.auditW.Write(ctx, q, row); err != nil {
			return err
		}
		// Deprovisioned from the staff organization is no longer staff;
		// whoever deprovisioned is the actor.
		actor := ev
		actor.Action = audit.ActionUserStaffSync
		return s.syncStaffIn(ctx, q, userID, registry.StaffSyncMembership, actor)
	})
	return kept, err
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
