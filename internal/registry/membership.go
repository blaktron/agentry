package registry

// The membership chokepoint (plan organization-subscriptions §5.2, D3, D7,
// D26; agentry#361). Every path that makes someone an active member of an
// organization — accepting an invitation, an admin approving a
// SCIM-provisioned or domain-folded person, an admin changing a role —
// comes through ActivateMember. It is one function so the things that must
// be true of every door are true by construction rather than by each
// door's diligence: the seat count is taken under the organization's row
// lock, an unresolvable entitlement refuses, a person may be active in one
// organization at a time, and `member.added` fires exactly once per
// membership that actually became active.

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// OrgEventSink receives an organization-scoped event after it has
// committed (the API layer's webhook fan-out plus extension hooks). Set by
// the api layer; nil means no fan-out.
type OrgEventSink func(ctx context.Context, orgID uuid.UUID, event string, payload map[string]any)

// SetOrgEventSink wires the post-commit organization fan-out.
func (s *Service) SetOrgEventSink(sink OrgEventSink) { s.orgEventSink = sink }

// Seats is what an organization holds against its allowance: Used is its
// active memberships, Invited its open invitations — an invitation
// reserves a seat when it is sent, so the wall is met by the admin who
// invites, not by the person who accepts — and Pending the people waiting
// for an admin, who hold none. Max is the allowance; 0 means unbounded,
// which is what a registry with no extension answers.
type Seats struct {
	Used    int64 `json:"used"`
	Invited int64 `json:"invited"`
	Pending int64 `json:"pending"`
	Max     int64 `json:"max"`
}

// Taken is the seats an organization has spent: active members plus open
// invitations.
func (s Seats) Taken() int64 { return s.Used + s.Invited }

// ErrSeatAllowance reports that the organization holds as many seats as its
// subscription allows. Nothing is removed when it is returned: over the
// allowance nothing can be added and nothing is lost.
var ErrSeatAllowance = errors.New("registry: this organization holds as many seats as its subscription allows")

// ErrAlreadyAMember reports that the person is an active member of another
// organization (D26: one organization per person).
var ErrAlreadyAMember = errors.New("registry: this person is already a member of another organization")

// ErrSeatsNotOffered reports that the organization may hold no seats at
// all — a subscription that is not paying. Distinct from the allowance
// being reached, so the caller can say which it is.
var ErrSeatsNotOffered = errors.New("registry: this organization's subscription does not include seats")

// MembershipVia names the door a membership came through, for the audit
// row and the event payload.
type MembershipVia string

// The doors (plan §4 "The doors").
const (
	ViaInvitation MembershipVia = "invitation" // the invitee accepted
	ViaApproval   MembershipVia = "approval"   // an admin approved a pending member
	ViaRoleChange MembershipVia = "role"       // an admin changed an existing member's role
)

// ActivateMember is the one operation that makes a membership active.
//
// orgID and userID name the membership; role is what they hold; via names
// the door, for the audit row. actorEvent carries the acting principal
// (the invitee for an accept, the admin for an approval), already filled
// in by the API layer the way every other audited act is.
//
// It reports whether this call was the activation: a membership that was
// already active is left alone and reports false, so a repeated accept or
// a double-clicked approval does not fire a second `member.added`.
func (s *Service) ActivateMember(ctx context.Context, orgID, userID uuid.UUID, role auth.OrgRole, via MembershipVia, actorEvent audit.Event) (bool, error) {
	var (
		activated bool
		viaSCIM   bool
	)
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		// The organization's row is the lock every seat decision is taken
		// under, so two admins approving at the same moment cannot both
		// see the last seat free.
		if err := q.LockOrg(ctx, orgID); err != nil {
			return err
		}
		current, err := q.GetMembership(ctx, storegen.GetMembershipParams{OrgID: orgID, UserID: userID})
		switch {
		case err == nil:
			viaSCIM = current.ViaScim
			if current.State == "active" {
				// Already a member: a role change, not an activation. It
				// consumes no seat and is not a new membership.
				if auth.OrgRole(current.Role) == role {
					return nil
				}
				return q.UpsertMembership(ctx, storegen.UpsertMembershipParams{
					OrgID: orgID, UserID: userID, Role: string(role), ViaScim: viaSCIM,
				})
			}
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return err
		}

		// A person is active in at most one organization at a time (D26).
		elsewhere, err := q.CountActiveMembershipsElsewhere(ctx, storegen.CountActiveMembershipsElsewhereParams{UserID: userID, OrgID: orgID})
		if err != nil {
			return err
		}
		if elsewhere > 0 {
			return ErrAlreadyAMember
		}

		// The seat wall. A person accepting an invitation already holds the
		// seat that invitation reserved, so their acceptance is not asked
		// to find another one.
		holdsAnInvitation := via == ViaInvitation
		if err := s.checkSeatAllowance(ctx, q, orgID, holdsAnInvitation); err != nil {
			return err
		}

		n, err := q.ActivateMembership(ctx, storegen.ActivateMembershipParams{
			OrgID: orgID, UserID: userID, Role: string(role), ViaScim: viaSCIM,
		})
		if err != nil {
			return err
		}
		activated = n > 0
		if !activated {
			return nil
		}
		e := actorEvent
		e.Action = audit.ActionOrgMemberSet
		e.OrgID = orgID
		e.TargetKind, e.TargetID = "user", userID
		e.Detail = map[string]any{"role": string(role), "state": "active", "via": string(via)}
		return s.aud.Write(ctx, q, e)
	})
	if err != nil {
		return false, err
	}
	if activated && s.orgEventSink != nil {
		s.orgEventSink(ctx, orgID, eventMemberAdded, map[string]any{
			"user": userID.String(), "role": string(role), "via": string(via),
		})
	}
	return activated, nil
}

// eventMemberAdded is the webhook kind the chokepoint fires. It is spelled
// here rather than imported from internal/webhook so the domain package
// does not depend on the delivery one.
const eventMemberAdded = "member.added"

// CheckSeatAllowanceIn reports whether the organization may take one more
// seat, for a door that reserves one before any membership exists — an
// admin sending an invitation. It runs inside the caller's transaction, so
// the count and the insert that consumes it commit together; the caller
// holds the organization's row lock first, as ActivateMember does.
func (s *Service) CheckSeatAllowanceIn(ctx context.Context, q *storegen.Queries, orgID uuid.UUID) error {
	return s.checkSeatAllowance(ctx, q, orgID, false)
}

// checkSeatAllowance refuses one more seat when the organization's
// allowance is reached. An unresolvable entitlement is not permission: the
// error is returned and the caller stores nothing.
//
// holdsAnInvitation excuses the one seat the caller's own open invitation
// is already counted in, so accepting an invitation that was within the
// allowance when it was sent is not refused for the seat it reserved.
func (s *Service) checkSeatAllowance(ctx context.Context, q *storegen.Queries, orgID uuid.UUID, holdsAnInvitation bool) error {
	f, err := s.Entitlements().Features(ctx, entitlements.ForOrg(orgID))
	if err != nil {
		return fmt.Errorf("registry: entitlements: %w", err)
	}
	if !f.Seats.Enabled {
		return ErrSeatsNotOffered
	}
	if f.Seats.Max <= 0 {
		return nil // unbounded: a registry with no extension caps nothing
	}
	seats, err := s.seats(ctx, q, orgID, f.Seats.Max)
	if err != nil {
		return err
	}
	taken := seats.Taken()
	if holdsAnInvitation && taken > 0 {
		taken--
	}
	if taken >= f.Seats.Max {
		return ErrSeatAllowance
	}
	return nil
}

// Seats reports the organization's seat usage against its allowance, for
// the org resource and for a refusal's fields.
func (s *Service) Seats(ctx context.Context, orgID uuid.UUID) (Seats, error) {
	f, err := s.Entitlements().Features(ctx, entitlements.ForOrg(orgID))
	if err != nil {
		return Seats{}, fmt.Errorf("registry: entitlements: %w", err)
	}
	return s.seats(ctx, s.st.Queries(), orgID, f.Seats.Max)
}

func (s *Service) seats(ctx context.Context, q *storegen.Queries, orgID uuid.UUID, max int64) (Seats, error) {
	row, err := q.CountOrgSeats(ctx, orgID)
	if err != nil {
		return Seats{}, fmt.Errorf("registry: seat count: %w", err)
	}
	return Seats{Used: row.Used, Invited: row.Invited, Pending: row.Pending, Max: max}, nil
}
