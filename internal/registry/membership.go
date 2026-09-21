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
	"github.com/jackc/pgx/v5/pgconn"

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

// The membership states (memberships.state). A pending membership holds no
// seat and confers nothing; an active one is a member.
const (
	StatePending = "pending"
	StateActive  = "active"
)

// MembershipVia names the door a membership came through, for the audit
// row and the event payload.
type MembershipVia string

// The doors (plan §4 "The doors").
const (
	ViaInvitation MembershipVia = "invitation" // the invitee accepted
	ViaApproval   MembershipVia = "approval"   // an admin approved a pending member
	ViaRoleChange MembershipVia = "role"       // an admin changed an existing member's role
	// The two provisioning doors, which write pending and nothing else:
	// the organization's IdP, and its domain (DEV-111).
	ViaSCIM   MembershipVia = "scim"
	ViaDomain MembershipVia = "domain"
)

// DoorOf names the provisioning door a membership row records, from its
// two flags: the IdP's door first, since SCIM provisioning is the
// organization's own act and the domain is the registry's inference. An
// admin-granted membership has neither and is "".
func DoorOf(viaSCIM, viaDomain bool) MembershipVia {
	switch {
	case viaSCIM:
		return ViaSCIM
	case viaDomain:
		return ViaDomain
	}
	return ""
}

// ActivateMemberRequest is what one activation needs.
type ActivateMemberRequest struct {
	OrgID  uuid.UUID
	UserID uuid.UUID
	// Role is what the person will hold.
	Role auth.OrgRole
	// Via names the door, for the audit row and the event.
	Via MembershipVia
	// Actor carries the acting principal (the invitee for an accept, the
	// admin for an approval), filled in by the API layer the way every
	// other audited act is.
	Actor audit.Event
	// Spend runs inside the same transaction, before the seat is counted:
	// the invitation door spends its token here. Putting it inside means a
	// token cannot be consumed by an activation that is then refused, and
	// that the invitation has left the open count by the time the seat is
	// counted — so the seat it reserved is the one being taken, not a
	// second one. nil for a door that reserves nothing.
	Spend func(ctx context.Context, q *storegen.Queries) error
}

// ActivateMember is the one operation that makes a membership active.
//
// It reports whether this call was the activation: a membership that was
// already active is left alone and reports false, so a repeated accept or
// a double-clicked approval does not fire a second `member.added`.
func (s *Service) ActivateMember(ctx context.Context, req ActivateMemberRequest) (bool, error) {
	var (
		activated bool
		viaSCIM   bool
		viaDomain bool
	)
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		// The organization's row is the lock every seat decision is taken
		// under, so two admins approving at the same moment cannot both
		// see the last seat free.
		if err := q.LockOrg(ctx, req.OrgID); err != nil {
			return err
		}
		current, err := q.GetMembership(ctx, storegen.GetMembershipParams{OrgID: req.OrgID, UserID: req.UserID})
		switch {
		case err == nil:
			viaSCIM, viaDomain = current.ViaScim, current.ViaDomain
			if current.State == StateActive {
				// Already a member: a role change, not an activation. It
				// consumes no seat and is not a new membership.
				if auth.OrgRole(current.Role) == req.Role {
					return nil
				}
				_, err := q.UpsertMembership(ctx, storegen.UpsertMembershipParams{
					OrgID: req.OrgID, UserID: req.UserID, Role: string(req.Role),
				})
				return err
			}
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return err
		}

		if req.Spend != nil {
			if err := req.Spend(ctx, q); err != nil {
				return err
			}
		}

		// Nobody joins an organization that is suspended or in its
		// decommission hold (agentry#363); the row lock above means the
		// state read here is the one the activation commits against.
		if err := s.OrgGateIn(ctx, q, req.OrgID, auth.ActOrgMembersManage); err != nil {
			return err
		}

		// A person is active in at most one organization at a time (D26).
		// The person's row lock — after the organization's, always in
		// that order — serialises this count against every other
		// organization's door; the partial unique index on active
		// memberships is the wall behind it (agentry#412).
		if err := q.LockUser(ctx, req.UserID); err != nil {
			return err
		}
		elsewhere, err := q.CountActiveMembershipsElsewhere(ctx, storegen.CountActiveMembershipsElsewhereParams{UserID: req.UserID, OrgID: req.OrgID})
		if err != nil {
			return err
		}
		if elsewhere > 0 {
			return ErrAlreadyAMember
		}

		if err := s.checkSeatAllowance(ctx, q, req.OrgID); err != nil {
			return err
		}

		n, err := q.ActivateMembership(ctx, storegen.ActivateMembershipParams{
			OrgID: req.OrgID, UserID: req.UserID, Role: string(req.Role), ViaScim: viaSCIM, ViaDomain: viaDomain,
		})
		if err != nil {
			if isOneOrgPerPersonViolation(err) {
				return ErrAlreadyAMember
			}
			return err
		}
		activated = n > 0
		if !activated {
			return nil
		}
		// An admin's invitation or approval supersedes a decline the
		// fold-in remembered (agentry#364, D25): the person is a member.
		if _, err := q.DeleteFoldInDecline(ctx, storegen.DeleteFoldInDeclineParams{OrgID: req.OrgID, UserID: req.UserID}); err != nil {
			return err
		}
		e := req.Actor
		e.Action = audit.ActionOrgMemberSet
		e.OrgID = req.OrgID
		e.TargetKind, e.TargetID = "user", req.UserID
		e.Detail = map[string]any{"role": string(req.Role), "state": StateActive, "via": string(req.Via)}
		return s.aud.Write(ctx, q, e)
	})
	if err != nil {
		return false, err
	}
	if activated && s.orgEventSink != nil {
		s.orgEventSink(ctx, req.OrgID, eventMemberAdded, map[string]any{
			"user": req.UserID.String(), "role": string(req.Role), "via": string(req.Via),
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
	return s.checkSeatAllowance(ctx, q, orgID)
}

// checkSeatAllowance refuses one more seat when the organization's
// allowance is reached. An unresolvable entitlement is not permission: the
// error is returned and the caller stores nothing.
//
// The count is authoritative at the moment it runs, under the
// organization's row lock: an invitation that has just been spent has
// already left the open count, so accepting one takes the seat that
// invitation was holding rather than a second one.
func (s *Service) checkSeatAllowance(ctx context.Context, q *storegen.Queries, orgID uuid.UUID) error {
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
	if seats.Taken() >= f.Seats.Max {
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

// isOneOrgPerPersonViolation recognises the database refusing a second
// active membership for one person (memberships_one_active_per_user): the
// doors count under the person's lock and should never reach it, and when
// something does, the answer is the same 409 the count gives.
func isOneOrgPerPersonViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "memberships_one_active_per_user"
}
