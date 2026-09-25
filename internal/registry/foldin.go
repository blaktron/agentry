package registry

// The fold-in (plan organization-subscriptions §4 "Fold-in", §5.5; D22,
// D25; agentry#364). When an organization exists at a domain, an account
// whose verified address is at that domain and who is a member of nothing
// becomes a pending member of it — at the person's next directory sign-in,
// or when the sweep runs over the accounts already known at the domain.
// It is the SCIM door's twin: it writes `pending` and nothing else, so the
// seat is still taken where every seat is, in ActivateMember, by an admin.
// It never fires for an unverified address, for a public mail domain, for
// a person who holds a membership anywhere (pending included), for an
// organization that is suspended or in its hold, or for a person the
// organization declined before — an admin's invitation supersedes that.

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/maildomains"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// FoldInRequest is one person's fold-in, at their sign-in.
type FoldInRequest struct {
	UserID uuid.UUID
	// Email and EmailVerified are the identity token's fresh assertion,
	// not the stored address: the plan keys the step on what the
	// directory said at this sign-in.
	Email         string
	EmailVerified bool
	// Actor is the audit event to fill in — the person themselves.
	Actor audit.Event
}

// FoldInResult says what the fold-in did.
type FoldInResult struct {
	// Fired is whether this call wrote a pending membership.
	Fired bool
	// OrgHandle is the organization at the domain, when it fired.
	OrgHandle string
}

// FoldIn runs the sign-in step for one person. It is idempotent on
// (organization, person): a second sign-in finds the pending row and
// writes nothing. Every reason not to fire returns a zero result and no
// error; an error is a failure to look, which the caller logs — a sign-in
// never fails because the fold-in could not run.
func (s *Service) FoldIn(ctx context.Context, req FoldInRequest) (FoldInResult, error) {
	if !req.EmailVerified || req.Email == "" {
		return FoldInResult{}, nil
	}
	domain := maildomains.Of(req.Email)
	if domain == "" || maildomains.Shared(domain) {
		return FoldInResult{}, nil
	}
	org, err := s.st.Queries().GetOrgByDomain(ctx, domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return FoldInResult{}, nil
	}
	if err != nil {
		return FoldInResult{}, fmt.Errorf("registry: fold-in: org at domain: %w", err)
	}
	if permits, err := s.orgPermitsFoldIn(ctx, org.ID); err != nil || !permits {
		return FoldInResult{}, err
	}
	fired, err := s.writePending(ctx, org.ID, req.UserID, domain, req.Actor)
	if err != nil {
		return FoldInResult{}, err
	}
	return FoldInResult{Fired: fired, OrgHandle: org.Handle}, nil
}

// orgPermitsFoldIn reports whether the organization's state lets anyone
// be folded in: nobody joins, even as pending, an organization that is
// suspended or in its hold, whose admins can approve nobody. A refusal is
// a fact; a failure to read the state is an error.
func (s *Service) orgPermitsFoldIn(ctx context.Context, orgID uuid.UUID) (bool, error) {
	err := s.OrgGate(ctx, orgID, auth.ActOrgMembersManage)
	var gate *OrgGateError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &gate), errors.Is(err, ErrNotFound):
		return false, nil
	}
	return false, fmt.Errorf("registry: fold-in: org state: %w", err)
}

// FoldInSweep folds in every account already known at a domain the
// organization has just gained — at its creation, or a DNS verification —
// so its admins see them at once rather than as each signs in. Reports how
// many it folded in. The listing applies the same rules as FoldIn; the
// write is the same write.
func (s *Service) FoldInSweep(ctx context.Context, orgID uuid.UUID, domain string) (int, error) {
	if domain == "" || maildomains.Shared(domain) {
		return 0, nil
	}
	if permits, err := s.orgPermitsFoldIn(ctx, orgID); err != nil || !permits {
		return 0, err
	}
	rows, err := s.st.Queries().ListUsersAtDomainForFoldIn(ctx, storegen.ListUsersAtDomainForFoldInParams{Domain: domain, OrgID: orgID})
	if err != nil {
		return 0, fmt.Errorf("registry: fold-in sweep: %w", err)
	}
	folded := 0
	for _, u := range rows {
		fired, err := s.writePending(ctx, orgID, u.ID, domain, audit.Event{ActorKind: audit.ActorSystem})
		if err != nil {
			return folded, err
		}
		if fired {
			folded++
		}
	}
	return folded, nil
}

// writePending is the fold-in's one write: the pending row, once, and its
// audit event in the same transaction, after the two rules about the
// person are checked under the person's advisory lock — no membership row
// anywhere, no decline by this organization — so two fold-ins of one
// person (a sign-in and a sweep at once) cannot both pass. An activation
// elsewhere at the same moment is not serialised against this (the
// chokepoint takes the person's row lock, agentry#412, and this takes an
// advisory lock on the person: different locks); the worst of it is a
// pending row beside an active membership, which the approval then
// refuses with already-a-member and an admin declines. Reports whether
// the row was written by this call.
func (s *Service) writePending(ctx context.Context, orgID, userID uuid.UUID, domain string, actor audit.Event) (bool, error) {
	fired := false
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if err := q.LockKey(ctx, "fold-in:"+userID.String()); err != nil {
			return err
		}
		if n, err := q.CountMemberships(ctx, userID); err != nil || n > 0 {
			// A member of something — this organization (pending or
			// active) or another — is left as they are.
			return err
		}
		if _, err := q.GetFoldInDecline(ctx, storegen.GetFoldInDeclineParams{OrgID: orgID, UserID: userID}); err == nil {
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// The staff organization folds in only its own domain (agentry#556):
		// a DNS claim of another domain does not make its people eligible.
		if err := s.CheckStaffOrgDoorIn(ctx, q, orgID, userID); errors.Is(err, ErrStaffOrgDomain) {
			return nil
		} else if err != nil {
			return err
		}
		n, err := q.UpsertPendingMembership(ctx, storegen.UpsertPendingMembershipParams{
			OrgID: orgID, UserID: userID, Role: string(auth.RoleMember), ViaScim: false, ViaDomain: true,
		})
		if err != nil {
			return err
		}
		fired = n > 0
		if !fired {
			return nil
		}
		e := actor
		e.Action = audit.ActionOrgMemberPending
		e.OrgID = orgID
		e.TargetKind, e.TargetID = "user", userID
		e.Detail = map[string]any{"via": string(ViaDomain), "domain": domain, "state": StatePending}
		return s.aud.Write(ctx, q, e)
	})
	if err != nil {
		return false, fmt.Errorf("registry: fold-in: write pending: %w", err)
	}
	return fired, nil
}
