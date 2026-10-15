// Platform staff is membership of the staff organization.
//
// A deployment names its staff organization and that organization's domain
// (config auth.staffOrg, auth.staffDomain). An account is platform staff
// exactly while three facts hold, none of which a person can set about
// themselves:
//
//   - the account is active;
//   - its address is verified and its domain is exactly the staff domain
//     (plain ASCII, so an internationalised look-alike never matches); a
//     stored address changes only at erasure, and signing in to it needs
//     its mailbox or the directory, where nobody changes their own;
//   - it is an active member of the staff organization, which only that
//     organization's admins grant.
//
// Founding the staff organization is reserved to platform staff (the API's
// CreateOrg), so a deployment's first staff are seeded by its operator. The
// staff organization admits nobody whose address is outside its domain,
// at every door: the activation chokepoint (invitations, approvals), the
// pending doors (the fold-in, SCIM) and the invitation itself. The flag is
// recomputed by SyncStaffIn inside the transaction of every membership
// change, at sign-in, and over every candidate once when the server starts,
// and each change is audited as user.staff_sync naming the rule. Nothing
// else writes platform_staff: neither a directory group nor a domain
// alone makes anyone staff.
package registry

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/maildomains"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// ErrStaffOrgDomain refuses an address outside the staff domain at one of
// the staff organization's doors.
var ErrStaffOrgDomain = errors.New("registry: the staff organization admits only addresses at its domain")

// StaffRule is the rule name the audit row records for the staff
// organization's grant or revocation.
const StaffRule = "staff-org"

// The reasons a staff sync ran, for the audit row.
const (
	StaffSyncSignIn     = "sign-in"
	StaffSyncMembership = "membership"
	StaffSyncErasure    = "erasure"
	StaffSyncStartup    = "startup"
)

// SetStaffOrg names the staff organization and its domain. Both empty (the
// default) leaves platform_staff alone: nothing syncs and no door checks.
func (s *Service) SetStaffOrg(handle, domain string) {
	s.staffOrg, s.staffDomain = handle, domain
}

// SetStaffChanged names a function to call after a sync changed someone's
// platform_staff. It runs inside the sync's transaction, before it commits,
// so it must not read the change back: the directory mirror it serves
// queues a run for a few seconds later.
func (s *Service) SetStaffChanged(fn func()) { s.staffChanged = fn }

// StaffConfigured reports whether a staff organization is named.
func (s *Service) StaffConfigured() bool { return s.staffOrg != "" && s.staffDomain != "" }

// staffOrgIDIn resolves the staff organization's id. ok is false when none
// is configured or the organization does not exist yet: then nobody is staff
// through it.
func (s *Service) staffOrgIDIn(ctx context.Context, q *storegen.Queries) (uuid.UUID, bool, error) {
	if !s.StaffConfigured() {
		return uuid.Nil, false, nil
	}
	org, err := q.GetOrgByHandle(ctx, s.staffOrg)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	return org.ID, true, nil
}

// atStaffDomain reports whether a verified address is at exactly the staff
// domain. The domain must be plain ASCII before it is compared:
// strings.ToLower folds the Kelvin sign to "k" and a dotted capital I to
// "i", so an internationalised look-alike would otherwise match.
func (s *Service) atStaffDomain(email string, verified bool) bool {
	if !verified || s.staffDomain == "" {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	raw := email[at+1:]
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 0x80 {
			return false
		}
	}
	return maildomains.Of(email) == s.staffDomain
}

// CheckStaffOrgDoorIn refuses to admit userID to orgID when orgID is the
// staff organization and the account's verified address is not at its
// domain. Every door into an organization calls it inside its own
// transaction; for any other organization it answers nil.
func (s *Service) CheckStaffOrgDoorIn(ctx context.Context, q *storegen.Queries, orgID, userID uuid.UUID) error {
	staffID, ok, err := s.staffOrgIDIn(ctx, q)
	if err != nil || !ok || staffID != orgID {
		return err
	}
	u, err := q.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !s.atStaffDomain(u.Email, u.EmailVerifiedAt != nil) {
		return ErrStaffOrgDomain
	}
	return nil
}

// CheckStaffOrgAddress is the door check for an address that has no
// account behind it yet: an invitation to the staff organization is refused
// unless the address is at its domain. The address is checked as written;
// the accept checks the account's verified one.
func (s *Service) CheckStaffOrgAddress(ctx context.Context, q *storegen.Queries, orgID uuid.UUID, email string) error {
	staffID, ok, err := s.staffOrgIDIn(ctx, q)
	if err != nil || !ok || staffID != orgID {
		return err
	}
	if !s.atStaffDomain(email, true) {
		return ErrStaffOrgDomain
	}
	return nil
}

// SyncStaffIn recomputes one account's platform_staff inside the caller's
// transaction and audits a change. actor is the act's principal (the admin
// who approved or removed, the person signing in); a zero actor is the
// system. With no staff organization configured it does nothing.
func (s *Service) SyncStaffIn(ctx context.Context, q *storegen.Queries, userID uuid.UUID, reason string, actor audit.Event) error {
	if !s.StaffConfigured() {
		return nil
	}
	// The person's row lock serialises this against every other sync and
	// membership change for them: a sign-in that read the membership just
	// before a removal committed cannot write its stale answer after the
	// removal's own sync. The activation chokepoint already holds it.
	if err := q.LockUser(ctx, userID); err != nil {
		return err
	}
	u, err := q.GetUserByID(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	want := false
	staffID, ok, err := s.staffOrgIDIn(ctx, q)
	if err != nil {
		return err
	}
	if ok && u.State == "active" && s.atStaffDomain(u.Email, u.EmailVerifiedAt != nil) {
		m, err := q.GetMembership(ctx, storegen.GetMembershipParams{OrgID: staffID, UserID: userID})
		switch {
		case err == nil:
			want = m.State == StateActive
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return err
		}
	}
	if u.PlatformStaff == want {
		return nil
	}
	if err := q.SetUserPlatformStaff(ctx, storegen.SetUserPlatformStaffParams{ID: userID, PlatformStaff: want}); err != nil {
		return err
	}
	e := actor
	if e.ActorKind == "" {
		e.ActorKind = audit.ActorSystem
	}
	e.Action = audit.ActionUserStaffSync
	e.TargetKind, e.TargetID = "user", userID
	e.Detail = map[string]any{
		"platformStaff": want, "rule": StaffRule, "reason": reason,
		"org": s.staffOrg, "domain": s.staffDomain,
	}
	if err := s.aud.Write(ctx, q, e); err != nil {
		return err
	}
	if s.staffChanged != nil {
		s.staffChanged()
	}
	return nil
}

// SyncStaff is SyncStaffIn in a transaction of its own, for a door that has
// no transaction open (the sign-in).
func (s *Service) SyncStaff(ctx context.Context, userID uuid.UUID, reason string, actor audit.Event) error {
	if !s.StaffConfigured() {
		return nil
	}
	return s.st.WithTx(ctx, func(q *storegen.Queries) error {
		return s.SyncStaffIn(ctx, q, userID, reason, actor)
	})
}

// ResyncStaffIn recomputes every account the rule could change — everyone
// flagged today and every active member of the staff organization — inside
// the caller's transaction, under an advisory lock so two replicas starting
// at once do not both audit the same change. It reports how many accounts
// it looked at.
func (s *Service) ResyncStaffIn(ctx context.Context, q *storegen.Queries, reason string, actor audit.Event) (int, error) {
	if !s.StaffConfigured() {
		return 0, nil
	}
	if err := q.LockKey(ctx, "staff-resync"); err != nil {
		return 0, err
	}
	staffID, _, err := s.staffOrgIDIn(ctx, q)
	if err != nil {
		return 0, err
	}
	ids, err := q.ListStaffSyncCandidates(ctx, staffID)
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err := s.SyncStaffIn(ctx, q, id, reason, actor); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

// StaffOrgMembersNotStaff returns the handles of the staff organization's
// active members who are not platform staff: members from before the
// organization's door checked the domain, or whose account is no longer
// active. They are reported, never removed: removing a member
// is the organization's admins' act.
func (s *Service) StaffOrgMembersNotStaff(ctx context.Context) ([]string, error) {
	if !s.StaffConfigured() {
		return nil, nil
	}
	q := s.st.Queries()
	staffID, ok, err := s.staffOrgIDIn(ctx, q)
	if err != nil || !ok {
		return nil, err
	}
	return q.ListStaffOrgMembersNotStaff(ctx, staffID)
}

// ResyncStaff is ResyncStaffIn in a transaction of its own, run once when
// the server starts, so a configuration change takes effect then rather
// than at each person's next sign-in.
func (s *Service) ResyncStaff(ctx context.Context) (int, error) {
	if !s.StaffConfigured() {
		return 0, nil
	}
	var n int
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		var err error
		n, err = s.ResyncStaffIn(ctx, q, StaffSyncStartup, audit.Event{})
		return err
	})
	return n, err
}
