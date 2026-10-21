package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/maildomains"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/webhook"
)

// lookupFailed writes the problem for a handle lookup that did not yield an
// active row, and reports whether it wrote one. A missing row is 404; a
// query error is 500, logged — never 404, because a client that takes 404 as
// "this handle is nobody's" (the site's namespace rule) must
// be able to mean it. The caller decides the inactive case.
func (s *Server) lookupFailed(w http.ResponseWriter, r *http.Request, what string, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, pgx.ErrNoRows) {
		problemNotFound(w, r)
		return true
	}
	s.log.ErrorContext(r.Context(), what+" lookup", "err", err)
	problemInternal(w, r)
	return true
}

// orgOrNotFound resolves an org handle or writes the problem: 404 for a
// handle no active organisation holds, 500 for a lookup that failed. An
// organization in its decommission hold is found — its members still
// read it — and the authorize chokepoint refuses every change to it; a
// suspended or erased one is absent.
func (s *Server) orgOrNotFound(w http.ResponseWriter, r *http.Request, handle string) (storegen.GetOrgByHandleRow, bool) {
	row, err := s.q().GetOrgByHandle(r.Context(), handle)
	if s.lookupFailed(w, r, "org", err) {
		return storegen.GetOrgByHandleRow{}, false
	}
	switch row.State {
	case registry.OrgStateActive, registry.OrgStateDecommissioning:
		return row, true
	}
	problemNotFound(w, r)
	return storegen.GetOrgByHandleRow{}, false
}

// userOrNotFound resolves a user handle or writes the problem: 404 for a
// handle no active account holds, 500 for a lookup that failed.
func (s *Server) userOrNotFound(w http.ResponseWriter, r *http.Request, handle string) (storegen.GetUserByHandleRow, bool) {
	row, err := s.q().GetUserByHandle(r.Context(), handle)
	if s.lookupFailed(w, r, "user", err) {
		return storegen.GetUserByHandleRow{}, false
	}
	if row.State != "active" {
		problemNotFound(w, r)
		return storegen.GetUserByHandleRow{}, false
	}
	return row, true
}

func orgToAPI(row storegen.GetOrgByHandleRow, includeSettings bool) Org {
	o := Org{Id: row.ID, Handle: row.Handle, DisplayName: row.DisplayName, CreatedAt: row.CreatedAt}
	state := OrgState(row.State)
	o.State = &state
	if row.State == registry.OrgStateDecommissioning && row.DecommissionAt != nil {
		o.DecommissionAt = row.DecommissionAt
	}
	if row.Domain != nil && *row.Domain != "" {
		o.Domain = row.Domain
	}
	if len(row.VerifiedDomains) > 0 {
		vd := append([]string(nil), row.VerifiedDomains...)
		o.VerifiedDomains = &vd
		first := vd[0]
		o.VerifiedDomain = &first
	}
	if includeSettings {
		sso := row.SsoRequired
		o.SsoRequired = &sso
	}
	if u := logoURL(row.Handle, row.LogoObjectKey); u != "" {
		o.LogoUrl = &u
	}
	return o
}

// withSeats adds the organization's seat usage, which its members may see
// and nobody else may: how many people an organization licenses is its own
// business. A seat count that cannot be resolved is left off rather than
// failing the read — the resource is the organization, not its billing.
func (s *Server) withSeats(r *http.Request, o Org, orgID uuid.UUID) Org {
	seats, err := s.reg.Seats(r.Context(), orgID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "org seats", "org", orgID, "err", err)
		return o
	}
	o.Seats = &Seats{Used: seats.Used, Invited: seats.Invited, Pending: seats.Pending, Max: seats.Max}
	return o
}

// CreateOrg implements POST /orgs; the caller becomes its first admin.
// Four gates precede the handle rules. The account's
// email must be verified, because an organization is keyed on its
// creator's domain: the domain
// of that address is recorded as the organization's unless the body says
// `none` or the domain is one nobody owns (a public mail provider), and a
// domain already registered to an organization — at its creation, or
// verified over DNS — is 409 domain-claimed naming it. The
// account may be an active member of no other organization (one
// organization per person): the creator becomes the org's
// first admin, and that is a membership like any other. And the account
// may have at most one organization awaiting activation: on the hosted
// product an org is a paid thing that starts out awaiting payment, and
// the core refuses a second until the first is activated or gone, so
// nobody squats handles behind organizations that never pay. Where
// nothing will activate an org later — no admission extension, so no
// payment — it is activated as it is created, and the rule never bites
// (the core with no extension is unchanged).
func (s *Server) CreateOrg(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActOrgCreate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if !p.EmailVerified {
		problemEmailUnverified(w, r, "Verify this account's email address before creating an organization.")
		return
	}
	ik, handled := s.beginIdempotent(w, r, "POST /orgs")
	if handled {
		return
	}
	defer ik.abandon(r)
	var req CreateOrgRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !reHandle.MatchString(req.Handle) {
		problemValidation(w, r, "An org handle is 1-39 lowercase letters, digits and hyphens, starting and ending with a letter or digit.")
		return
	}
	if orgHandleReserved(req.Handle, p.PlatformStaff) {
		problemValidation(w, r, "That org handle is reserved. Choose another.")
		return
	}
	// The staff organization's handle is reserved to platform staff:
	// founding it makes its first member, and so its first
	// staff, and nobody may make themselves staff. A deployment's first
	// staff are seeded by its operator (docs/self-hosting.md).
	if req.Handle == s.cfg.Auth.StaffOrg && !p.PlatformStaff {
		problemValidation(w, r, "That org handle is reserved. Choose another.")
		return
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" || len(name) > 120 {
		problemValidation(w, r, "Set displayName to 1-120 characters.")
		return
	}
	activated := !s.orgsAwaitActivation()
	if !activated {
		// The early answer names the pending organization; the unique
		// partial index is what holds the rule under concurrent requests.
		pending, err := s.q().GetPendingOrgCreatedBy(r.Context(), &p.UserID)
		switch {
		case err == nil:
			problemOrgPending(w, r, pending)
			return
		case !errors.Is(err, pgx.ErrNoRows):
			s.log.ErrorContext(r.Context(), "pending org", "err", err)
			problemInternal(w, r)
			return
		}
	}
	// One organization per person: the creator's founding
	// membership is a membership, and the rule that refuses an invitation
	// or an approval for someone active elsewhere refuses this door too.
	// Platform staff are not exempt — a first-party organization is made
	// by an account that belongs to no other, and the invariant holds at
	// every door or it is not one. After the pending rule,
	// which names the organization that is in the way.
	elsewhere, err := s.q().CountActiveMemberships(r.Context(), p.UserID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "memberships", "err", err)
		problemInternal(w, r)
		return
	}
	if elsewhere > 0 {
		problemAlreadyAMember(w, r, alreadyAMemberCreatorDetail)
		return
	}
	domain, ok := s.orgDomainFor(w, r, p.UserID, req.Domain)
	if !ok {
		return
	}
	orgID := newUUID()
	var domainParam *string
	if domain != "" {
		domainParam = &domain
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		// One organization per domain spans orgs.domain and the verified
		// claims, which no constraint covers together: the domain's
		// advisory lock serialises this creation against a verification of
		// the same domain, and the holder is checked again under it.
		if domain != "" {
			if err := q.LockKey(r.Context(), domainLockKey(domain)); err != nil {
				return err
			}
			if _, err := q.GetOrgByDomain(r.Context(), domain); err == nil {
				return errDomainClaimed
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		// The one-organization-per-person count again, under the person's
		// row lock this time: the read above was on the pool, and two
		// doors for the same person at once must not both count zero
		// (the index memberships_one_active_per_user is the
		// wall behind this).
		if err := q.LockUser(r.Context(), p.UserID); err != nil {
			return err
		}
		if elsewhere, err := q.CountActiveMemberships(r.Context(), p.UserID); err != nil {
			return err
		} else if elsewhere > 0 {
			return registry.ErrAlreadyAMember
		}
		if err := q.CreateHandle(r.Context(), storegen.CreateHandleParams{ID: orgID, Handle: req.Handle, Kind: "org"}); err != nil {
			return err
		}
		if _, err := q.CreateOrg(r.Context(), storegen.CreateOrgParams{
			ID: orgID, DisplayName: name, CreatedBy: &p.UserID, Activated: activated, Domain: domainParam,
		}); err != nil {
			return err
		}
		if err := q.CreateFounderMembership(r.Context(), storegen.CreateFounderMembershipParams{
			OrgID: orgID, UserID: p.UserID, Role: string(auth.RoleAdmin),
		}); err != nil {
			return err
		}
		// The founder of the staff organization is its first member, so the
		// domain rule holds for them too, and founding it makes them staff.
		// For any other organization both are no-ops.
		if err := s.staffOrgDoorIn(r.Context(), q, orgID, p.UserID); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionOrgCreate)
		e.OrgID = orgID
		e.TargetKind, e.TargetID = "org", orgID
		e.Detail = map[string]any{"domain": domain}
		if err := s.auditW.Write(r.Context(), q, e); err != nil {
			return err
		}
		return s.syncStaffIn(r.Context(), q, p.UserID, registry.StaffSyncMembership, auditEvent(r, audit.ActionUserStaffSync))
	})
	if err != nil {
		if errors.Is(err, registry.ErrStaffOrgDomain) {
			problemStaffOrgDomain(w, r, req.Handle, s.cfg.Auth.StaffDomain)
			return
		}
		if errors.Is(err, registry.ErrAlreadyAMember) || uniqueViolationOn(err, "memberships_one_active_per_user") {
			problemAlreadyAMember(w, r, alreadyAMemberCreatorDetail)
			return
		}
		if uniqueViolationOn(err, "orgs_pending_by_creator_idx") {
			problemOrgPending(w, r, "an organization")
			return
		}
		if errors.Is(err, errDomainClaimed) || uniqueViolationOn(err, "orgs_domain_key") {
			// Two creations at one domain at once: the constraint decides,
			// and the loser learns who won.
			if !s.domainClaimed(w, r, domain, uuid.Nil) {
				problemDomainClaimed(w, r, domain, "another organization", "")
			}
			return
		}
		if isUniqueViolation(err) {
			problemConflict(w, r, "That org handle is already in use. Choose another.")
			return
		}
		s.log.ErrorContext(r.Context(), "create org", "err", err)
		problemInternal(w, r)
		return
	}
	row, err := s.q().GetOrgByHandle(r.Context(), req.Handle)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := orgToAPI(row, true)
	// The creator rides on the event: the extension that
	// opens the organization's billing row needs to know whose it is, and
	// the org's only member at this moment is the person who made it.
	s.fireEvent(r.Context(), Event{Kind: "org.created", OrgID: out.Id, UserID: p.UserID,
		Payload: map[string]any{"org": out.Handle, "creator": p.Handle}})
	// The accounts already known at the domain are folded in now, so the
	// admins see them at once; the ones that arrive later
	// fold in at their sign-in.
	s.enqueueFoldInSweep(r.Context(), orgID, domain)
	ik.complete(r, http.StatusCreated, out)
	writeJSON(w, http.StatusCreated, out)
}

// orgDomainFor decides the domain a new organization is keyed on, or
// writes the refusal and reports false: the creator's verified email
// domain, unless the body asks for none, and never a domain no single
// organization owns; a domain already registered is 409 domain-claimed
// naming its holder. "" is none.
func (s *Server) orgDomainFor(w http.ResponseWriter, r *http.Request, userID uuid.UUID, requested *string) (string, bool) {
	u, err := s.q().GetUserByID(r.Context(), userID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "creator", "err", err)
		problemInternal(w, r)
		return "", false
	}
	domain := maildomains.Of(u.Email)
	if requested != nil {
		switch normalizeDomain(*requested) {
		case "none":
			domain = ""
		case domain:
			// Spelled out: fine.
		default:
			problemValidation(w, r, "An organization's domain is the creator's verified email domain ("+domain+") or none; a further domain is claimed over DNS after creation.")
			return "", false
		}
	}
	if maildomains.Shared(domain) {
		// A public mail provider, or a reserved name: nobody's.
		domain = ""
	}
	if domain == "" {
		return "", true
	}
	if s.domainClaimed(w, r, domain, uuid.Nil) {
		return "", false
	}
	return domain, true
}

// errDomainClaimed is what a transaction returns when the domain it was
// about to record belongs to another organization.
var errDomainClaimed = errors.New("api: the domain belongs to another organization")

// domainLockKey is the advisory-lock name for a domain.
func domainLockKey(domain string) string { return "domain:" + domain }

// domainClaimed reports whether an organization other than except holds
// the domain — recorded at its creation, or verified over DNS — and writes
// 409 domain-claimed naming it when one does. A lookup that failed is
// written as a 500 and reported as claimed: an unreadable answer is not a
// free domain.
func (s *Server) domainClaimed(w http.ResponseWriter, r *http.Request, domain string, except uuid.UUID) bool {
	holder, err := s.q().GetOrgByDomain(r.Context(), domain)
	switch {
	case err == nil && holder.ID == except:
		return false
	case err == nil:
		problemDomainClaimed(w, r, domain, holder.Handle, holder.DisplayName)
		return true
	case errors.Is(err, pgx.ErrNoRows):
		return false
	default:
		s.log.ErrorContext(r.Context(), "domain holder", "domain", domain, "err", err)
		problemInternal(w, r)
		return true
	}
}

// GetOrg implements GET /orgs/{org} (public profile; settings for admins).
func (s *Server) GetOrg(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.authorize(w, r, auth.ActOrgRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	row, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	isAdmin := auth.Check(p, auth.Resource{OrgID: row.ID}, auth.ActOrgUpdate) == nil
	out := orgToAPI(row, isAdmin)
	// Members see the seats; the public profile does not.
	if auth.Check(p, auth.Resource{OrgID: row.ID}, auth.ActOrgMembersRead) == nil {
		out = s.withSeats(r, out, row.ID)
	}
	writeJSON(w, http.StatusOK, out)
}

// UpdateOrg implements PATCH /orgs/{org} (admin+).
func (s *Server) UpdateOrg(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	row, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, row.ID) {
		return
	}
	var req UpdateOrgJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	if req.DisplayName == nil && req.SsoRequired == nil {
		problemValidation(w, r, "Send at least one of displayName or ssoRequired.")
		return
	}
	name := ""
	if req.DisplayName != nil {
		name = strings.TrimSpace(*req.DisplayName)
		if name == "" || len(name) > 120 {
			problemValidation(w, r, "Set displayName to 1-120 characters.")
			return
		}
	}
	// Toggling enforced SSO is an SSO setting: the settings
	// action, declared apart from the update so the two can diverge again.
	if req.SsoRequired != nil {
		p := principalFrom(r.Context())
		if auth.Check(p, auth.Resource{OrgID: row.ID}, auth.ActOrgSettingsManage) != nil {
			problemForbidden(w, r, "Only an admin can change ssoRequired.")
			return
		}
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if req.DisplayName != nil {
			if _, err := q.UpdateOrgDisplayName(r.Context(), storegen.UpdateOrgDisplayNameParams{ID: row.ID, DisplayName: name}); err != nil {
				return err
			}
		}
		if req.SsoRequired != nil {
			if err := q.SetOrgSSORequired(r.Context(), storegen.SetOrgSSORequiredParams{ID: row.ID, SsoRequired: *req.SsoRequired}); err != nil {
				return err
			}
		}
		e := auditEvent(r, audit.ActionOrgUpdate)
		e.OrgID = row.ID
		e.TargetKind, e.TargetID = "org", row.ID
		if req.SsoRequired != nil {
			e.Detail = map[string]any{"sso_required": *req.SsoRequired}
		}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "update org", "err", err)
		problemInternal(w, r)
		return
	}
	updated, err := s.q().GetOrgByHandle(r.Context(), org)
	if err != nil {
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, orgToAPI(updated, true))
}

// ListOrgMembers implements GET /orgs/{org}/members (member+).
func (s *Server) ListOrgMembers(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	row, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgMembersRead, row.ID) {
		return
	}
	rows, err := s.q().ListOrgMembers(r.Context(), row.ID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "list members", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]Membership, 0, len(rows))
	for _, m := range rows {
		via, viaDomain, state := m.ViaScim, m.ViaDomain, MembershipState(m.State)
		out = append(out, Membership{
			User: PublicUser{Handle: m.Handle, DisplayName: m.DisplayName},
			Role: OrgRole(m.Role), ViaScim: &via, ViaDomain: &viaDomain, State: &state,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// reEmail is the address grammar an invitation accepts: the registry's own
// sign-up rule (an @, a bounded length), not a parser of RFC 5322.
var reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$`)

// requireSessionCaller refuses a token where only a browser session will
// do, and reports whether the caller may proceed. Accepting an invitation
// is such an act: it is a person answering an offer made to their address,
// not something an automation holds authority to do.
func (s *Server) requireSessionCaller(w http.ResponseWriter, r *http.Request) bool {
	p := principalFrom(r.Context())
	if p == nil || p.Anonymous {
		problemUnauthorized(w, r, "Sign in to answer an invitation.")
		return false
	}
	if p.Via != "session" {
		problemForbidden(w, r, "Answering an invitation requires a session, not a token.")
		return false
	}
	return true
}

// assignableOrgRole validates a role an admin is assigning and reports
// whether it may be. security_reviewer exists only inside a first-party
// organization; the retired owner is refused by name.
func (s *Server) assignableOrgRole(w http.ResponseWriter, r *http.Request, org storegen.GetOrgByHandleRow, role auth.OrgRole) bool {
	switch role {
	case auth.RoleAdmin, auth.RoleMember:
		return true
	case auth.RoleSecurityReviewer:
		if firstPartyOrg(org.Handle) {
			return true
		}
		problemValidation(w, r, "The security_reviewer role exists only in a first-party organization; in "+org.Handle+" its powers belong to the admins.")
		return false
	}
	roles := "admin or member"
	if firstPartyOrg(org.Handle) {
		roles = "admin, member or security_reviewer"
	}
	problemValidation(w, r, "Set role to "+roles+".")
	return false
}

// seatRefusal turns the membership chokepoint's refusals into problems and
// reports whether it wrote one. A seat refusal carries the counts; an
// entitlement that could not be resolved is not permission and is not one
// of these — it reaches the caller as a 500 with nothing written.
func (s *Server) seatRefusal(w http.ResponseWriter, r *http.Request, org storegen.GetOrgByHandleRow, err error) bool {
	switch {
	case errors.Is(err, registry.ErrSeatAllowance):
		var counts *registry.Seats
		if seats, serr := s.reg.Seats(r.Context(), org.ID); serr == nil {
			counts = &seats
		} else {
			s.log.ErrorContext(r.Context(), "seats", "org", org.ID, "err", serr)
		}
		problemSeatAllowance(w, r, org.Handle, counts)
		return true
	case errors.Is(err, registry.ErrSeatsNotOffered):
		problemFeatureNotIncluded(w, r, "The "+org.Handle+" organization's subscription includes no seats. Start or restore its subscription, then invite people.")
		return true
	case errors.Is(err, registry.ErrAlreadyAMember):
		problemAlreadyAMember(w, r, alreadyAMemberDetail)
		return true
	case s.staffOrgProblem(w, r, org.Handle, err):
		return true
	case s.orgGateProblem(w, r, org.Handle, err):
		return true
	}
	return false
}

// memberChangeAction picks the action for a role change: touching
// the admin role (either direction) is an elevation. Both actions need an
// admin; they stay distinct so
// the declaration says which is which.
func memberChangeAction(current, requested auth.OrgRole) auth.Action {
	if current == auth.RoleAdmin || requested == auth.RoleAdmin {
		return auth.ActOrgMembersElevate
	}
	return auth.ActOrgMembersManage
}

// errLastAdmin is what a membership transaction returns when the change
// would leave the organization with no admin who can act.
var errLastAdmin = errors.New("api: the organization's last admin")

// guardLastAdmin runs inside a transaction that removes or demotes a
// membership: it locks the organization's row, so two
// such changes serialise and the second counts what the first committed,
// then refuses with errLastAdmin when the membership is that of the last
// admin whose account is active. Erased accounts keep their membership rows
// and do not count. A user who is not a member, or not an admin, passes.
func guardLastAdmin(ctx context.Context, q *storegen.Queries, orgID, userID uuid.UUID) error {
	if err := q.LockOrg(ctx, orgID); err != nil {
		return err
	}
	m, err := q.GetMembership(ctx, storegen.GetMembershipParams{OrgID: orgID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if auth.OrgRole(m.Role) != auth.RoleAdmin {
		return nil
	}
	n, err := q.CountOrgAdmins(ctx, orgID)
	if err != nil {
		return err
	}
	if n <= 1 {
		return errLastAdmin
	}
	return nil
}

// SetOrgMember implements PUT /orgs/{org}/members/{handle}.
func (s *Server) SetOrgMember(w http.ResponseWriter, r *http.Request, org OrgHandle, handle Handle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	// Baseline gate before resolving targets (the precise manage-vs-elevate
	// check runs again below once the roles involved are known).
	if !s.authorize(w, r, auth.ActOrgMembersManage, orgRow.ID) {
		return
	}
	target, ok := s.userOrNotFound(w, r, handle)
	if !ok {
		return
	}
	var req SetOrgMemberJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	requested := auth.OrgRole(req.Role)
	if !s.assignableOrgRole(w, r, orgRow, requested) {
		return
	}

	current := auth.RoleNone
	state := ""
	viaScim, viaDomain := false, false
	if m, err := s.q().GetMembership(r.Context(), storegen.GetMembershipParams{OrgID: orgRow.ID, UserID: target.ID}); err == nil {
		current, state = auth.OrgRole(m.Role), m.State
		viaScim, viaDomain = m.ViaScim, m.ViaDomain
	}
	// The precise gate first, so that whether a handle is a member of this
	// organization is not something an unauthorized caller learns from
	// which refusal they get.
	if !s.authorize(w, r, memberChangeAction(current, requested), orgRow.ID) {
		return
	}
	// An organization is joined by accepting an invitation or by an admin
	// approving a pending member, and both go through the seat chokepoint.
	// This route only changes the role of someone who
	// is already here.
	if current == auth.RoleNone {
		problemValidation(w, r,
			"Nobody joins an organization by being added. Invite "+target.Handle+" by email (POST /orgs/"+orgRow.Handle+"/invitations), or approve them if they are waiting.")
		return
	}
	// A pending member's role is set by approving them, where the seat
	// check fires; changing it here would let an admin skip that.
	if state == "pending" {
		problemValidation(w, r,
			target.Handle+" is waiting for approval in "+orgRow.Handle+". Approve them with the role you want (POST /orgs/"+orgRow.Handle+"/members/"+target.Handle+"/approve).")
		return
	}

	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if requested != auth.RoleAdmin {
			if err := guardLastAdmin(r.Context(), q, orgRow.ID, target.ID); err != nil {
				return err
			}
		}
		if _, err := q.UpsertMembership(r.Context(), storegen.UpsertMembershipParams{
			OrgID: orgRow.ID, UserID: target.ID, Role: string(requested),
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionOrgMemberSet)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "user", target.ID
		e.Detail = map[string]any{"role": string(requested), "previous": string(current)}
		if err := s.auditW.Write(r.Context(), q, e); err != nil {
			return err
		}
		// Any active role in the staff organization is staff; the sync
		// runs at every membership change all the same.
		return s.syncStaffIn(r.Context(), q, target.ID, registry.StaffSyncMembership, auditEvent(r, audit.ActionUserStaffSync))
	})
	if errors.Is(err, errLastAdmin) {
		problemLastAdmin(w, r, orgRow.Handle)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "set member", "err", err)
		problemInternal(w, r)
		return
	}
	activeState := MembershipState("active")
	writeJSON(w, http.StatusOK, Membership{
		User: PublicUser{Handle: target.Handle, DisplayName: target.DisplayName},
		Role: OrgRole(requested), ViaScim: &viaScim, ViaDomain: &viaDomain, State: &activeState,
	})
}

// ApproveOrgMember implements POST /orgs/{org}/members/{handle}/approve
// (admin). This is where the seat check bites for the provisioning and fold-in
// doors: a person the IdP provisioned holds no seat until an admin says so.
func (s *Server) ApproveOrgMember(w http.ResponseWriter, r *http.Request, org OrgHandle, handle Handle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgMembersManage, orgRow.ID) {
		return
	}
	target, ok := s.userOrNotFound(w, r, handle)
	if !ok {
		return
	}
	m, err := s.q().GetMembership(r.Context(), storegen.GetMembershipParams{OrgID: orgRow.ID, UserID: target.ID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemNotFound(w, r)
			return
		}
		problemInternal(w, r)
		return
	}
	role := auth.OrgRole(m.Role)
	var body ApproveOrgMemberJSONBody
	if r.ContentLength > 0 {
		if !readJSON(w, r, &body) {
			return
		}
		if body.Role != nil {
			role = auth.OrgRole(*body.Role)
		}
	}
	if !s.assignableOrgRole(w, r, orgRow, role) {
		return
	}
	// Granting admin is an elevation whichever door it comes through.
	if !s.authorize(w, r, memberChangeAction(auth.OrgRole(m.Role), role), orgRow.ID) {
		return
	}
	if m.State == "active" {
		problemConflict(w, r, target.Handle+" is already a member of "+orgRow.Handle+".")
		return
	}

	if _, err := s.reg.ActivateMember(r.Context(), registry.ActivateMemberRequest{
		OrgID: orgRow.ID, UserID: target.ID, Role: role, Via: registry.ViaApproval,
		Actor: auditEvent(r, audit.ActionOrgMemberSet),
	}); err != nil {
		if s.seatRefusal(w, r, orgRow, err) {
			return
		}
		s.log.ErrorContext(r.Context(), "approve member", "err", err)
		problemInternal(w, r)
		return
	}
	via, viaDomain, state := m.ViaScim, m.ViaDomain, MembershipState("active")
	writeJSON(w, http.StatusOK, Membership{
		User: PublicUser{Handle: target.Handle, DisplayName: target.DisplayName},
		Role: OrgRole(role), ViaScim: &via, ViaDomain: &viaDomain, State: &state,
	})
}

// DeclineOrgMember implements POST /orgs/{org}/members/{handle}/decline
// (admin): the pending membership is removed and no seat was ever taken.
// An active member is removed with DELETE, which the last-admin guard
// covers; a pending member can never be the last admin, since a pending
// admin holds nothing.
func (s *Server) DeclineOrgMember(w http.ResponseWriter, r *http.Request, org OrgHandle, handle Handle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgMembersManage, orgRow.ID) {
		return
	}
	target, ok := s.userOrNotFound(w, r, handle)
	if !ok {
		return
	}
	m, err := s.q().GetMembership(r.Context(), storegen.GetMembershipParams{OrgID: orgRow.ID, UserID: target.ID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemNotFound(w, r)
			return
		}
		problemInternal(w, r)
		return
	}
	if m.State != "pending" {
		problemConflict(w, r, target.Handle+" is an active member of "+orgRow.Handle+"; remove them instead.")
		return
	}
	p := principalFrom(r.Context())
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.DeleteMembership(r.Context(), storegen.DeleteMembershipParams{OrgID: orgRow.ID, UserID: target.ID}); err != nil {
			return err
		}
		// The decline is remembered: the domain does
		// not fold this person in again; an admin's invitation supersedes
		// it. Whichever door they came through — declining someone the
		// IdP provisioned says the same thing about them.
		if err := q.UpsertFoldInDecline(r.Context(), storegen.UpsertFoldInDeclineParams{OrgID: orgRow.ID, UserID: target.ID, DeclinedBy: &p.UserID}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionOrgMemberDecline)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "user", target.ID
		e.Detail = map[string]any{"via": string(registry.DoorOf(m.ViaScim, m.ViaDomain))}
		if err := s.auditW.Write(r.Context(), q, e); err != nil {
			return err
		}
		// A pending member was never staff, but an approval can land
		// between the pending check above and this delete; the sync keeps
		// the flag true to the membership either way.
		return s.syncStaffIn(r.Context(), q, target.ID, registry.StaffSyncMembership, auditEvent(r, audit.ActionUserStaffSync))
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "decline member", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RemoveOrgMember implements DELETE /orgs/{org}/members/{handle}: an admin
// removes a member, or a member leaves. Leaving is any active member's
// own act: a person belongs to one organization at a time,
// so they must be able to end the membership they hold, and it
// deletes nothing of theirs. The last admin can do neither (409
// last-admin) — only a decommission removes them.
func (s *Server) RemoveOrgMember(w http.ResponseWriter, r *http.Request, org OrgHandle, handle Handle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	leaving := !p.Anonymous && strings.EqualFold(handle, p.Handle)
	// Baseline gate before resolving targets (elevation re-checked below).
	// Someone leaving needs only to be here, and may go during a hold.
	if leaving {
		if !s.authorize(w, r, auth.ActOrgLeave, orgRow.ID) {
			return
		}
	} else if !s.authorize(w, r, auth.ActOrgMembersManage, orgRow.ID) {
		return
	}
	target, ok := s.userOrNotFound(w, r, handle)
	if !ok {
		return
	}
	m, err := s.q().GetMembership(r.Context(), storegen.GetMembershipParams{OrgID: orgRow.ID, UserID: target.ID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemNotFound(w, r)
			return
		}
		problemInternal(w, r)
		return
	}
	current := auth.OrgRole(m.Role)
	if !leaving && !s.authorize(w, r, memberChangeAction(current, auth.RoleNone), orgRow.ID) {
		return
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := guardLastAdmin(r.Context(), q, orgRow.ID, target.ID); err != nil {
			return err
		}
		if _, err := q.DeleteMembership(r.Context(), storegen.DeleteMembershipParams{OrgID: orgRow.ID, UserID: target.ID}); err != nil {
			return err
		}
		// Enforced-SSO hygiene: org-bound PATs die with
		// the membership.
		if _, err := q.RevokeOrgBoundPATsForUser(r.Context(), storegen.RevokeOrgBoundPATsForUserParams{UserID: target.ID, OrgID: &orgRow.ID}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionOrgMemberRemove)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "user", target.ID
		e.Detail = map[string]any{"previous": string(current), "left": leaving}
		if err := s.auditW.Write(r.Context(), q, e); err != nil {
			return err
		}
		// Leaving or being removed from the staff organization ends staff
		// in the same transaction.
		return s.syncStaffIn(r.Context(), q, target.ID, registry.StaffSyncMembership, auditEvent(r, audit.ActionUserStaffSync))
	})
	if errors.Is(err, errLastAdmin) {
		problemLastAdmin(w, r, orgRow.Handle)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "remove member", "err", err)
		problemInternal(w, r)
		return
	}
	s.emitOrgEvent(r.Context(), orgRow.ID, webhook.EventMemberRemoved,
		map[string]any{"user": target.Handle, "left": leaving})
	w.WriteHeader(http.StatusNoContent)
}

// ListTeams implements GET /orgs/{org}/teams (member+).
func (s *Server) ListTeams(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgTeamsRead, orgRow.ID) {
		return
	}
	rows, err := s.q().ListTeams(r.Context(), orgRow.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]Team, 0, len(rows))
	for _, t := range rows {
		out = append(out, Team{Id: t.ID, Slug: t.Slug})
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateTeam implements POST /orgs/{org}/teams (admin+).
func (s *Server) CreateTeam(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgTeamsManage, orgRow.ID) {
		return
	}
	var req CreateTeamJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	if !reHandle.MatchString(req.Slug) {
		problemValidation(w, r, "A team slug is 1-39 lowercase letters, digits and hyphens, starting and ending with a letter or digit.")
		return
	}
	var created storegen.Team
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		t, err := q.CreateTeam(r.Context(), storegen.CreateTeamParams{ID: newUUID(), OrgID: orgRow.ID, Slug: req.Slug})
		if err != nil {
			return err
		}
		created = t
		e := auditEvent(r, audit.ActionTeamCreate)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "team", t.ID
		e.Detail = map[string]any{"slug": req.Slug}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		if isUniqueViolation(err) {
			problemConflict(w, r, "That team slug is already taken in this organization. Choose another.")
			return
		}
		s.log.ErrorContext(r.Context(), "create team", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, Team{Id: created.ID, Slug: created.Slug})
}

// DeleteTeam implements DELETE /orgs/{org}/teams/{team} (admin+).
func (s *Server) DeleteTeam(w http.ResponseWriter, r *http.Request, org OrgHandle, team TeamSlug) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgTeamsManage, orgRow.ID) {
		return
	}
	teamRow, err := s.q().GetTeam(r.Context(), storegen.GetTeamParams{OrgID: orgRow.ID, Slug: team})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.DeleteTeam(r.Context(), storegen.DeleteTeamParams{OrgID: orgRow.ID, Slug: team}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionTeamDelete)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "team", teamRow.ID
		e.Detail = map[string]any{"slug": team}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "delete team", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListTeamMembers implements GET /orgs/{org}/teams/{team}/members (member+).
func (s *Server) ListTeamMembers(w http.ResponseWriter, r *http.Request, org OrgHandle, team TeamSlug) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgTeamsRead, orgRow.ID) {
		return
	}
	teamRow, err := s.q().GetTeam(r.Context(), storegen.GetTeamParams{OrgID: orgRow.ID, Slug: team})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	rows, err := s.q().ListTeamMembers(r.Context(), teamRow.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]PublicUser, 0, len(rows))
	for _, m := range rows {
		out = append(out, PublicUser{Handle: m.Handle, DisplayName: m.DisplayName})
	}
	writeJSON(w, http.StatusOK, out)
}

// AddTeamMember implements PUT /orgs/{org}/teams/{team}/members/{handle}.
func (s *Server) AddTeamMember(w http.ResponseWriter, r *http.Request, org OrgHandle, team TeamSlug, handle Handle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgTeamsManage, orgRow.ID) {
		return
	}
	teamRow, err := s.q().GetTeam(r.Context(), storegen.GetTeamParams{OrgID: orgRow.ID, Slug: team})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	target, ok := s.userOrNotFound(w, r, handle)
	if !ok {
		return
	}
	// Team membership requires org membership.
	if _, err := s.q().GetMembership(r.Context(), storegen.GetMembershipParams{OrgID: orgRow.ID, UserID: target.ID}); err != nil {
		problemValidation(w, r, "Add this user to the organization before adding them to a team.")
		return
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.AddTeamMember(r.Context(), storegen.AddTeamMemberParams{TeamID: teamRow.ID, UserID: target.ID}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionTeamMemberAdd)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "user", target.ID
		e.Detail = map[string]any{"team": team}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "add team member", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RemoveTeamMember implements DELETE /orgs/{org}/teams/{team}/members/{handle}.
func (s *Server) RemoveTeamMember(w http.ResponseWriter, r *http.Request, org OrgHandle, team TeamSlug, handle Handle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgTeamsManage, orgRow.ID) {
		return
	}
	teamRow, err := s.q().GetTeam(r.Context(), storegen.GetTeamParams{OrgID: orgRow.ID, Slug: team})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	target, ok := s.userOrNotFound(w, r, handle)
	if !ok {
		return
	}
	var rows int64
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.RemoveTeamMember(r.Context(), storegen.RemoveTeamMemberParams{TeamID: teamRow.ID, UserID: target.ID})
		if err != nil {
			return err
		}
		rows = n
		if n == 0 {
			return nil
		}
		e := auditEvent(r, audit.ActionTeamMemberRemove)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "user", target.ID
		e.Detail = map[string]any{"team": team}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "remove team member", "err", err)
		problemInternal(w, r)
		return
	}
	if rows == 0 {
		problemNotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// orgFeatures answers what the organization's subscription includes. Every
// caller decides what an error means for its own act. Enforced SSO does not
// ask (enforceSSO says why): billing state does not loosen identity.
func (s *Server) orgFeatures(ctx context.Context, orgID uuid.UUID) (entitlements.Features, error) {
	return s.entitlements().Features(ctx, entitlements.ForOrg(orgID))
}
