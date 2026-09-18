package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/notify"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/webhook"
)

// lookupFailed writes the problem for a handle lookup that did not yield an
// active row, and reports whether it wrote one. A missing row is 404; a
// query error is 500, logged — never 404, because a client that takes 404 as
// "this handle is nobody's" (the site's namespace rule, agentry-web#35) must
// be able to mean it (agentry#261). The caller decides the inactive case.
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
// handle no active organisation holds, 500 for a lookup that failed.
func (s *Server) orgOrNotFound(w http.ResponseWriter, r *http.Request, handle string) (storegen.GetOrgByHandleRow, bool) {
	row, err := s.q().GetOrgByHandle(r.Context(), handle)
	if s.lookupFailed(w, r, "org", err) {
		return storegen.GetOrgByHandleRow{}, false
	}
	if row.State != "active" {
		problemNotFound(w, r)
		return storegen.GetOrgByHandleRow{}, false
	}
	return row, true
}

// notifyOrgInvite tells someone they were added to an organisation (§13.4).
// Best-effort: the membership is already committed, and a mail failure must
// not turn a successful grant into a 500 the admin would retry.
func (s *Server) notifyOrgInvite(ctx context.Context, org storegen.GetOrgByHandleRow, target storegen.GetUserByHandleRow, role, invitedBy string) {
	if s.notifier == nil || !notify.AllowsEmail(ctx, s.q(), s.log, target.ID, notify.KindOrgInvite) {
		return
	}
	if err := s.notifier.OrgInvite(ctx, notify.InviteNotice{
		ToEmail:   target.Email,
		Org:       org.Handle,
		Role:      role,
		InvitedBy: invitedBy,
	}); err != nil {
		s.log.ErrorContext(ctx, "org invite notification", "org", org.ID, "user", target.ID, "err", err)
	}
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
	if row.VerifiedDomain != nil {
		o.VerifiedDomain = row.VerifiedDomain
	}
	if includeSettings {
		sso := row.SsoRequired
		o.SsoRequired = &sso
	}
	return o
}

// CreateOrg implements POST /orgs; the caller becomes its first admin
// (§12.2, agentry#360). Two gates precede the handle rules. The account's
// email must be verified: an organization is keyed on its creator's domain
// (plan organization-subscriptions D13, D21 — the domain itself lands in
// M4). And the account may have at most one organization awaiting
// activation: on the hosted product an org is a paid thing that starts out
// awaiting payment, and the core refuses a second until the first is
// activated or gone (D5), so nobody squats handles behind organizations
// that never pay. Where nothing will activate an org later — no admission
// extension, so no payment — it is activated as it is created, and the
// rule never bites (§3: the core with no extension is unchanged).
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
	orgID := newUUID()
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.CreateHandle(r.Context(), storegen.CreateHandleParams{ID: orgID, Handle: req.Handle, Kind: "org"}); err != nil {
			return err
		}
		if _, err := q.CreateOrg(r.Context(), storegen.CreateOrgParams{
			ID: orgID, DisplayName: name, CreatedBy: &p.UserID, Activated: activated,
		}); err != nil {
			return err
		}
		if err := q.UpsertMembership(r.Context(), storegen.UpsertMembershipParams{
			OrgID: orgID, UserID: p.UserID, Role: string(auth.RoleAdmin),
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionOrgCreate)
		e.OrgID = orgID
		e.TargetKind, e.TargetID = "org", orgID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		if uniqueViolationOn(err, "orgs_pending_by_creator_idx") {
			problemOrgPending(w, r, "an organization")
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
	s.fireEvent(r.Context(), Event{Kind: "org.created", OrgID: out.Id, Payload: map[string]any{"org": out.Handle}})
	ik.complete(r, http.StatusCreated, out)
	writeJSON(w, http.StatusCreated, out)
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
	writeJSON(w, http.StatusOK, orgToAPI(row, isAdmin))
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
	// Toggling enforced SSO is an SSO setting (§12.2, §12.4): the settings
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
		via := m.ViaScim
		out = append(out, Membership{
			User: PublicUser{Handle: m.Handle, DisplayName: m.DisplayName},
			Role: OrgRole(m.Role), ViaScim: &via,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// memberChangeAction picks the §12.2 action for a role change: touching
// the admin role (either direction) is an elevation. Both actions need an
// admin since the owner role retired (agentry#360); they stay distinct so
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
// membership (agentry#360, D14): it locks the organization's row, so two
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
	switch requested {
	case auth.RoleAdmin, auth.RoleMember:
	case auth.RoleSecurityReviewer:
		// A platform-internal role: it exists only inside a first-party
		// organization (D20). Everywhere else the admins accept risk.
		if !firstPartyOrg(orgRow.Handle) {
			problemValidation(w, r, "The security_reviewer role exists only in a first-party organization; in "+orgRow.Handle+" its powers belong to the admins.")
			return
		}
	default:
		roles := "admin or member"
		if firstPartyOrg(orgRow.Handle) {
			roles = "admin, member or security_reviewer"
		}
		problemValidation(w, r, "Set role to "+roles+".")
		return
	}

	current := auth.RoleNone
	if m, err := s.q().GetMembership(r.Context(), storegen.GetMembershipParams{OrgID: orgRow.ID, UserID: target.ID}); err == nil {
		current = auth.OrgRole(m.Role)
	}
	if !s.authorize(w, r, memberChangeAction(current, requested), orgRow.ID) {
		return
	}

	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if requested != auth.RoleAdmin {
			if err := guardLastAdmin(r.Context(), q, orgRow.ID, target.ID); err != nil {
				return err
			}
		}
		if err := q.UpsertMembership(r.Context(), storegen.UpsertMembershipParams{
			OrgID: orgRow.ID, UserID: target.ID, Role: string(requested),
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionOrgMemberSet)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "user", target.ID
		e.Detail = map[string]any{"role": string(requested), "previous": string(current)}
		return s.auditW.Write(r.Context(), q, e)
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
	// Webhook fan-out (§9.3): a brand-new membership is a member.added event.
	if current == auth.RoleNone {
		s.emitOrgEvent(r.Context(), orgRow.ID, webhook.EventMemberAdded,
			map[string]any{"user": target.Handle, "role": string(requested)})
	}
	// §13.4 lists invites among the transactional mails. There is no separate
	// invite object in v1 — org membership is GRANTED by an admin, not offered
	// and accepted — so the notification belongs on the same transition the
	// member.added webhook fires on. Telling someone they were added to an org
	// they did not ask to join is also how they find out to object.
	if current == auth.RoleNone {
		s.notifyOrgInvite(r.Context(), orgRow, target, string(requested), principalFrom(r.Context()).Handle)
	}
	via := false
	writeJSON(w, http.StatusOK, Membership{
		User: PublicUser{Handle: target.Handle, DisplayName: target.DisplayName},
		Role: OrgRole(requested), ViaScim: &via,
	})
}

// RemoveOrgMember implements DELETE /orgs/{org}/members/{handle}.
func (s *Server) RemoveOrgMember(w http.ResponseWriter, r *http.Request, org OrgHandle, handle Handle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	// Baseline gate before resolving targets (elevation re-checked below).
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
	current := auth.OrgRole(m.Role)
	if !s.authorize(w, r, memberChangeAction(current, auth.RoleNone), orgRow.ID) {
		return
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := guardLastAdmin(r.Context(), q, orgRow.ID, target.ID); err != nil {
			return err
		}
		if _, err := q.DeleteMembership(r.Context(), storegen.DeleteMembershipParams{OrgID: orgRow.ID, UserID: target.ID}); err != nil {
			return err
		}
		// Enforced-SSO hygiene (§12.5 semantics): org-bound PATs die with
		// the membership.
		if _, err := q.RevokeOrgBoundPATsForUser(r.Context(), storegen.RevokeOrgBoundPATsForUserParams{UserID: target.ID, OrgID: &orgRow.ID}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionOrgMemberRemove)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "user", target.ID
		e.Detail = map[string]any{"previous": string(current)}
		return s.auditW.Write(r.Context(), q, e)
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
		map[string]any{"user": target.Handle})
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
	// Team membership requires org membership (§4.1 model).
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
