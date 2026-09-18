package api

// Organization invitations (plan organization-subscriptions §4 "The doors",
// §5.2; D7, D12; agentry#361). Nobody joins an organization uninvited: an
// admin invites an address, the invitation reserves a seat from the moment
// it is sent, and the person accepts it from a session whose verified email
// is that address. The token is a credential — shown once at creation,
// stored only as its SHA-256, single use, seven days, bound to the address.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// invitationTTL is how long an invitation stands (plan §4: seven days).
const invitationTTL = 7 * 24 * time.Hour

// invitationToAPI renders a stored invitation.
func invitationToAPI(row storegen.OrgInvitation, invitedBy *string) Invitation {
	expired := row.ExpiresAt.Before(time.Now())
	inv := Invitation{
		Id: row.ID, Email: row.Email, Role: OrgRole(row.Role),
		ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt, Expired: &expired,
	}
	if invitedBy != nil && *invitedBy != "" {
		inv.InvitedBy = invitedBy
	}
	return inv
}

// ListInvitations implements GET /orgs/{org}/invitations (admin).
func (s *Server) ListInvitations(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgInvitationsManage, orgRow.ID) {
		return
	}
	rows, err := s.q().ListOpenInvitations(r.Context(), orgRow.ID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "list invitations", "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]Invitation, 0, len(rows))
	for _, row := range rows {
		out = append(out, invitationToAPI(storegen.OrgInvitation{
			ID: row.ID, OrgID: row.OrgID, Email: row.Email, Role: row.Role,
			ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
		}, row.InvitedByHandle))
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateInvitation implements POST /orgs/{org}/invitations (admin). The
// seat is reserved here, not at accept: the wall is met by the admin who
// invites, so an invitee is never turned away at the door.
func (s *Server) CreateInvitation(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgInvitationsManage, orgRow.ID) {
		return
	}
	var req CreateInvitationRequest
	if !readJSON(w, r, &req) {
		return
	}
	email := strings.TrimSpace(req.Email)
	if !reEmail.MatchString(email) {
		problemValidation(w, r, "Set email to the address to invite.")
		return
	}
	role := auth.RoleMember
	if req.Role != nil {
		role = auth.OrgRole(*req.Role)
	}
	if !s.assignableOrgRole(w, r, orgRow, role) {
		return
	}

	// Someone already in this organization is not invited again; someone
	// active in another organization cannot be (D26).
	if u, err := s.q().GetUserByEmail(r.Context(), email); err == nil {
		if m, err := s.q().GetMembership(r.Context(), storegen.GetMembershipParams{OrgID: orgRow.ID, UserID: u.ID}); err == nil && m.State == "active" {
			problemConflict(w, r, "That person is already a member of "+orgRow.Handle+".")
			return
		}
		n, err := s.q().CountActiveMembershipsElsewhere(r.Context(), storegen.CountActiveMembershipsElsewhereParams{UserID: u.ID, OrgID: orgRow.ID})
		if err != nil {
			problemInternal(w, r)
			return
		}
		if n > 0 {
			problemAlreadyAMember(w, r)
			return
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.log.ErrorContext(r.Context(), "invite: user lookup", "err", err)
		problemInternal(w, r)
		return
	}

	token, err := auth.NewToken(auth.InvitePrefix)
	if err != nil {
		problemInternal(w, r)
		return
	}
	p := principalFrom(r.Context())
	var row storegen.OrgInvitation
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		// The seat count and the insert are one transaction under the
		// organization's row lock, so two admins inviting at once cannot
		// both take the last seat.
		if err := q.LockOrg(r.Context(), orgRow.ID); err != nil {
			return err
		}
		if err := s.reg.CheckSeatAllowanceIn(r.Context(), q, orgRow.ID); err != nil {
			return err
		}
		// Re-inviting supersedes the standing invitation: its token stops
		// working and its seat is released to this one.
		if _, err := q.DeleteUnacceptedInvitationsFor(r.Context(), storegen.DeleteUnacceptedInvitationsForParams{OrgID: orgRow.ID, Email: email}); err != nil {
			return err
		}
		created, err := q.CreateInvitation(r.Context(), storegen.CreateInvitationParams{
			ID: newUUID(), OrgID: orgRow.ID, Email: email, Role: string(role),
			TokenSha256: auth.HashToken(token), InvitedBy: &p.UserID,
			ExpiresAt: time.Now().Add(invitationTTL),
		})
		if err != nil {
			return err
		}
		row = created
		e := auditEvent(r, audit.ActionOrgInviteCreate)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "invitation", created.ID
		// The address is the subject of the act, so it is recorded; the
		// token never is.
		e.Detail = map[string]any{"email": email, "role": string(role)}
		return s.auditW.Write(r.Context(), q, e)
	})
	if s.seatRefusal(w, r, orgRow, err) {
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "create invitation", "err", err)
		problemInternal(w, r)
		return
	}

	acceptURL := s.paths.invitationURL(token)
	mailed := s.mailInvitation(r, orgRow, row, acceptURL, p.Handle)
	out := CreatedInvitation{
		AcceptUrl: acceptURL, CreatedAt: row.CreatedAt, Email: row.Email,
		ExpiresAt: row.ExpiresAt, Id: row.ID, Role: OrgRole(row.Role),
		Token: token, Mailed: mailed,
	}
	writeJSON(w, http.StatusCreated, out)
}

// mailInvitation sends the offer and reports whether it went. The registry
// mails no address it has not verified (DEV-099), and an invitation is a
// mail like any other: an address that belongs to no account, or to one
// whose address was never confirmed, is not written to — the admin has the
// link and conveys it. That is the trade DEV-099 made deliberately, and an
// invitation is the case where it costs the most, so the response says
// plainly whether the mail went.
func (s *Server) mailInvitation(r *http.Request, org storegen.GetOrgByHandleRow, inv storegen.OrgInvitation, acceptURL, invitedBy string) bool {
	if s.notifier == nil {
		return false
	}
	u, err := s.q().GetUserByEmail(r.Context(), inv.Email)
	if err != nil {
		return false
	}
	if !notify.AllowsEmail(r.Context(), s.q(), s.log, u.ID, notify.KindOrgInvite) {
		return false
	}
	if err := s.notifier.OrgInvite(r.Context(), notify.InviteOffer{
		ToEmail: inv.Email, Org: org.Handle, OrgDisplayName: org.DisplayName,
		Role: inv.Role, InvitedBy: invitedBy, AcceptURL: acceptURL, ExpiresAt: inv.ExpiresAt,
	}); err != nil {
		s.log.ErrorContext(r.Context(), "invitation mail", "org", org.ID, "err", err)
		return false
	}
	return true
}

// RevokeInvitation implements DELETE /orgs/{org}/invitations/{id} (admin).
func (s *Server) RevokeInvitation(w http.ResponseWriter, r *http.Request, org OrgHandle, id openapi_types.UUID) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgInvitationsManage, orgRow.ID) {
		return
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.DeleteInvitation(r.Context(), storegen.DeleteInvitationParams{OrgID: orgRow.ID, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return pgx.ErrNoRows
		}
		e := auditEvent(r, audit.ActionOrgInviteRevoke)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "invitation", id
		return s.auditW.Write(r.Context(), q, e)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		problemNotFound(w, r)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "revoke invitation", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// invitationForToken resolves a token to its invitation, or writes the
// problem. A token nobody holds and an expired one are both 404: a caller
// guessing tokens learns nothing from the difference.
func (s *Server) invitationForToken(w http.ResponseWriter, r *http.Request, token string) (storegen.GetInvitationByTokenRow, bool) {
	row, err := s.q().GetInvitationByToken(r.Context(), auth.HashToken(token))
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.log.ErrorContext(r.Context(), "invitation lookup", "err", err)
			problemInternal(w, r)
			return row, false
		}
		problemNotFound(w, r)
		return row, false
	}
	if row.AcceptedAt != nil || row.ExpiresAt.Before(time.Now()) {
		problemNotFound(w, r)
		return row, false
	}
	return row, true
}

// invitationAcceptable reports whether the signed-in caller may accept this
// invitation, and why not when they may not. Accepting is bound to the
// address: the session's email must be the invited one and must be
// verified, so an invitation cannot be redeemed by whoever happens to hold
// the link.
func (s *Server) invitationAcceptable(r *http.Request, row storegen.GetInvitationByTokenRow) (bool, string) {
	p := principalFrom(r.Context())
	u, err := s.q().GetUserByID(r.Context(), p.UserID)
	if err != nil {
		return false, "This account could not be read."
	}
	if u.EmailVerifiedAt == nil {
		return false, "Verify this account's email address before accepting an invitation."
	}
	if !strings.EqualFold(strings.TrimSpace(u.Email), strings.TrimSpace(row.Email)) {
		return false, "This invitation was sent to " + row.Email + ". Sign in as that account to accept it."
	}
	return true, ""
}

// GetInvitation implements GET /invitations/{token} (session only).
func (s *Server) GetInvitation(w http.ResponseWriter, r *http.Request, token string) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireSessionCaller(w, r) {
		return
	}
	row, ok := s.invitationForToken(w, r, token)
	if !ok {
		return
	}
	acceptable, reason := s.invitationAcceptable(r, row)
	out := InvitationOffer{
		Org: row.OrgHandle, OrgDisplayName: row.OrgDisplayName, Email: row.Email,
		Role: OrgRole(row.Role), ExpiresAt: row.ExpiresAt, Acceptable: acceptable,
	}
	if reason != "" {
		out.Reason = &reason
	}
	writeJSON(w, http.StatusOK, out)
}

// AcceptInvitation implements POST /invitations/{token} (session only).
func (s *Server) AcceptInvitation(w http.ResponseWriter, r *http.Request, token string) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireSessionCaller(w, r) {
		return
	}
	row, ok := s.invitationForToken(w, r, token)
	if !ok {
		return
	}
	if acceptable, reason := s.invitationAcceptable(r, row); !acceptable {
		problemForbidden(w, r, reason)
		return
	}
	p := principalFrom(r.Context())
	orgRow, err := s.q().GetOrgByID(r.Context(), row.OrgID)
	if err != nil {
		problemInternal(w, r)
		return
	}

	// Single use: the invitation is spent in the same transaction the
	// membership is written in, so a token cannot be redeemed twice even
	// if two requests arrive together.
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.MarkInvitationAccepted(r.Context(), storegen.MarkInvitationAcceptedParams{
			ID: row.ID, OrgID: row.OrgID, AcceptedBy: &p.UserID,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return pgx.ErrNoRows
		}
		e := auditEvent(r, audit.ActionOrgInviteAccept)
		e.OrgID = row.OrgID
		e.TargetKind, e.TargetID = "invitation", row.ID
		return s.auditW.Write(r.Context(), q, e)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		problemNotFound(w, r)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "accept invitation", "err", err)
		problemInternal(w, r)
		return
	}

	if _, err := s.reg.ActivateMember(r.Context(), row.OrgID, p.UserID, auth.OrgRole(row.Role),
		registry.ViaInvitation, auditEvent(r, audit.ActionOrgMemberSet)); err != nil {
		if s.seatRefusal(w, r, storegen.GetOrgByHandleRow{ID: orgRow.ID, Handle: orgRow.Handle}, err) {
			return
		}
		s.log.ErrorContext(r.Context(), "accept invitation: activate", "err", err)
		problemInternal(w, r)
		return
	}
	u, _ := s.q().GetUserByID(r.Context(), p.UserID)
	state := MembershipState("active")
	via := false
	writeJSON(w, http.StatusOK, Membership{
		User: PublicUser{Handle: p.Handle, DisplayName: u.DisplayName},
		Role: OrgRole(row.Role), ViaScim: &via, State: &state,
	})
}
