package api

// Organization invitations (plan organization-subscriptions §4 "The doors",
// §5.2; D7, D12; agentry#361). Nobody joins an organization uninvited: an
// admin invites an address, the invitation reserves a seat from the moment
// it is sent, and the person accepts it from a session whose verified email
// is that address. The token is a credential — shown once at creation,
// stored only as its SHA-256, single use, seven days, bound to the address.

import (
	"context"
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

// errInvitationSpent reports that the token was already used, from inside
// the transaction that tried to spend it.
var errInvitationSpent = errors.New("api: the invitation was already accepted")

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
	// Offering admin is an elevation, the same as granting it through any
	// other door: the invitation door does not become the cheap way in.
	if role == auth.RoleAdmin && !s.authorize(w, r, auth.ActOrgMembersElevate, orgRow.ID) {
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
		// Re-inviting supersedes the standing invitation: its token stops
		// working and its seat is released. That happens before the count,
		// so re-inviting the same address at the allowance is not refused
		// for a seat this very invitation is about to give back.
		if _, err := q.DeleteUnacceptedInvitationsFor(r.Context(), storegen.DeleteUnacceptedInvitationsForParams{OrgID: orgRow.ID, Email: email}); err != nil {
			return err
		}
		if err := s.reg.CheckSeatAllowanceIn(r.Context(), q, orgRow.ID); err != nil {
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

// atOrgDomain reports whether an address belongs to the organization's own
// verified domain — the one it proved control of with a DNS TXT record
// (handlers_domains.go). That proof is what lets an invitation to such an
// address be treated as an address the organization vouches for
// (operator decision, 2026-09-18): the organization holds the mail domain,
// so it holds the mailbox.
func atOrgDomain(org storegen.GetOrgByHandleRow, email string) bool {
	if org.VerifiedDomain == nil {
		return false
	}
	domain := strings.TrimSpace(*org.VerifiedDomain)
	if domain == "" {
		return false
	}
	at := strings.LastIndex(email, "@")
	return at >= 0 && strings.EqualFold(strings.TrimSpace(email[at+1:]), domain)
}

// mailInvitation sends the offer and reports whether it went.
//
// The registry mails no address it has not verified (DEV-099), which for
// an invitation would mean never writing to the very people an
// organization most needs to invite — colleagues with no account here yet.
// The organization's own verified domain is the way out (operator
// decision, 2026-09-18): an address at a domain the organization proved
// control of is one it vouches for, so the offer is mailed there whether
// or not an account holds it. Every other address keeps DEV-099's rule —
// a verified account, and its orgInvites preference — and the response
// says plainly whether the mail went, because when it did not the admin's
// copy of the link is the only one.
func (s *Server) mailInvitation(r *http.Request, org storegen.GetOrgByHandleRow, inv storegen.OrgInvitation, acceptURL, invitedBy string) bool {
	if s.notifier == nil {
		return false
	}
	ownDomain := atOrgDomain(org, inv.Email)
	u, err := s.q().GetUserByEmail(r.Context(), inv.Email)
	switch {
	case err == nil:
		// An account exists: its owner's preference is theirs to set, and
		// is honoured whichever domain the address is at. The verified-
		// address gate is what the organization's domain stands in for.
		prefs, perr := notify.Settings(r.Context(), s.q(), u.ID)
		if perr != nil {
			prefs = notify.Defaults(u.ID)
		}
		if !notify.EmailPermitted(true, prefs, notify.KindOrgInvite) {
			return false
		}
		if !ownDomain && !notify.AllowsEmail(r.Context(), s.q(), s.log, u.ID, notify.KindOrgInvite) {
			return false
		}
	case ownDomain:
		// Nobody holds the address yet, and it is the organization's own
		// domain: this is the invitation that brings them in.
	default:
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
// address: the session's email must be the invited one, so an invitation
// cannot be redeemed by whoever happens to hold the link.
//
// The address must also be one the registry trusts, which is either of two
// things: the account confirmed it, or the invitation is at a domain the
// organization proved it controls, in which case the organization's proof
// stands in for the account's (operator decision, 2026-09-18) and
// accepting confirms it.
func (s *Server) invitationAcceptable(r *http.Request, row storegen.GetInvitationByTokenRow) (bool, string) {
	p := principalFrom(r.Context())
	u, err := s.q().GetUserByID(r.Context(), p.UserID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "invitation: caller lookup", "user", p.UserID, "err", err)
		return false, "This account could not be read."
	}
	if !strings.EqualFold(strings.TrimSpace(u.Email), strings.TrimSpace(row.Email)) {
		return false, "This invitation was sent to " + row.Email + ". Sign in as that account to accept it."
	}
	if u.EmailVerifiedAt == nil && !invitationAtOrgDomain(row) {
		return false, "Verify this account's email address before accepting an invitation."
	}
	return true, ""
}

// invitationAtOrgDomain reports whether the invited address is at the
// organization's own verified domain.
func invitationAtOrgDomain(row storegen.GetInvitationByTokenRow) bool {
	return atOrgDomain(storegen.GetOrgByHandleRow{VerifiedDomain: row.VerifiedDomain}, row.Email)
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

	// The token is spent inside the activation's own transaction: single
	// use even when two requests arrive together, and — because the two
	// commit or roll back together — an activation the seat wall or the
	// one-organization rule refuses leaves the invitation standing rather
	// than spending it for nothing.
	spent := false
	activated, err := s.reg.ActivateMember(r.Context(), registry.ActivateMemberRequest{
		OrgID: row.OrgID, UserID: p.UserID, Role: auth.OrgRole(row.Role), Via: registry.ViaInvitation,
		Actor: auditEvent(r, audit.ActionOrgMemberSet),
		Spend: func(ctx context.Context, q *storegen.Queries) error {
			n, err := q.MarkInvitationAccepted(ctx, storegen.MarkInvitationAcceptedParams{
				ID: row.ID, OrgID: row.OrgID, AcceptedBy: &p.UserID,
			})
			if err != nil {
				return err
			}
			if n == 0 {
				return errInvitationSpent
			}
			spent = true
			e := auditEvent(r, audit.ActionOrgInviteAccept)
			e.OrgID = row.OrgID
			e.TargetKind, e.TargetID = "invitation", row.ID
			return s.auditW.Write(ctx, q, e)
		},
	})
	switch {
	case errors.Is(err, errInvitationSpent):
		problemNotFound(w, r)
		return
	case err != nil:
		if s.seatRefusal(w, r, storegen.GetOrgByHandleRow{ID: orgRow.ID, Handle: orgRow.Handle}, err) {
			return
		}
		s.log.ErrorContext(r.Context(), "accept invitation", "err", err)
		problemInternal(w, r)
		return
	}
	if !activated && !spent {
		// Already an active member of this organization, and the token was
		// not spent: nothing to do, and the invitation stays answerable.
		problemConflict(w, r, "You are already a member of "+orgRow.Handle+".")
		return
	}

	// The organization's own verified domain vouches for the address, so
	// accepting from it confirms the account's address (operator decision,
	// 2026-09-18). Best effort after the fact: the membership is what the
	// request was for, and a stamp that did not land is retried by the
	// ordinary verification mail.
	if invitationAtOrgDomain(row) {
		if err := s.q().MarkEmailVerified(r.Context(), p.UserID); err != nil {
			s.log.ErrorContext(r.Context(), "invitation: mark verified", "user", p.UserID, "err", err)
		}
	}

	u, _ := s.q().GetUserByID(r.Context(), p.UserID)
	state := MembershipState("active")
	via := false
	writeJSON(w, http.StatusOK, Membership{
		User: PublicUser{Handle: p.Handle, DisplayName: u.DisplayName},
		Role: OrgRole(row.Role), ViaScim: &via, State: &state,
	})
}
