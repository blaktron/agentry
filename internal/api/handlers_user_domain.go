package api

// The organization at a person's email domain (agentry#363, plan
// organization-subscriptions §4 "The sign-up and the org's domain"; D13,
// D21): a signed-in person can ask which organization their verified
// address's domain belongs to, and mail its administrators a request to be
// added. Nobody joins uninvited (D7), so the request is a request — the
// admins invite, or do not.

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/maildomains"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// accessRequestWindow is how often one person may ask one organization.
const accessRequestWindow = 24 * time.Hour

// errAskedToday is what the request's transaction returns when the person
// already asked within the window.
var errAskedToday = errors.New("api: access already requested today")

// GetDomainOrg implements GET /user/domain-org.
func (s *Server) GetDomainOrg(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if !p.EmailVerified {
		problemEmailUnverified(w, r, "Verify this account's email address to find the organization at its domain.")
		return
	}
	u, err := s.q().GetUserByID(r.Context(), p.UserID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "domain org: caller", "err", err)
		problemInternal(w, r)
		return
	}
	domain := maildomains.Of(u.Email)
	out := DomainOrg{Domain: domain}
	if maildomains.Shared(domain) {
		out.Domain = ""
		writeJSON(w, http.StatusOK, out)
		return
	}
	org, err := s.q().GetOrgByDomain(r.Context(), domain)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		writeJSON(w, http.StatusOK, out)
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "domain org", "err", err)
		problemInternal(w, r)
		return
	}
	// A suspended or erased organization is absent to everyone; it still
	// holds the domain, but there is nobody there to ask.
	if org.State != registry.OrgStateActive && org.State != registry.OrgStateDecommissioning {
		writeJSON(w, http.StatusOK, out)
		return
	}
	out.Org = &struct {
		DisplayName string `json:"displayName"`
		Handle      string `json:"handle"`
	}{DisplayName: org.DisplayName, Handle: org.Handle}
	// The two facts beside the organization are left off when they cannot
	// be read — the answer is the organization — and the failure is logged.
	switch _, err := s.q().GetMembership(r.Context(), storegen.GetMembershipParams{OrgID: org.ID, UserID: p.UserID}); {
	case err == nil:
		member := true
		out.Member = &member
	case !errors.Is(err, pgx.ErrNoRows):
		s.log.ErrorContext(r.Context(), "domain org: membership", "err", err)
	}
	n, err := s.q().CountAuditActionsByActorSince(r.Context(), storegen.CountAuditActionsByActorSinceParams{
		ActorID: &p.UserID, Action: string(audit.ActionOrgAccessRequest), OccurredAt: time.Now().Add(-accessRequestWindow),
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "domain org: requests", "err", err)
	} else {
		requested := n > 0
		out.RequestedToday = &requested
	}
	writeJSON(w, http.StatusOK, out)
}

// RequestDomainOrgAccess implements POST /user/domain-org/request-access
// (session only). The audit row is the record and the rate limit: one
// request per person per day, whatever the mail did.
func (s *Server) RequestDomainOrgAccess(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserOrgRequest, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if !p.EmailVerified {
		problemEmailUnverified(w, r, "Verify this account's email address before asking an organization for access.")
		return
	}
	u, err := s.q().GetUserByID(r.Context(), p.UserID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "access request: caller", "err", err)
		problemInternal(w, r)
		return
	}
	domain := maildomains.Of(u.Email)
	if maildomains.Shared(domain) {
		problemNotFound(w, r)
		return
	}
	org, err := s.q().GetOrgByDomain(r.Context(), domain)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		problemNotFound(w, r)
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "domain org", "err", err)
		problemInternal(w, r)
		return
	}
	if err := s.reg.OrgGate(r.Context(), org.ID, auth.ActOrgMembersManage); err != nil {
		if !s.orgGateProblem(w, r, org.Handle, err) {
			problemInternal(w, r)
		}
		return
	}
	if m, err := s.q().GetMembership(r.Context(), storegen.GetMembershipParams{OrgID: org.ID, UserID: p.UserID}); err == nil {
		if m.State == registry.StateActive {
			problemConflict(w, r, "You are already a member of "+org.Handle+".")
		} else {
			problemConflict(w, r, "You are already waiting for an admin of "+org.Handle+" to approve you.")
		}
		return
	}
	// The count and the record commit together under the person's advisory
	// lock, so two requests at once cannot both pass the once-a-day rule.
	since := time.Now().Add(-accessRequestWindow)
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.LockKey(r.Context(), "access-request:"+p.UserID.String()); err != nil {
			return err
		}
		n, err := q.CountAuditActionsByActorSince(r.Context(), storegen.CountAuditActionsByActorSinceParams{
			ActorID: &p.UserID, Action: string(audit.ActionOrgAccessRequest), OccurredAt: since,
		})
		if err != nil {
			return err
		}
		if n > 0 {
			return errAskedToday
		}
		e := auditEvent(r, audit.ActionOrgAccessRequest)
		e.OrgID = org.ID
		e.TargetKind, e.TargetID = "org", org.ID
		e.Detail = map[string]any{"domain": domain, "org": org.Handle}
		return s.auditW.Write(r.Context(), q, e)
	})
	if errors.Is(err, errAskedToday) {
		problemTooMany(w, r, "You asked the administrators of "+org.Handle+" for access in the last day. Ask again tomorrow.")
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "access request", "err", err)
		problemInternal(w, r)
		return
	}
	mailed := s.mailAccessRequest(r, org, u.Handle, u.Email)
	writeJSON(w, http.StatusAccepted, AccessRequestResult{Org: org.Handle, MailedAdmins: mailed})
}

// mailAccessRequest writes to each of the organization's active admins
// that notify.AllowsEmail admits — a verified address (DEV-099) and the
// orgInvites preference, since the request is the invitation flow seen
// from the admin's side. Reports how many went.
func (s *Server) mailAccessRequest(r *http.Request, org storegen.GetOrgByDomainRow, requester, requesterEmail string) int {
	if s.notifier == nil {
		return 0
	}
	mailed := 0
	s.forEachMailableAdmin(r.Context(), s.q(), org.ID, func(email string) {
		if err := s.notifier.OrgAccessRequest(r.Context(), notify.AccessRequestNotice{
			ToEmail: email, Org: org.Handle, OrgDisplayName: org.DisplayName,
			Requester: requester, RequesterEmail: requesterEmail,
			ConsoleURL: s.paths.orgConsoleURL(org.Handle),
		}); err != nil {
			s.log.ErrorContext(r.Context(), "access request mail", "org", org.ID, "err", err)
			return
		}
		mailed++
	})
	return mailed
}
