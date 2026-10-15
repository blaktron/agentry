package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Platform staff is membership of the staff organization (registry/staff.go
// holds the rule). These wrap the registry for handlers
// that may run without one wired.

// syncStaffIn recomputes userID's platform_staff inside the caller's
// transaction, the act's principal as the audit actor.
func (s *Server) syncStaffIn(ctx context.Context, q *storegen.Queries, userID uuid.UUID, reason string, actor audit.Event) error {
	if s.reg == nil {
		return nil
	}
	return s.reg.SyncStaffIn(ctx, q, userID, reason, actor)
}

// staffOrgDoorIn refuses userID at orgID's door when orgID is the staff
// organization and the account's verified address is outside its domain.
func (s *Server) staffOrgDoorIn(ctx context.Context, q *storegen.Queries, orgID, userID uuid.UUID) error {
	if s.reg == nil {
		return nil
	}
	return s.reg.CheckStaffOrgDoorIn(ctx, q, orgID, userID)
}

// staffOrgAddressIn is the same door for an address with no account yet
// (an invitation).
func (s *Server) staffOrgAddressIn(ctx context.Context, q *storegen.Queries, orgID uuid.UUID, email string) error {
	if s.reg == nil {
		return nil
	}
	return s.reg.CheckStaffOrgAddress(ctx, q, orgID, email)
}

// problemStaffOrgDomain is the staff organization's refusal of an address
// outside its domain: 409, because the request is well formed and the
// organization's rule is what stands in the way.
func problemStaffOrgDomain(w http.ResponseWriter, r *http.Request, orgHandle, domain string) {
	writeProblem(w, r, http.StatusConflict, "staff-org-domain", "Outside the staff organization's domain",
		"The "+orgHandle+" organization is this deployment's staff organization. It admits only accounts with a verified address at "+domain+", because its members are platform staff.")
}

// staffOrgProblem writes problemStaffOrgDomain for registry.ErrStaffOrgDomain
// and reports whether it did.
func (s *Server) staffOrgProblem(w http.ResponseWriter, r *http.Request, orgHandle string, err error) bool {
	if !errors.Is(err, registry.ErrStaffOrgDomain) {
		return false
	}
	problemStaffOrgDomain(w, r, orgHandle, s.cfg.Auth.StaffDomain)
	return true
}
