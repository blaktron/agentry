package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/dnsx"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

func domainClaimToAPI(row storegen.DomainClaim) DomainClaim {
	recordName := dnsx.TXTName(row.Domain)
	recordValue := "agentry-domain-verification=" + row.VerificationToken
	dc := DomainClaim{
		Domain: row.Domain, VerificationToken: row.VerificationToken,
		RecordName: &recordName, RecordValue: &recordValue,
		Verified: row.VerifiedAt != nil,
	}
	if row.VerifiedAt != nil {
		dc.VerifiedAt = row.VerifiedAt
	}
	return dc
}

// ListDomainClaims implements GET /orgs/{org}/domain-claims (admin+, §12.4).
func (s *Server) ListDomainClaims(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	rows, err := s.q().ListDomainClaims(r.Context(), orgRow.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]DomainClaim, 0, len(rows))
	for _, row := range rows {
		out = append(out, domainClaimToAPI(row))
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateDomainClaim implements POST /orgs/{org}/domain-claims (admin+, §12.4).
func (s *Server) CreateDomainClaim(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	var req CreateDomainClaimJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	domain := normalizeDomain(req.Domain)
	if !validDomain(domain) {
		problemValidation(w, r, "A domain must contain a dot, use only letters, digits and hyphens, and be at most 253 characters.")
		return
	}
	token, err := auth.NewToken("")
	if err != nil {
		problemInternal(w, r)
		return
	}
	var created storegen.DomainClaim
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		row, err := q.CreateDomainClaim(r.Context(), storegen.CreateDomainClaimParams{
			ID: newUUID(), OrgID: orgRow.ID, Domain: domain, VerificationToken: token,
		})
		if err != nil {
			return err
		}
		created = row
		e := auditEvent(r, audit.ActionDomainClaim)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "domain_claim", row.ID
		e.Detail = map[string]any{"domain": domain}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "create domain claim", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, domainClaimToAPI(created))
}

// VerifyDomainClaim implements POST /orgs/{org}/domain-claims/verify: it looks
// up the DNS TXT record via the injected resolver and, on success, marks the
// claim verified (the T-12 auto-link basis, §12.4). A domain belongs to one
// organization (agentry#363, D21, D26): one that another organization was
// created at, or has verified, is 409 domain-claimed here too.
func (s *Server) VerifyDomainClaim(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	var req VerifyDomainClaimJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	domain := normalizeDomain(req.Domain)
	claim, err := s.q().GetDomainClaim(r.Context(), storegen.GetDomainClaimParams{OrgID: orgRow.ID, Domain: domain})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	verified, err := dnsx.VerifyTXT(r.Context(), s.resolver, claim.Domain, claim.VerificationToken)
	if err != nil {
		s.log.WarnContext(r.Context(), "domain verify lookup", "domain", domain, "err", err)
		problemValidation(w, r, "The registry could not read the TXT record for this domain: "+err.Error())
		return
	}
	if !verified {
		out := domainClaimToAPI(claim)
		out.Verified = false
		writeJSON(w, http.StatusOK, out)
		return
	}
	if s.domainClaimed(w, r, domain, orgRow.ID) {
		return
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		// Under the domain's advisory lock, checked again: a creation at
		// this domain racing this verification cannot both commit.
		if err := q.LockKey(r.Context(), domainLockKey(domain)); err != nil {
			return err
		}
		if holder, err := q.GetOrgByDomain(r.Context(), domain); err == nil && holder.ID != orgRow.ID {
			return errDomainClaimed
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := q.MarkDomainClaimVerified(r.Context(), storegen.MarkDomainClaimVerifiedParams{OrgID: orgRow.ID, Domain: domain}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionDomainVerified)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "domain_claim", claim.ID
		e.Detail = map[string]any{"domain": domain}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		if errors.Is(err, errDomainClaimed) || uniqueViolationOn(err, "domain_claims_verified_domain_idx") {
			if !s.domainClaimed(w, r, domain, orgRow.ID) {
				problemDomainClaimed(w, r, domain, "another organization", "")
			}
			return
		}
		s.log.ErrorContext(r.Context(), "verify domain claim", "domain", domain, "err", err)
		problemInternal(w, r)
		return
	}
	refreshed, err := s.q().GetDomainClaim(r.Context(), storegen.GetDomainClaimParams{OrgID: orgRow.ID, Domain: domain})
	if err != nil {
		problemInternal(w, r)
		return
	}
	// A verified domain is the organization's like the one it was created
	// at: the accounts already known there are folded in (agentry#364).
	s.enqueueFoldInSweep(r.Context(), orgRow.ID, domain)
	writeJSON(w, http.StatusOK, domainClaimToAPI(refreshed))
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
}

// validDomain is a light structural check (a real registrable-domain check is
// out of scope; the DNS challenge is the actual proof of control).
func validDomain(d string) bool {
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, r := range d {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}
