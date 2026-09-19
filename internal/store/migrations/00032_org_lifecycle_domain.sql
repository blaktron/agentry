-- +goose Up
-- The organization's lifecycle and its domain (agentry#363, plan
-- organization-subscriptions §4 "The sign-up and the org's domain",
-- "Decommission", §5.4; D13, D14, D21, D23, D26).

-- The domain an organization was created at: the creator's verified email
-- domain, recorded by POST /orgs, or NULL when the creator asked for none
-- or the address is at a domain nobody owns (a public mail provider). A
-- domain belongs to at most one organization, which the unique constraint
-- holds under concurrent creations; the same rule across this column and
-- the DNS-verified claims below is the API's.
ALTER TABLE orgs ADD COLUMN domain citext UNIQUE;

-- The single verified_domain column is gone: verified DNS-TXT claims are
-- the record of which domains an organization proved control of, one row
-- each, and an organization may hold several (the second domain of D21).
-- Every reader — the SSO auto-link rule of T-12, search's verified
-- filter, the invitation door's own-domain rule — reads domain_claims.
-- Every value the column held on a live database came from a verified
-- claim (VerifyDomainClaim wrote both in one transaction), so nothing is
-- lost by dropping it.
ALTER TABLE orgs DROP COLUMN verified_domain;

-- A verified domain belongs to one organization. A claim is a challenge
-- until it is verified, so two organizations may hold unverified claims
-- on one domain and only one can win it. This index fails loudly on a
-- database where two organizations have verified the same domain (the
-- plan's deploy note lists the claims on dev before this runs): that is a
-- fact to resolve by hand, not one to paper over.
CREATE UNIQUE INDEX domain_claims_verified_domain_idx
  ON domain_claims (domain) WHERE verified_at IS NOT NULL;

-- Two more states. `decommissioning` is the read-only hold after an admin
-- (or platform staff, or the extension's pending-payment sweep) asked for
-- the organization to go: members keep read and export until
-- decommission_at, when the erasure job runs. `decommissioned` is what the
-- row becomes afterwards: the handle is released, the domain freed, the
-- name scrubbed, and the row stays because immutable records (versions,
-- review items, the audit log) still point at its id. `suspended` — a
-- state nothing wrote until now — is platform staff's: the organization
-- and everything under it answer as absent until it is reinstated.
ALTER TABLE orgs DROP CONSTRAINT orgs_state_check;
ALTER TABLE orgs
  ADD CONSTRAINT orgs_state_check
  CHECK (state IN ('active','suspended','decommissioning','decommissioned'));
ALTER TABLE orgs
  ADD COLUMN decommission_at timestamptz,
  ADD COLUMN decommission_reason text;
CREATE INDEX orgs_decommissioning_idx ON orgs (decommission_at) WHERE state = 'decommissioning';

-- +goose Down
DROP INDEX IF EXISTS orgs_decommissioning_idx;
ALTER TABLE orgs DROP COLUMN IF EXISTS decommission_reason, DROP COLUMN IF EXISTS decommission_at;
ALTER TABLE orgs DROP CONSTRAINT orgs_state_check;
ALTER TABLE orgs ADD CONSTRAINT orgs_state_check CHECK (state IN ('active','suspended'));
DROP INDEX IF EXISTS domain_claims_verified_domain_idx;
ALTER TABLE orgs ADD COLUMN verified_domain citext;
UPDATE orgs o SET verified_domain = (
  SELECT dc.domain FROM domain_claims dc
  WHERE dc.org_id = o.id AND dc.verified_at IS NOT NULL
  ORDER BY dc.verified_at LIMIT 1);
ALTER TABLE orgs DROP COLUMN IF EXISTS domain;
