package registry

// The one place an organization's state is enforced (agentry#363, plan
// organization-subscriptions §5.4). Before this the API answered 404 for
// a suspended organization at its own lookup and nothing else read
// orgs.state — an agent under a suspended organization answered every
// route as usual, and the git door and the API disagreed on a failed org
// lookup. Now every door that touches an organization or something under
// it asks OrgGate: the API's authorize chokepoint for org-scoped routes,
// the agent resolution for agent-scoped ones, CreateAgent, the membership
// chokepoint, the SCIM data plane and the git transport.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// The organization states (orgs.state, migration 00032).
const (
	OrgStateActive          = "active"
	OrgStateSuspended       = "suspended"
	OrgStateDecommissioning = "decommissioning"
	OrgStateDecommissioned  = "decommissioned"
)

// OrgGateError is why the organization's state refused an act. State is
// what the organization is in; DecommissionAt is set during a hold, so a
// refusal can say when the erasure runs.
type OrgGateError struct {
	State          string
	DecommissionAt *time.Time
}

func (e *OrgGateError) Error() string {
	switch e.State {
	case OrgStateDecommissioning:
		return "registry: this organization is being decommissioned and is read-only"
	case OrgStateDecommissioned:
		return "registry: this organization has been decommissioned"
	}
	return "registry: this organization is suspended"
}

// Absent reports whether the organization should answer as if it did not
// exist: suspended by platform staff, or already erased. A decommissioning
// organization is not absent — its members still read it.
func (e *OrgGateError) Absent() bool { return e.State != OrgStateDecommissioning }

// OrgGate reports whether the organization's state permits act on it or
// on something under it. An active organization permits everything; a
// suspended or decommissioned one nothing; one in its decommission hold
// only the read-only actions (auth.ReadOnly). An organization that does
// not exist is ErrNotFound. An unreadable state is an error, never
// permission.
func (s *Service) OrgGate(ctx context.Context, orgID uuid.UUID, act auth.Action) error {
	return s.OrgGateIn(ctx, s.st.Queries(), orgID, act)
}

// OrgGateIn is OrgGate inside a caller's transaction, so a state read
// under the organization's row lock is the one the change commits against.
func (s *Service) OrgGateIn(ctx context.Context, q *storegen.Queries, orgID uuid.UUID, act auth.Action) error {
	row, err := q.GetOrgState(ctx, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("registry: org state: %w", err)
	}
	switch row.State {
	case OrgStateActive:
		return nil
	case OrgStateDecommissioning:
		if auth.HoldPermits(act) {
			return nil
		}
		return &OrgGateError{State: row.State, DecommissionAt: row.DecommissionAt}
	default:
		return &OrgGateError{State: row.State}
	}
}

// OrgGateFor is OrgGate for an agent's namespace: a personal namespace
// has no state and always passes.
func (s *Service) OrgGateFor(ctx context.Context, a Agent, act auth.Action) error {
	if a.NamespaceKind != "org" {
		return nil
	}
	return s.OrgGate(ctx, a.NamespaceID, act)
}
