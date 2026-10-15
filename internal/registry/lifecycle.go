package registry

// Retire, Restore and the tombstone Delete: what a publisher does with a
// QuickAgent of their own that they no longer want in front of anyone.

import (
	"context"
	"errors"
	"fmt"

	"github.com/blaktron/agentry/internal/audit"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// ErrRetired reports a write a retired agent does not take: a submission,
// or making it public other than by Restore. The API answers 409
// agent-retired.
var ErrRetired = errors.New("registry: this QuickAgent is retired")

// ErrVersionsInFlight reports a delete of an agent a version of which the
// pipeline or a reviewer has yet to decide: the verdict would otherwise
// land on a tombstone. The API answers 409.
var ErrVersionsInFlight = errors.New("registry: a version of this QuickAgent is still in flight")

// ErrNotRetired reports a Restore of an agent that is not retired.
var ErrNotRetired = errors.New("registry: this QuickAgent is not retired")

// ErrPipelineSkipOnRestore reports a Restore to public of an agent whose
// pipeline: skip was set while it was retired: a public agent is always
// scanned. The API answers it as PATCH answers the same state,
// 409 agent-unscanned.
var ErrPipelineSkipOnRestore = errors.New("registry: this QuickAgent is off the pipeline and cannot be made public")

// UnscannedStandingError reports a Restore to public refused because N
// versions admitted unscanned still stand.
type UnscannedStandingError struct{ N int64 }

func (e *UnscannedStandingError) Error() string {
	return fmt.Sprintf("registry: %d unscanned versions stand", e.N)
}

// tombstoneYankReason is what a deleted agent's published versions carry
// as their yank reason: the record says who withdrew them and why.
const tombstoneYankReason = "The publisher deleted this QuickAgent."

// ResolveIncludingDeleted is Resolve with a deleted agent's tombstone
// found, not hidden: the trust & safety actions' door to an agent its
// publisher deleted, and the create's way to tell a held name from a
// taken one once the namespace has admitted the caller. No read a
// publisher or a consumer makes goes through it, save one: the advisories
// of an agent the caller holds a release of reach its owning
// organization's gate through it, after the holder is
// proved.
func (s *Service) ResolveIncludingDeleted(ctx context.Context, namespace, name string) (Agent, error) {
	return s.resolve(ctx, namespace, name, true)
}

// Retire makes the agent private and labels it retired, keeping the
// visibility it had for Restore. It takes no new submission until it
// is restored. A retired agent holds no place under the private-agent cap,
// so retiring is never refused by it. Retiring an agent that is already
// retired changes nothing and is not an error.
func (s *Service) Retire(ctx context.Context, a Agent, actorEvent audit.Event) error {
	return s.st.WithTx(ctx, func(q *storegen.Queries) error {
		locked, err := q.GetAgentForUpdate(ctx, a.ID)
		if err != nil {
			return fmt.Errorf("registry: lock agent: %w", err)
		}
		if locked.RetiredAt != nil {
			return nil
		}
		if _, err := q.RetireAgent(ctx, a.ID); err != nil {
			return fmt.Errorf("registry: retire: %w", err)
		}
		e := actorEvent
		e.Action = audit.ActionAgentRetire
		if a.NamespaceKind == "org" {
			e.OrgID = a.NamespaceID
		}
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{"namespace": a.Namespace, "name": a.Name, "visibility": locked.Visibility}
		return s.aud.Write(ctx, q, e)
	})
}

// Restore returns a retired agent to the visibility it had. Back to public
// it meets the rules any agent becoming public meets: not off
// the pipeline, no unscanned version standing. Back to private it takes a
// place under the private-agent cap again, so the cap is checked under the
// namespace's lock.
func (s *Service) Restore(ctx context.Context, a Agent, actorEvent audit.Event) error {
	return s.st.WithTx(ctx, func(q *storegen.Queries) error {
		locked, err := q.GetAgentForUpdate(ctx, a.ID)
		if err != nil {
			return fmt.Errorf("registry: lock agent: %w", err)
		}
		if locked.RetiredAt == nil || locked.RetiredVisibility == nil {
			return ErrNotRetired
		}
		to := *locked.RetiredVisibility
		switch to {
		case "public":
			if locked.PipelineSkip {
				return ErrPipelineSkipOnRestore
			}
			n, err := q.CountUnscannedVersionsStanding(ctx, a.ID)
			if err != nil {
				return fmt.Errorf("registry: unscanned versions: %w", err)
			}
			if n > 0 {
				return &UnscannedStandingError{N: n}
			}
		case "private":
			if err := s.CheckPrivateAgentCapInTx(ctx, q, a); err != nil {
				return err
			}
		}
		if _, err := q.RestoreAgent(ctx, a.ID); err != nil {
			return fmt.Errorf("registry: restore: %w", err)
		}
		e := actorEvent
		e.Action = audit.ActionAgentRestore
		if a.NamespaceKind == "org" {
			e.OrgID = a.NamespaceID
		}
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{"namespace": a.Namespace, "name": a.Name, "visibility": to}
		return s.aud.Write(ctx, q, e)
	})
}

// Tombstone deletes an agent that has version history. Every
// published or quarantined version is yanked, the agent becomes private
// and deleted, and every read by name stops finding it. Nothing is
// removed: the version rows (which the 00004 trigger keeps), the
// archives, the receipts and the audit trail all stay, and the row holds
// the name in its namespace for good. The caller has already refused
// the cases the tombstone does not take: trust & safety records and
// versions still in flight. The audit event says how many were yanked.
func (s *Service) Tombstone(ctx context.Context, a Agent, actorEvent audit.Event) error {
	var results []TransitionResult
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if _, err := q.GetAgentForUpdate(ctx, a.ID); err != nil {
			return fmt.Errorf("registry: lock agent: %w", err)
		}
		// Counted again under the lock SubmitVersion's insert takes, so a
		// submission that raced the handler's check is either seen here or
		// refused there.
		blockers, err := q.CountAgentDeleteBlockers(ctx, a.ID)
		if err != nil {
			return fmt.Errorf("registry: delete blockers: %w", err)
		}
		if blockers.VersionsInFlight > 0 {
			return ErrVersionsInFlight
		}
		versions, err := q.ListVersions(ctx, a.ID)
		if err != nil {
			return err
		}
		yank := actorEvent
		yank.Action = audit.ActionVersionYank
		if a.NamespaceKind == "org" {
			yank.OrgID = a.NamespaceID
		}
		for _, v := range versions {
			switch Status(v.Status) {
			case StatusPublished, StatusQuarantined:
			default:
				continue
			}
			res, err := s.TransitionInTx(ctx, q, v.ID, StatusYanked, tombstoneYankReason, yank)
			if err != nil {
				return fmt.Errorf("registry: yank %s: %w", v.Version, err)
			}
			results = append(results, res)
		}
		n, err := q.TombstoneAgent(ctx, a.ID)
		if err != nil {
			return fmt.Errorf("registry: tombstone: %w", err)
		}
		if n != 1 {
			return ErrNotFound
		}
		e := actorEvent
		e.Action = audit.ActionAgentDelete
		if a.NamespaceKind == "org" {
			e.OrgID = a.NamespaceID
		}
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{
			"namespace": a.Namespace, "name": a.Name,
			"tombstone": true, "versionsYanked": len(results),
		}
		return s.aud.Write(ctx, q, e)
	})
	if err != nil {
		return err
	}
	for _, res := range results {
		s.EmitTransition(ctx, res)
	}
	return nil
}
