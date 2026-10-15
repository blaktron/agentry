package knowledge

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/entitlements"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Pool is the allocation an owner's knowledge packs draw on: the owner
// alone in the core, or, where an extension pools owners, a paid
// organization's seats shared by its packs and its members'.
type Pool struct {
	// Key names the pool: every upload into it is reserved under one
	// transaction-scoped lock on the key, so two owners who share it
	// cannot both pass its cap.
	Key string
	// Owners are every owner whose packs count against the pool, the one
	// asking included.
	Owners []Owner
	// Cap is the pool's allocation; a cap never deletes.
	Cap entitlements.Cap
}

// Pools is the optional interface of an entitlements resolver that pools
// owners' knowledge. The core asks the resolver it holds, so an extension's
// resolver answers; an error is not permission. The contract the core
// cannot check: every owner a pool lists must be answered with that same
// pool (the same Key), or two of them are not serialised on one lock.
// Pooling discloses the pool's total to every owner in it — the meter and
// the refusal name it — which a shared cap cannot avoid.
type Pools interface {
	KnowledgePool(ctx context.Context, owner Owner) (Pool, error)
}

// sumParams is the store's question for the pool's bytes, except aside
// (uuid.Nil for none).
func (p Pool) sumParams(except uuid.UUID) storegen.SumKnowledgeBytesOfPoolParams {
	arg := storegen.SumKnowledgeBytesOfPoolParams{ExceptID: except}
	for _, o := range p.Owners {
		arg.OwnerKinds = append(arg.OwnerKinds, string(o.Kind))
		arg.OwnerIds = append(arg.OwnerIds, o.ID)
	}
	return arg
}

// fits is the allocation rule for a pack whose tree of cur bytes is
// replaced by one of next, beside the others bytes the pool's other packs
// hold. A cap never deletes: a tree no larger than the one it replaces is
// always taken; one that grows must fit under an enabled cap.
func (p Pool) fits(others, cur, next int64) error {
	if c := p.Cap; next > cur && (!c.Enabled || (c.Max > 0 && others+next > c.Max)) {
		return &AllocationError{Bytes: others + next, Max: c.Max}
	}
	return nil
}

// pooled says whether the pool counts owners other than owner.
func (p Pool) pooled(owner Owner) bool {
	return slices.ContainsFunc(p.Owners, func(o Owner) bool { return o != owner })
}
