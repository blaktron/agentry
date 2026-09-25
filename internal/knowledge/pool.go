package knowledge

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/entitlements"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Pool is the allocation an owner's knowledge packs draw on (agentry#612):
// the owner alone in the core, or, where an extension pools owners, a paid
// organization's seats shared by its packs and its members' (plan
// knowledge.md §4.4, D5).
type Pool struct {
	// Key names the pool: every upload into it is reserved under one
	// transaction-scoped lock on the key, so two owners who share it
	// cannot both pass its cap.
	Key string
	// Owners are every owner whose packs count against the pool, the one
	// asking included.
	Owners []Owner
	// Cap is the pool's allocation; a cap never deletes (D25).
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

// pooled says whether the pool counts owners other than owner.
func (p Pool) pooled(owner Owner) bool {
	return slices.ContainsFunc(p.Owners, func(o Owner) bool { return o != owner })
}
