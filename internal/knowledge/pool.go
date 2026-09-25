package knowledge

import (
	"context"

	"github.com/blaktron/agentry/internal/entitlements"
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
// resolver answers; an error is not permission.
type Pools interface {
	KnowledgePool(ctx context.Context, owner Owner) (Pool, error)
}

func (p Pool) counts(owner Owner) bool {
	for _, o := range p.Owners {
		if o == owner {
			return true
		}
	}
	return false
}

// owners is the pool's owners as the store names them, "<kind>/<id>".
func (p Pool) owners() []string {
	out := make([]string, 0, len(p.Owners))
	for _, o := range p.Owners {
		out = append(out, o.String())
	}
	return out
}
