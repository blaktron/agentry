package knowledge

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// StoreSalts keeps owner salts in knowledge_owner_keys.
type StoreSalts struct{ st *store.Store }

// NewStoreSalts is the database's OwnerSalts.
func NewStoreSalts(st *store.Store) *StoreSalts { return &StoreSalts{st: st} }

// Salt implements OwnerSalts.
func (s *StoreSalts) Salt(ctx context.Context, owner Owner, create bool) ([]byte, error) {
	q := s.st.Queries()
	salt, err := q.GetKnowledgeOwnerSalt(ctx, storegen.GetKnowledgeOwnerSaltParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID})
	switch {
	case err == nil:
		return salt, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	case !create:
		return nil, ErrNotOwner
	}
	fresh := make([]byte, SaltSize)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	return q.CreateKnowledgeOwnerSalt(ctx, storegen.CreateKnowledgeOwnerSaltParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID, Salt: fresh})
}

// DeleteSalt implements OwnerSalts.
func (s *StoreSalts) DeleteSalt(ctx context.Context, owner Owner) error {
	return s.st.Queries().DeleteKnowledgeOwnerSalt(ctx, storegen.DeleteKnowledgeOwnerSaltParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID})
}
