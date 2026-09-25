// Package knowledge is the registry's store of knowledge packs (plan
// knowledge.md §4.3, §4.4; agentry#593): the packs a signed-in person, or
// later an organization, keeps in Agentry, each held as its tree sealed
// under a data key of its own (pkg/packseal) with that key wrapped for its
// owner by a KeyWrapper, scanned when it arrives, and destroyed with its
// owner. The core carries all of it without certificates: its wrapper is
// the deployment's knowledge sealing key; an extension (SecureAgentry's
// certificate wrapper) replaces the wrapper and nothing else.
package knowledge

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// OwnerKind is what owns a pack: a person or an organization.
type OwnerKind string

// The owners a pack can have.
const (
	OwnerUser OwnerKind = "user"
	OwnerOrg  OwnerKind = "org"
)

// Owner is a pack's owner, by the id of its account or its organization.
type Owner struct {
	Kind OwnerKind
	ID   uuid.UUID
}

// User is the owner that is the person with this account id.
func User(id uuid.UUID) Owner { return Owner{Kind: OwnerUser, ID: id} }

// Org is the owner that is the organization with this id.
func Org(id uuid.UUID) Owner { return Owner{Kind: OwnerOrg, ID: id} }

// Valid says whether the owner names a kind and an id.
func (o Owner) Valid() bool {
	return (o.Kind == OwnerUser || o.Kind == OwnerOrg) && o.ID != uuid.Nil
}

func (o Owner) String() string { return fmt.Sprintf("%s/%s", o.Kind, o.ID) }

var (
	// ErrNotOwner is a wrapped key that does not open for the owner who
	// presents it: wrapped for someone else, under a key since destroyed,
	// or altered. Which of those is not the caller's to learn.
	ErrNotOwner = errors.New("knowledge: the wrapped key is not this owner's")
	// ErrUnconfigured is a deployment with no knowledge sealing key and no
	// extension wrapper: it stores no packs.
	ErrUnconfigured = errors.New("knowledge: no key wrapper is configured")
)
