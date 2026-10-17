package api

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// DirectoryLink is how the registry names a person's directory account:
// the directory's own id for it where one was recorded; the uid the
// directory reports for it, which is the subject of the person's sign-in
// through the sign-in provider without its "<id>:" prefix; and the
// registry's copy of the address, the lookup of last resort. The id and the
// uid are zero for an account that never signed in through the sign-in
// provider.
type DirectoryLink struct {
	AccountID int64
	UID       string
	Email     string
}

// DirectoryLookup is how a directory found the account a link names, or why
// it took none. The erasure's audit row records it.
type DirectoryLookup string

const (
	DirectoryLookupByID      DirectoryLookup = "id"
	DirectoryLookupByUID     DirectoryLookup = "uid"
	DirectoryLookupByAddress DirectoryLookup = "address"
	// The three that leave an account the person may hold in place: more
	// than one account at the address, the recorded id now holding an
	// account with another uid, and a superuser, which erasure never
	// deletes. Erasure reports these as unresolved, for the operator.
	DirectoryLookupAddressShared DirectoryLookup = "address-shared"
	DirectoryLookupIDMismatch    DirectoryLookup = "id-mismatch"
	DirectoryLookupSuperuser     DirectoryLookup = "superuser"
)

// unresolved reports a lookup that may have left the person's account in
// the directory.
func (l DirectoryLookup) unresolved() bool {
	return l == DirectoryLookupAddressShared || l == DirectoryLookupIDMismatch || l == DirectoryLookupSuperuser
}

// DirectoryDevice is one enrolled authenticator as the directory reports it.
type DirectoryDevice struct {
	ID        string
	Kind      string
	Name      string
	CreatedAt *time.Time
}

// DirectorySignInFacts is how an account signs in at the directory; a nil
// field is one the directory did not answer.
type DirectorySignInFacts struct {
	FirstSource *DirectorySource
	HasPassword *bool
}

// DirectorySource is a social provider as the directory names it.
type DirectorySource struct {
	Slug string
	Name string
}

// DirectoryAccount is an account as the directory lists it, for its group
// calls.
type DirectoryAccount struct {
	PK     int
	Email  string
	UID    string
	Active bool
	// HasPassword is the directory's own record of whether the account has
	// a password; nil when it has none yet.
	HasPassword *bool
}

// directoryLinksFor names every directory account the person is linked to,
// oldest first: the uid (and any recorded id) of each sign-in through the
// sign-in provider, with the registry's address as the last resort. With no
// such sign-in, or no sign-in provider, it is the address alone.
func (s *Server) directoryLinksFor(ctx context.Context, userID uuid.UUID, email string) ([]DirectoryLink, error) {
	p, ok := s.cfg.SignInOIDC()
	if !ok {
		return []DirectoryLink{{Email: email}}, nil
	}
	rows, err := s.q().ListUserDirectoryLinks(ctx, storegen.ListUserDirectoryLinksParams{ProviderID: p.ID, UserID: userID})
	if err != nil {
		return nil, fmt.Errorf("read the account's directory links: %w", err)
	}
	if len(rows) == 0 {
		return []DirectoryLink{{Email: email}}, nil
	}
	links := make([]DirectoryLink, 0, len(rows))
	for _, r := range rows {
		links = append(links, DirectoryLink{AccountID: r.DirectoryAccountID, UID: r.DirectorySubject, Email: email})
	}
	return links, nil
}
