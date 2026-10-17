package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
)

// Directory is the registry's port to the directory service that holds
// people's sign-in accounts. The registry asks it to erase an account and
// whether an account is still there (EraseAccount, AccountGone); the other
// methods are the directory's own surface, which an extension that is the
// directory implements and serves. The registry keeps the rules (when an
// account is erased, who is platform staff); the directory carries them out
// on its own records.
//
// A server has at most one, which an extension supplies with SetDirectory
// (pkg/extension.ManagesDirectory). With none, erasure stops at the
// registry ("not-configured").
//
// Every method reads the account a DirectoryLink names and never another:
// a link the directory cannot tell apart from somebody else's account is
// answered as unresolved or as nothing, never as a guess.
type Directory interface {
	// EraseAccount deletes the account the link names, never a superuser
	// or a service account, and says which rule it looked by. False with
	// no error when no account qualifies.
	EraseAccount(ctx context.Context, link DirectoryLink) (bool, DirectoryLookup, error)
	// Devices lists the authenticators the account has enrolled; an empty
	// list, not an error, for no account or no devices.
	Devices(ctx context.Context, link DirectoryLink) ([]DirectoryDevice, error)
	// DeleteDevice removes one of the account's own authenticators; false
	// when the account has no device of that kind and id.
	DeleteDevice(ctx context.Context, link DirectoryLink, kind, id string) (bool, error)
	// SignInFacts says how the account signs in at the directory. A link
	// with no uid is answered with nothing: an address alone never picks
	// the account.
	SignInFacts(ctx context.Context, link DirectoryLink) (DirectorySignInFacts, error)
	// AccountGone reports that the account is no longer in the directory;
	// false when it cannot tell.
	AccountGone(ctx context.Context, link DirectoryLink) (bool, error)
	// GroupMembers returns a group's id and members, creating the group
	// when it does not exist.
	GroupMembers(ctx context.Context, group string) (groupID string, members []DirectoryAccount, err error)
	// AccountsByEmail returns the accounts at exactly this address
	// (case-blind), service accounts left out.
	AccountsByEmail(ctx context.Context, email string) ([]DirectoryAccount, error)
	// SetMember adds an account to a group or removes it.
	SetMember(ctx context.Context, groupID string, accountPK int, member bool) error
}

// SetDirectory makes d the server's directory, for every caller: erasure
// (by d's own DirectoryErasure where it has one, else by one attempt
// through d) and the superseded-account check. The directory's own sign-in
// work (its claims, remembered browsers, its callbacks, a staff mirror) is
// d's, through the sign-in hook, its callback mount and staff.changed. A nil
// d leaves the server with no directory.
func (s *Server) SetDirectory(d Directory) { s.directory = d }

// DirectoryErasure is the optional interface for a directory that carries
// out the directory half of an account's erasure itself, retries included.
// The core then calls EraseErased once, after the registry's erasure has
// committed, in place of its own attempt, and reports the
// outcome it returns on the erasure's response (X-Agentry-Directory-Erasure),
// which the site reads to tell the person where their sign-in account
// stands. EraseErased is called in the request, so it makes at most one
// quick attempt and queues the rest. The directory records each attempt
// as a user.directory_erase audit event and raises one that never
// completes. An outcome outside the set below
// is reported as failed and raised.
type DirectoryErasure interface {
	EraseErased(r *http.Request, a ErasedAccount) string
}

// ErasedAccount is an account whose registry erasure has committed: what a
// directory needs to find the person's sign-in account. Identities are the
// subjects it signed in with ("<provider>:<sub>"), oldest first; Email is
// the address it held before the erasure.
type ErasedAccount struct {
	UserID     uuid.UUID
	Identities []string
	Email      string
}

// The outcomes the erasure's response reports for the directory half.
const (
	DirectoryErasureDeleted       = dirEraseDeleted
	DirectoryErasureNotFound      = dirEraseNotFound
	DirectoryErasureUnresolved    = dirEraseUnresolved
	DirectoryErasureNotConfigured = dirEraseNotConfigured
	DirectoryErasureFailed        = dirEraseFailed
	DirectoryErasurePending       = dirErasePending
)

// knownDirectoryErasure reports an outcome the response may carry.
func knownDirectoryErasure(outcome string) bool {
	switch outcome {
	case dirEraseDeleted, dirEraseNotFound, dirEraseUnresolved, dirEraseNotConfigured, dirEraseFailed, dirErasePending:
		return true
	}
	return false
}

// eraseInDirectory is the directory half of a person's erasure, after the
// registry's has committed: handed to a directory that carries it out
// itself, else the core's one attempt. It returns what the response
// reports.
func (s *Server) eraseInDirectory(r *http.Request, base audit.Event, userID uuid.UUID, email string) string {
	if de, ok := s.directory.(DirectoryErasure); ok {
		return s.delegateErasure(r, de, userID, email)
	}
	return s.eraseDirectoryAccount(r.Context(), base, userID, email)
}

// delegateErasure hands the directory half to the directory. An outcome the
// response does not define, or a directory that panicked, is reported as
// failed and raised to the operator as a failed erasure is: the registry
// cannot tell that the sign-in account went.
func (s *Server) delegateErasure(r *http.Request, de DirectoryErasure, userID uuid.UUID, email string) (outcome string) {
	ctx := r.Context()
	subjects, err := s.q().ListUserSignInSubjects(ctx, userID)
	if err != nil {
		s.log.ErrorContext(ctx, "gdpr: read the identities for the directory's erasure", "user", userID, "err", err)
	}
	defer func() {
		if rec := recover(); rec != nil {
			s.alertDirectoryErasure(ctx, userID, fmt.Errorf("the directory's erasure panicked: %v", rec))
			outcome = dirEraseFailed
		}
	}()
	outcome = de.EraseErased(r, ErasedAccount{UserID: userID, Identities: subjects, Email: email})
	if !knownDirectoryErasure(outcome) {
		s.alertDirectoryErasure(ctx, userID, fmt.Errorf("the directory's erasure answered %q, which is no outcome the response defines", outcome))
		return dirEraseFailed
	}
	return outcome
}

// HasDirectory reports whether the server has a directory.
func (s *Server) HasDirectory() bool { return s.directory != nil }
