package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
)

// Directory is the registry's port to the directory service that holds
// people's sign-in accounts: everything the registry asks of it or tells
// it. The registry keeps the rules (when an account is erased, which
// devices a caller may remove, who is platform staff); the directory
// carries them out on its own records.
//
// A server has at most one. The built-in one speaks authentik's API with
// auth.idpAdminURL and auth.idpAdminToken; an extension supplies its own
// with SetDirectory (pkg/extension.ManagesDirectory), which replaces it.
// With none, erasure stops at the registry ("not-configured"), the
// settings page lists no authenticators and the staff mirror does
// nothing.
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

var _ Directory = (*authentikEraser)(nil)

// SetDirectory makes d the server's directory in place of the built-in
// one, for every caller: erasure (by d's own DirectoryErasure where it has
// one, else by the core's attempt and retries through d), the settings page
// and the superseded-account check. Under auth.externalOnly the settings
// page then reports the account as the directory's (managed), with or
// without a directory sign-in provider to link to.
//
// An extension's directory takes the directory's whole path, so the core
// stops doing the directory's own work beside it: it reads none of the
// directory's claims at sign-in (its account id, the sign-up promo code,
// the remember-this-browser request), mints no remembered browser for the
// directory and answers its /internal/directory/ checks 404, and keeps no
// staff mirror group. The extension does each of these itself, through
// the sign-in hook, its callback mount and staff.changed. A nil d leaves
// the server with no directory.
func (s *Server) SetDirectory(d Directory) {
	s.dirSet = d != nil
	s.dirGroups = nil
	if d == nil {
		s.dirEraser = nil
		return
	}
	s.dirEraser = d
}

// builtInDirectory reports whether the directory path is the core's own:
// no extension supplied the directory. The directory's claims, its trust
// and verification checks and the staff mirror are read only then.
func (s *Server) builtInDirectory() bool { return !s.dirSet }

// DirectoryErasure is the optional interface for a directory that carries
// out the directory half of an account's erasure itself, retries included.
// The core then calls EraseErased once, after the registry's erasure has
// committed, in place of its own attempt and retry job, and reports the
// outcome it returns on the erasure's response (X-Agentry-Directory-Erasure),
// which the site reads to tell the person where their sign-in account
// stands. EraseErased is called in the request, so it makes at most one
// quick attempt and queues the rest.
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
// registry's has committed: handed to an extension's directory that carries
// it out itself, else the core's first attempt with its retry queued on
// failure. It returns what the response reports. An outcome a directory
// returns that the response does not define is logged and left off, so the
// site says what it says when it cannot tell.
func (s *Server) eraseInDirectory(r *http.Request, base audit.Event, userID uuid.UUID, email string) string {
	ctx := r.Context()
	if de, ok := s.dirEraser.(DirectoryErasure); ok && s.dirSet {
		subjects, err := s.q().ListUserSignInSubjects(ctx, userID)
		if err != nil {
			s.log.ErrorContext(ctx, "gdpr: read the identities for the directory's erasure", "user", userID, "err", err)
		}
		outcome := de.EraseErased(r, ErasedAccount{UserID: userID, Identities: subjects, Email: email})
		if !knownDirectoryErasure(outcome) {
			s.log.ErrorContext(ctx, "gdpr: the directory's erasure answered an outcome the response does not define", "user", userID, "outcome", outcome)
			return ""
		}
		return outcome
	}
	dir, derr := s.eraseDirectoryAccount(ctx, base, userID, email, 0)
	if derr != nil {
		dir = s.scheduleDirectoryErasure(ctx, userID, email, derr)
	}
	return dir
}

// HasDirectory reports whether the server has a directory, built in or an
// extension's.
func (s *Server) HasDirectory() bool { return s.dirEraser != nil }
