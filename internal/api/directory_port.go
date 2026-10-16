package api

import "context"

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
// one, for every caller: erasure and its retries, the settings page, the
// superseded-account check and, where auth.idpStaffMirrorGroup is set, the
// staff mirror. Under auth.externalOnly the settings page then reports the
// account as the directory's (managed), with or without a directory
// sign-in provider to link to. A nil d leaves the server with no directory.
func (s *Server) SetDirectory(d Directory) {
	s.dirSet = d != nil
	if d == nil {
		s.dirEraser, s.dirGroups = nil, nil
		return
	}
	s.dirEraser = d
	s.dirGroups = nil
	if s.cfg.Auth.IdPStaffMirrorGroup != "" {
		s.dirGroups = d
	}
}

// HasDirectory reports whether the server has a directory, built in or an
// extension's.
func (s *Server) HasDirectory() bool { return s.dirEraser != nil }
