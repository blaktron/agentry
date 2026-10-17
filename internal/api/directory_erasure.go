package api

// The directory half of account erasure, after the registry's erasure
// commits. A directory that carries it out itself (DirectoryErasure) is
// handed it, retries included; any other gets one attempt through
// EraseAccount, audited as a user.directory_erase row. An attempt that
// fails, or that cannot tell the person's account apart, is raised to the
// operator on the fail-open path (the failopen.directory_erasure line and
// the FailOpenEvents{path="directory_erasure"} count), because a sign-in
// account left in the directory is personal data the privacy policy says
// is removed.

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/metrics"
)

// The outcomes a user.directory_erase row and the erasure's response header
// carry.
const (
	dirEraseDeleted  = "deleted"
	dirEraseNotFound = "not-found"
	// dirEraseUnresolved is a lookup that could not tell the person's
	// account apart (a shared address, an id holding another account now,
	// a superuser): nothing it could not tell apart is deleted, and the
	// operator is alerted to finish it by hand.
	dirEraseUnresolved    = "unresolved"
	dirEraseNotConfigured = "not-configured"
	dirEraseFailed        = "failed"
	// dirErasePending is a directory's word for "a retry is queued".
	dirErasePending = "pending"
)

// directoryErasureHeader carries the outcome on the erasure's 204.
const directoryErasureHeader = "X-Agentry-Directory-Erasure"

// eraseDirectoryAccount makes the one attempt and audits it on base (whose
// actor the caller sets): deleted, not-found, unresolved, not-configured, or
// failed. It deletes the directory account of every sign-in through the
// sign-in provider linked to the person, or with none, the one account at
// the address. A failed or unresolved attempt is raised to the operator.
func (s *Server) eraseDirectoryAccount(ctx context.Context, base audit.Event, userID uuid.UUID, email string) string {
	outcome := dirEraseNotConfigured
	detail := map[string]any{}
	if s.directory != nil {
		deleted, unresolved := false, false
		var lookups []string
		links, err := s.directoryLinksFor(ctx, userID, email)
		for _, link := range links {
			if err != nil {
				break
			}
			var ok bool
			var how DirectoryLookup
			ok, how, err = s.directory.EraseAccount(ctx, link)
			lookups = append(lookups, string(how))
			deleted = deleted || ok
			unresolved = unresolved || how.unresolved()
		}
		if len(lookups) > 0 {
			detail["directoryLookup"] = strings.Join(lookups, ",")
		}
		switch {
		case err != nil:
			outcome = dirEraseFailed
			detail["error"] = err.Error()
			s.alertDirectoryErasure(ctx, userID, err)
		case unresolved:
			outcome = dirEraseUnresolved
			s.alertDirectoryErasure(ctx, userID,
				fmt.Errorf("the directory account could not be told apart (%v): nothing was deleted that might be somebody else's", detail["directoryLookup"]))
		case deleted:
			outcome = dirEraseDeleted
		default:
			outcome = dirEraseNotFound
		}
	}
	detail["directoryErasure"] = outcome
	base.Action = audit.ActionUserDirectoryErase
	base.TargetKind, base.TargetID = "user", userID
	base.Detail = detail
	if err := s.auditW.Write(ctx, s.q(), base); err != nil {
		s.log.ErrorContext(ctx, "gdpr: audit directory erasure", "err", err)
	}
	return outcome
}

// alertDirectoryErasure raises an erasure whose directory half did not
// happen: an ERROR line under a catalogued fail-open name, which a log
// monitor keys on, and the fail-open count the ticket alarm reads.
func (s *Server) alertDirectoryErasure(ctx context.Context, userID uuid.UUID, err error) {
	s.log.ErrorContext(ctx, "gdpr: directory erasure did not complete — delete the sign-in account by hand",
		logevent.FailOpenDirectoryErasure.Attr(), "user", userID, "err", err)
	s.mx.RecordFailOpen(ctx, metrics.FailOpenDirectoryErasure)
}
