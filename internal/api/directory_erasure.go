package api

// The directory half of account erasure, finished rather
// than left behind. The request makes the first attempt after
// the registry's erasure commits; a failure is handed to a job that retries
// with the queue's backoff until the directory deletes the account or finds
// it gone. Every attempt is a user.directory_erase audit row. An erasure
// still pending after the last retry is audited as abandoned and raised to
// the operator on the fail-open path (the failopen.directory_erasure line
// and the FailOpenEvents{path="directory_erasure"} count), because a sign-in
// account left in the directory is personal data the privacy policy says is
// removed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
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
	// dirErasePending is the response's word for "a retry is queued".
	dirErasePending = "pending"
	// dirEraseAbandoned is the last retry failing: the operator finishes it.
	dirEraseAbandoned = "abandoned"
)

// directoryErasureHeader carries the outcome on the erasure's 204.
const directoryErasureHeader = "X-Agentry-Directory-Erasure"

// jobDirectoryErase is the retry's queue kind.
const jobDirectoryErase = "gdpr.directory_erase"

// defaultDirectoryEraseAttempts is the retry budget. The queue backs off
// 2^attempt seconds, so fourteen attempts span about four and a half hours:
// long enough to ride out a directory restart or upgrade, short enough that
// the operator hears about a real outage the same day.
const defaultDirectoryEraseAttempts = 14

// directoryEraseArgs is the retry job's payload. The address is sealed with
// the server's sealing key: the users row no longer holds it after the
// erasure, and the jobs table must not hold it in the clear either.
type directoryEraseArgs struct {
	UserID      uuid.UUID `json:"userId"`
	SealedEmail []byte    `json:"sealedEmail"`
}

// SetDirectoryErasureAttempts overrides the retry budget (tests).
func (s *Server) SetDirectoryErasureAttempts(n int) { s.dirEraseAttempts = n }

func (s *Server) directoryEraseAttempts() int {
	if s.dirEraseAttempts > 0 {
		return s.dirEraseAttempts
	}
	return defaultDirectoryEraseAttempts
}

// eraseDirectoryAccount makes one attempt and audits it on base (whose
// actor the caller sets): deleted, not-found, unresolved, not-configured, or
// failed with the error. It deletes the directory account of every
// directory sign-in linked to the person, or with none, the one account at
// the address (findAccount). attempt is 0 for the request's own attempt and
// the job's attempt number for a retry. The error is returned for a failed
// attempt.
func (s *Server) eraseDirectoryAccount(ctx context.Context, base audit.Event, userID uuid.UUID, email string, attempt int) (string, error) {
	outcome := dirEraseNotConfigured
	detail := map[string]any{}
	var failure error
	if s.dirEraser != nil {
		// The identity rows outlive the registry's erasure, so the request
		// and every retry read the same links.
		deleted, unresolved := false, false
		var lookups []string
		links, err := s.directoryLinksFor(ctx, userID, email)
		for _, link := range links {
			if err != nil {
				break
			}
			var ok bool
			var how directoryLookup
			ok, how, err = s.dirEraser.EraseAccount(ctx, link)
			lookups = append(lookups, string(how))
			deleted = deleted || ok
			unresolved = unresolved || how.unresolved()
		}
		if len(lookups) > 0 {
			detail["directoryLookup"] = strings.Join(lookups, ",")
		}
		switch {
		case err != nil:
			outcome, failure = dirEraseFailed, err
			detail["error"] = err.Error()
			s.log.WarnContext(ctx, "gdpr: directory erasure attempt failed", "user", userID, "attempt", attempt, "err", err)
		case unresolved:
			outcome = dirEraseUnresolved
		case deleted:
			outcome = dirEraseDeleted
		default:
			outcome = dirEraseNotFound
		}
	}
	if attempt > 0 {
		detail["attempt"] = attempt
		if failure != nil && attempt >= s.directoryEraseAttempts() {
			outcome = dirEraseAbandoned
		}
	}
	detail["directoryErasure"] = outcome
	s.auditDirectoryErasure(ctx, base, userID, detail)
	if outcome == dirEraseUnresolved {
		// Not retried: another attempt would find the same accounts.
		s.alertDirectoryErasure(ctx, userID, attempt,
			fmt.Errorf("the directory account could not be told apart (%v): nothing was deleted that might be somebody else's", detail["directoryLookup"]))
	}
	return outcome, failure
}

func (s *Server) auditDirectoryErasure(ctx context.Context, e audit.Event, userID uuid.UUID, detail map[string]any) {
	e.Action = audit.ActionUserDirectoryErase
	e.TargetKind, e.TargetID = "user", userID
	e.Detail = detail
	if err := s.auditW.Write(ctx, s.q(), e); err != nil {
		s.log.ErrorContext(ctx, "gdpr: audit directory erasure", "err", err)
	}
}

// scheduleDirectoryErasure queues the retry for a failed request attempt and
// says what the response should report: pending, or failed when the retry
// could not even be queued (which is raised to the operator at once).
func (s *Server) scheduleDirectoryErasure(ctx context.Context, userID uuid.UUID, email string, cause error) string {
	err := func() error {
		if s.jobs == nil {
			return errors.New("no job queue")
		}
		sealed, err := s.sealer.Seal([]byte(email))
		if err != nil {
			return err
		}
		_, err = s.jobs.Enqueue(ctx, jobDirectoryErase, "core",
			directoryEraseArgs{UserID: userID, SealedEmail: sealed},
			queue.WithMaxAttempts(s.directoryEraseAttempts()))
		return err
	}()
	if err != nil {
		s.alertDirectoryErasure(ctx, userID, 0, errors.Join(cause, err))
		return dirEraseFailed
	}
	return dirErasePending
}

// runDirectoryErase is one retry. Returning the error hands the job back to
// the queue's backoff; the last attempt's failure is audited as abandoned
// and raised to the operator.
func (s *Server) runDirectoryErase(ctx context.Context, job queue.Job) error {
	var a directoryEraseArgs
	if err := json.Unmarshal(job.Args, &a); err != nil {
		s.log.ErrorContext(ctx, "gdpr: directory erasure job args", "job", job.ID, "err", err)
		return nil // unreadable args never become readable: not retried
	}
	email, err := s.sealer.Open(a.SealedEmail)
	if err != nil {
		// A rotated sealing key: no retry can recover the address.
		s.auditDirectoryErasure(ctx, audit.Event{ActorKind: audit.ActorSystem}, a.UserID,
			map[string]any{"directoryErasure": dirEraseAbandoned, "attempt": job.Attempt, "error": "the queued address could not be unsealed"})
		s.alertDirectoryErasure(ctx, a.UserID, job.Attempt, err)
		return nil
	}
	outcome, err := s.eraseDirectoryAccount(ctx, audit.Event{ActorKind: audit.ActorSystem}, a.UserID, string(email), job.Attempt)
	if err == nil {
		return nil
	}
	if outcome == dirEraseAbandoned {
		s.alertDirectoryErasure(ctx, a.UserID, job.Attempt, err)
	}
	return err
}

// alertDirectoryErasure raises an erasure whose directory half did not
// happen: an ERROR line under a catalogued fail-open name, which a log
// monitor keys on, and the fail-open count the ticket alarm reads.
func (s *Server) alertDirectoryErasure(ctx context.Context, userID uuid.UUID, attempts int, err error) {
	s.log.ErrorContext(ctx, "gdpr: directory erasure did not complete — delete the sign-in account by hand",
		logevent.FailOpenDirectoryErasure.Attr(), "user", userID, "attempts", attempts, "err", err)
	s.mx.RecordFailOpen(ctx, metrics.FailOpenDirectoryErasure)
}

// registerDirectoryErasure wires the retry handler onto a worker.
func (s *Server) registerDirectoryErasure(q queue.Client) {
	q.Register(jobDirectoryErase, s.runDirectoryErase)
}
