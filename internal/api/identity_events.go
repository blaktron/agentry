package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/queue"
)

// The identity events an extension hears: an account erased, and the set of
// platform staff changed. Both are for an extension that keeps a copy of
// something about people elsewhere (a directory's accounts, a group of
// staff) and must follow the registry's word.

const (
	// EventAccountErased is heard once an account's erasure has committed
	// (POST /user/delete, or an unconfirmed account superseded by a verified
	// sign-in), with the identities it signed in with and the address it
	// held.
	EventAccountErased = "account.erased"
	// EventStaffChanged is heard a few seconds after a sync changed someone's
	// platform_staff flag. It names nobody: the reader reads the whole set
	// (PlatformStaff), which is idempotent and catches up on any it missed.
	EventStaffChanged = "staff.changed"

	// jobStaffChangedEvent carries staff.changed from the transaction that
	// changed a flag to the hooks, after that transaction has had time to
	// commit.
	jobStaffChangedEvent = "staff.changed_event"
	// staffChangedEventDelay is that time.
	staffChangedEventDelay = 5 * time.Second
)

// fireAccountErased tells the extensions an account was erased. Called after
// the commit; the identity rows outlive the erasure, so they are read here.
// A failed read still fires the event, without the identities, and is
// logged: the extension hears the erasure either way.
func (s *Server) fireAccountErased(ctx context.Context, userID uuid.UUID, email string) {
	if len(s.eventHooks) == 0 {
		return
	}
	subjects, err := s.q().ListUserSignInSubjects(ctx, userID)
	if err != nil {
		s.log.ErrorContext(ctx, "account erased: read the identities for the extensions", "user", userID, "err", err)
	}
	s.fireEvent(ctx, Event{Kind: EventAccountErased, UserID: userID, Identities: subjects, Email: email})
}

// staffChanged is the registry's staff hook (registry.Service.SetStaffChanged).
// It runs inside the transaction that changed a flag, so it only queues
// the staff.changed event, where an extension listens.
func (s *Server) staffChanged() {
	if len(s.eventHooks) == 0 || s.jobs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.jobs.Enqueue(ctx, jobStaffChangedEvent, "core", struct{}{},
		queue.WithDelay(staffChangedEventDelay), queue.WithMaxAttempts(3)); err != nil {
		s.log.WarnContext(ctx, "staff changed: enqueue the event", "err", err)
	}
}

func (s *Server) runStaffChangedEvent(ctx context.Context, _ queue.Job) error {
	s.fireEvent(ctx, Event{Kind: EventStaffChanged})
	return nil
}

// registerStaffChangedEvent wires the event's job on the worker. It is
// registered with or without a listener, so a job queued before an
// extension was removed drains as a no-op.
func (s *Server) registerStaffChangedEvent(q queue.Client) {
	if q == nil {
		return
	}
	q.Register(jobStaffChangedEvent, s.runStaffChangedEvent)
}

// StaffMember is one person who is platform staff, as an extension reads
// the set: the account, its handle, and its verified address, lower-cased.
type StaffMember struct {
	UserID uuid.UUID
	Handle string
	Email  string
}

// PlatformStaff lists every active account that is platform staff with a
// verified address, ordered by handle (pkg/extension.Deps.Staff). Platform
// staff is the staff organization's rule, recomputed by the registry alone;
// this is its read side, never a way to change it.
func (s *Server) PlatformStaff(ctx context.Context) ([]StaffMember, error) {
	if s.st == nil {
		return nil, errors.New("api: no database to read platform staff from")
	}
	rows, err := s.q().ListPlatformStaff(ctx)
	if err != nil {
		return nil, fmt.Errorf("api: platform staff: %w", err)
	}
	out := make([]StaffMember, 0, len(rows))
	for _, r := range rows {
		out = append(out, StaffMember{UserID: r.ID, Handle: r.Handle, Email: r.Email})
	}
	return out, nil
}
