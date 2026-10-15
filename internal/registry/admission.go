package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/entitlements"
)

// The admission seam. A closed build may refuse a submission for reasons
// the core does not know — a spent credit allowance — but only at one
// point: after every core gate has passed (quota, validation, 2FA, policy)
// and before anything is stored. The core build has no Admitter and admits everything; the gate,
// the pipeline and the review queue never see an admission at all.

// Admitter is asked once per submission.
type Admitter interface {
	// Admit returns a ticket the core carries on the version.submitted
	// event, or a Refusal the API turns into a problem response. An error
	// is "unknown": the core fails closed with ErrAdmissionUnavailable and
	// stores nothing.
	Admit(ctx context.Context, req Admission) (Ticket, *Refusal, error)
	// Void cancels a ticket the core could not honour — the version row was
	// never created. It must be idempotent.
	Void(ctx context.Context, t Ticket) error
}

// Admission describes the submission being admitted.
type Admission struct {
	// Kind names the act; today only "version.submit".
	Kind string
	// Subject is the namespace the release is submitted under; Submitter
	// the person submitting it, who is not always the namespace.
	Subject   entitlements.Subject
	Submitter uuid.UUID
	AgentID   uuid.UUID
	// Visibility is the agent's, Source the submission door's
	// ("git-tag" | "cli-upload").
	Visibility string
	Source     string
}

// Ticket is an Admitter's handle on one admission; empty means none.
type Ticket struct {
	ID string
}

// Refusal is an admission the Admitter declined: the status and problem
// slug the API answers with, a title and a detail in the crisp register,
// and Fields the response carries at top level so a client can render its
// own sentence (a balance and a reset date, say).
type Refusal struct {
	Status int
	Slug   string
	Title  string
	Detail string
	Fields map[string]any
}

// AdmissionKindVersionSubmit is the one admission kind today.
const AdmissionKindVersionSubmit = "version.submit"

// ErrAdmissionUnavailable reports that the Admitter could not answer. The
// submission is refused and nothing was stored.
var ErrAdmissionUnavailable = errors.New("registry: the admission check could not be reached")

// ErrAdmissionRefused wraps a Refusal as an error the API maps onto a
// problem of the refusal's own status.
type ErrAdmissionRefused struct {
	Refusal Refusal
}

func (e *ErrAdmissionRefused) Error() string {
	return fmt.Sprintf("registry: submission refused: %s", e.Refusal.Slug)
}

// SetAdmitter wires the admission seam; nil (the core build) admits all.
func (s *Service) SetAdmitter(a Admitter) { s.admitter = a }

// HasAdmitter reports whether an admission seam is wired: whether this
// deployment runs the extension that sells things.
func (s *Service) HasAdmitter() bool { return s.admitter != nil }

// admit asks the Admitter, if any. The returned ticket is empty when there
// is none to ask.
func (s *Service) admit(ctx context.Context, req Admission) (Ticket, error) {
	if s.admitter == nil {
		return Ticket{}, nil
	}
	t, refusal, err := s.admitter.Admit(ctx, req)
	if err != nil {
		return Ticket{}, fmt.Errorf("%w: %v", ErrAdmissionUnavailable, err)
	}
	if refusal != nil {
		return Ticket{}, &ErrAdmissionRefused{Refusal: *refusal}
	}
	return t, nil
}

// void hands a ticket back when the submission failed after admission.
func (s *Service) void(ctx context.Context, t Ticket) {
	if s.admitter == nil || t.ID == "" {
		return
	}
	if err := s.admitter.Void(ctx, t); err != nil {
		s.logger().Error("registry: admission void failed", "ticket", t.ID, "err", err)
	}
}
