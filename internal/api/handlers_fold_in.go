package api

// The fold-in's three moments: the step at a directory sign-in, the sweep
// when an organization
// gains a domain, and the daily digest that names the pending members to
// the organization's admins. The rules live in internal/registry/foldin.go;
// this file is where they are called from and what runs on the queue.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth/social"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

const (
	// JobFoldInSweep folds in the accounts already known at a domain an
	// organization has just gained; its args name the organization and
	// the domain. Enqueued by POST /orgs and by a DNS verification.
	JobFoldInSweep = "org.fold_in_sweep"
	// JobPendingMembersDigest mails each organization's admins the pending
	// members they have not been told about. The worker role enqueues it
	// on its period (config orgs.pendingDigestEvery, a day by default),
	// and the sweep enqueues it once when it folded somebody in, so a new
	// organization's admins hear at once.
	JobPendingMembersDigest = "org.pending_members_digest"
)

type foldInSweepArgs struct {
	OrgID  uuid.UUID `json:"orgId"`
	Domain string    `json:"domain"`
}

// pendingDigestArgs names one organization, or none for every one.
type pendingDigestArgs struct {
	OrgID *uuid.UUID `json:"orgId,omitempty"`
}

// registerFoldIn wires the two jobs onto a queue worker.
func (s *Server) registerFoldIn(q queue.Client) {
	if q == nil {
		return
	}
	q.Register(JobFoldInSweep, s.runFoldInSweep)
	q.Register(JobPendingMembersDigest, s.runPendingMembersDigest)
}

// foldInAtSignIn is the step beside syncPlatformStaff: keyed on the
// token's fresh email and its verified assertion, it makes the person a
// pending member of the organization at their domain, once. A failure is
// logged and the sign-in goes on — the fold-in is never a reason a person
// cannot sign in.
func (s *Server) foldInAtSignIn(r *http.Request, userID uuid.UUID, id *social.Identity) {
	if s.reg == nil {
		return
	}
	actor := auditEvent(r, audit.ActionOrgMemberPending)
	actor.Actor, actor.ActorKind = userID, audit.ActorUser
	res, err := s.reg.FoldIn(r.Context(), registry.FoldInRequest{
		UserID: userID, Email: id.Email, EmailVerified: id.EmailVerified, Actor: actor,
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "social login: fold-in", "err", err, "user", userID)
		return
	}
	if res.Fired {
		// The audit row's mirror line is the signal (audit.org.member_pending);
		// this is narration for the sign-in's own trace.
		s.log.InfoContext(r.Context(), "fold-in: pending member", "org", res.OrgHandle, "user", userID)
	}
}

// enqueueFoldInSweep asks the worker to fold in the accounts at a domain
// the organization has just gained. Without a queue (a server role with
// no worker, or a test) the sweep is the caller's to run: RunFoldInSweep.
func (s *Server) enqueueFoldInSweep(ctx context.Context, orgID uuid.UUID, domain string) {
	if s.jobs == nil || domain == "" {
		return
	}
	if _, err := s.jobs.Enqueue(ctx, JobFoldInSweep, "core", foldInSweepArgs{OrgID: orgID, Domain: domain}); err != nil {
		s.log.ErrorContext(ctx, "enqueue fold-in sweep", "org", orgID, "err", err)
	}
}

func (s *Server) runFoldInSweep(ctx context.Context, job queue.Job) error {
	var args foldInSweepArgs
	if err := json.Unmarshal(job.Args, &args); err != nil {
		return nil
	}
	n, err := s.RunFoldInSweep(ctx, args.OrgID, args.Domain)
	if err != nil {
		return err
	}
	// This organization's admins hear at once; the other organizations'
	// wait for the daily run.
	if n > 0 && s.jobs != nil {
		if _, err := s.jobs.Enqueue(ctx, JobPendingMembersDigest, "core", pendingDigestArgs{OrgID: &args.OrgID}); err != nil {
			s.log.ErrorContext(ctx, "enqueue pending members digest", "org", args.OrgID, "err", err)
		}
	}
	return nil
}

// RunFoldInSweep folds in every account already known at the domain and
// reports how many. Exported for the tests and for an operator's hand-run.
func (s *Server) RunFoldInSweep(ctx context.Context, orgID uuid.UUID, domain string) (int, error) {
	if s.reg == nil {
		return 0, nil
	}
	n, err := s.reg.FoldInSweep(ctx, orgID, domain)
	if err != nil {
		return n, err
	}
	if n > 0 {
		s.log.InfoContext(ctx, "fold-in sweep", "org", orgID, "domain", domain, "folded", n)
	}
	return n, nil
}

func (s *Server) runPendingMembersDigest(ctx context.Context, job queue.Job) error {
	var args pendingDigestArgs
	_ = json.Unmarshal(job.Args, &args)
	only := uuid.Nil
	if args.OrgID != nil {
		only = *args.OrgID
	}
	_, err := s.RunPendingMembersDigest(ctx, only)
	return err
}

// RunPendingMembersDigest mails each organization's active admins — or
// the one organization's, when only is not Nil — the pending members
// nobody has told them about: one mail per admin per organization naming
// them all, whichever door they came through. Each organization is done
// in a transaction under its row lock, so two runs at once (several
// worker replicas each tick) cannot both name the same people. The mail
// goes through the notifier under the verified-address rule and
// the admin's orgInvites preference, the way the access request does: the
// digest is the invitation flow seen from the admin's side. The members
// are marked told when at least one admin was written to, or when no
// admin can be — the members are on the console regardless, and an
// unreachable admin is not a reason to try daily forever; a delivery that
// failed leaves them unmarked for the next run. Reports how many
// organizations were mailed. Exported for the tests and for an operator's
// hand-run.
func (s *Server) RunPendingMembersDigest(ctx context.Context, only uuid.UUID) (int, error) {
	if s.st == nil {
		return 0, nil
	}
	var filter *uuid.UUID
	if only != uuid.Nil {
		filter = &only
	}
	orgs, err := s.q().ListOrgsWithUnnotifiedPending(ctx, filter)
	if err != nil {
		return 0, err
	}
	mailedOrgs := 0
	var first error
	for _, org := range orgs {
		mailed, err := s.digestOrg(ctx, org.ID, org.Handle, org.DisplayName)
		if err != nil {
			s.log.ErrorContext(ctx, "pending members digest", "org", org.Handle, "err", err)
			if first == nil {
				first = err
			}
			continue
		}
		if mailed {
			mailedOrgs++
		}
	}
	return mailedOrgs, first
}

// digestOrg is one organization's digest: under its row lock, the
// members no digest has named, the mail to each admin who can be written
// to, and the mark. Reports whether anybody was mailed.
func (s *Server) digestOrg(ctx context.Context, orgID uuid.UUID, handle, displayName string) (bool, error) {
	mailed := false
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if err := q.LockOrg(ctx, orgID); err != nil {
			return err
		}
		rows, err := q.ListPendingMembersUnnotified(ctx, orgID)
		if err != nil || len(rows) == 0 {
			return err
		}
		members := make([]notify.PendingMember, 0, len(rows))
		userIDs := make([]uuid.UUID, 0, len(rows))
		for _, row := range rows {
			members = append(members, notify.PendingMember{
				Handle: row.Handle, Email: row.Email, Via: string(registry.DoorOf(row.ViaScim, row.ViaDomain)), Since: row.CreatedAt,
			})
			userIDs = append(userIDs, row.UserID)
		}
		sent, eligible := 0, 0
		s.forEachMailableAdmin(ctx, q, orgID, func(email string) {
			eligible++
			if s.notifier == nil {
				return
			}
			if err := s.notifier.OrgPendingMembers(ctx, notify.PendingMembersNotice{
				ToEmail: email, Org: handle, OrgDisplayName: displayName,
				Members: members, ConsoleURL: s.paths.orgConsoleURL(handle),
			}); err != nil {
				s.log.ErrorContext(ctx, "pending members digest mail", "org", orgID, "err", err)
				return
			}
			sent++
		})
		mailed = sent > 0
		if sent == 0 && eligible > 0 {
			return nil // every delivery failed: the next run tries again
		}
		_, err = q.MarkPendingMembersNotified(ctx, storegen.MarkPendingMembersNotifiedParams{OrgID: orgID, UserIds: userIDs})
		return err
	})
	return mailed, err
}

// forEachMailableAdmin calls fn with the address of each of the
// organization's active admins that notify.AllowsEmail admits — a
// verified address and the orgInvites preference, since what
// reaches an admin about who wants in is the invitation flow seen from
// their side. The access request and the pending members digest share it.
func (s *Server) forEachMailableAdmin(ctx context.Context, q *storegen.Queries, orgID uuid.UUID, fn func(email string)) {
	admins, err := q.ListOrgAdminsForMail(ctx, orgID)
	if err != nil {
		s.log.ErrorContext(ctx, "org admins for mail", "org", orgID, "err", err)
		return
	}
	for _, a := range admins {
		if !notify.AllowsEmail(ctx, q, s.log, a.ID, notify.KindOrgInvite) {
			continue
		}
		fn(a.Email)
	}
}

// pendingOrgOf is GET /user's pendingOrg: the organization the person is
// waiting to be approved by, or nil.
func (s *Server) pendingOrgOf(ctx context.Context, userID uuid.UUID) *PendingOrg {
	row, err := s.q().GetUserPendingOrg(ctx, userID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.log.ErrorContext(ctx, "pending org", "user", userID, "err", err)
		}
		return nil
	}
	return &PendingOrg{Handle: row.Handle, DisplayName: row.DisplayName, Via: PendingOrgVia(registry.DoorOf(row.ViaScim, row.ViaDomain))}
}

// PendingDigestPeriod is how often the worker enqueues the digest: the
// configured period, or a day when the configuration names none.
func PendingDigestPeriod(cfg config.Config) time.Duration {
	if cfg.Orgs.PendingDigestEvery > 0 {
		return cfg.Orgs.PendingDigestEvery
	}
	return 24 * time.Hour
}
