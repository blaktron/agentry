package api

// The directory's mirror of platform staff (agentry#598, DB2 of the 1.0
// plan's Dashboards decisions). Platform staff is the registry's word: the
// platform_staff flag, which the staff organization's rule sets and nothing
// else does (agentry#556, registry/staff.go). An application that signs in
// through the directory and should admit staff alone, the log stack's
// OpenSearch Dashboards first, can read only what the directory's tokens
// carry. So the registry keeps one directory group, auth.idpStaffMirrorGroup,
// equal to its platform staff: for every active account with the flag and a
// verified address, the directory account it is linked to, and nobody else.
// The link is the registry's own record of a directory sign-in (identities,
// "authentik:<sub>"), and under the registry provider's sub_mode
// hashed_user_id the sub is the directory account's uid. An account is found
// by address and added only when its uid is that link: authentik does not
// keep addresses unique, and a second account at a staff member's address
// gains nothing. Staff who never signed in through the directory have no
// link and are not mirrored until they do. The directory never feeds the
// group back: it is a mirror, never a source, and the retired DEV-083 group
// stays retired.
//
// One job does all of it, idempotently: read the flagged set, read the
// group, add who is missing and remove who should not be there, each change
// audited as directory.staff_mirror. It runs a few seconds after any staff
// change (registry.Service's staff hook), every staffMirrorInterval, and
// soon after the server starts. A change is therefore mirrored within
// seconds when the directory answers, and within the interval when it did
// not, which bounds how long a removed member keeps the group. A directory
// session or a Dashboards session already open is not ended by it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/queue"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

const (
	// jobStaffMirror is the periodic reconcile, which schedules its
	// successor; jobStaffMirrorNudge is a one-off run after a staff change,
	// which does not.
	jobStaffMirror      = "directory.staff_mirror"
	jobStaffMirrorNudge = "directory.staff_mirror_nudge"
	// staffMirrorInterval bounds how stale the mirror can be when a nudged
	// run could not reach the directory.
	staffMirrorInterval = 10 * time.Minute
	// staffMirrorNudgeDelay lets the transaction that changed the flag
	// commit before the run reads it.
	staffMirrorNudgeDelay = 5 * time.Second
)

// directoryGroups is what the mirror needs of the directory: its group's
// members, and adding or removing one account. Accounts are the directory's
// own (authentik's user pk), found by exact address.
type directoryGroups interface {
	// GroupMembers returns the group's id and members, creating the group
	// when it does not exist.
	GroupMembers(ctx context.Context, group string) (groupID string, members []directoryAccount, err error)
	// AccountsByEmail returns the directory accounts at exactly this
	// address (case-blind), service accounts left out.
	AccountsByEmail(ctx context.Context, email string) ([]directoryAccount, error)
	SetMember(ctx context.Context, groupID string, accountPK int, member bool) error
}

// directoryAccount is one directory account as the mirror sees it: its pk,
// its address, and its uid, the sub the registry's provider issues for it.
type directoryAccount struct {
	PK     int
	Email  string
	UID    string
	Active bool
	// HasPassword is the directory's own record of whether the account has
	// a password (agentry#706); nil when it has none yet.
	HasPassword *bool
}

// StaffMirrorOutcome is what one run did, for its log line and the tests.
type StaffMirrorOutcome struct {
	Added, Removed int
	// NoAccount counts flagged staff the mirror cannot place: no directory
	// sign-in linked yet, or no directory account at their address carrying
	// the linked uid. Nothing to add until there is.
	NoAccount int
}

// ReconcileStaffMirror makes the directory's staff mirror group equal to
// the registry's platform staff, and audits every change. A run with no
// mirror configured does nothing.
func (s *Server) ReconcileStaffMirror(ctx context.Context) (StaffMirrorOutcome, error) {
	var out StaffMirrorOutcome
	group := s.cfg.Auth.IdPStaffMirrorGroup
	if group == "" || s.dirGroups == nil || s.st == nil {
		return out, nil
	}
	// One run at a time across replicas: two runs would audit the same
	// change twice. The transaction holds the lock (and one connection)
	// while the directory calls run; each change's audit row is written on
	// its own, committed as the change is made, so a run that fails midway
	// keeps the record of what it already changed in the directory, which a
	// rollback would otherwise lose for good (the next run sees nothing left
	// to do).
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		out = StaffMirrorOutcome{}
		if err := q.LockKey(ctx, "staff-mirror"); err != nil {
			return err
		}
		rows, err := q.ListStaffMirrorAccounts(ctx)
		if err != nil {
			return err
		}
		// want maps each linked directory uid to its staff account.
		type staffLink struct {
			user  uuid.UUID
			email string
		}
		want := make(map[string]staffLink, len(rows))
		for _, r := range rows {
			if r.DirectorySubject == "" {
				out.NoAccount++ // staff with no directory sign-in linked
				continue
			}
			want[r.DirectorySubject] = staffLink{user: r.ID, email: r.Email}
		}
		groupID, members, err := s.dirGroups.GroupMembers(ctx, group)
		if err != nil {
			return fmt.Errorf("read the directory group %s: %w", group, err)
		}
		have := make(map[string]bool, len(members))
		for _, m := range members {
			// An inactive directory account (enrolled and never confirmed,
			// or switched off) is not kept, whoever it is linked to.
			if _, ok := want[m.UID]; ok && m.UID != "" && m.Active {
				have[m.UID] = true
				continue
			}
			// In the group and not a staff account's linked directory
			// account (removed, suspended, no longer at the domain, a
			// second account at a staff address, or added by hand): out.
			if err := s.dirGroups.SetMember(ctx, groupID, m.PK, false); err != nil {
				return fmt.Errorf("remove directory account %d from %s: %w", m.PK, group, err)
			}
			out.Removed++
			if err := s.auditStaffMirror(ctx, group, s.registryAccountAt(ctx, q, strings.ToLower(m.Email)), m.PK, false); err != nil {
				return err
			}
		}
		for uid, link := range want {
			if have[uid] {
				continue
			}
			accounts, err := s.dirGroups.AccountsByEmail(ctx, link.email)
			if err != nil {
				return fmt.Errorf("find the directory account for a staff address: %w", err)
			}
			var found *directoryAccount
			for i := range accounts {
				if accounts[i].UID == uid {
					found = &accounts[i]
				}
			}
			if found == nil {
				out.NoAccount++ // the linked account is not at this address
				continue
			}
			if err := s.dirGroups.SetMember(ctx, groupID, found.PK, true); err != nil {
				return fmt.Errorf("add directory account %d to %s: %w", found.PK, group, err)
			}
			out.Added++
			if err := s.auditStaffMirror(ctx, group, link.user, found.PK, true); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// auditStaffMirror records one change to the mirror. The target is the
// registry account at the address when there is one (uuid.Nil otherwise: a
// directory account added to the group by hand); the address itself is not
// written into the detail, which the audit log keeps for its retention.
func (s *Server) auditStaffMirror(ctx context.Context, group string, userID uuid.UUID, directoryPK int, member bool) error {
	e := audit.Event{
		Action: audit.ActionDirectoryStaffMirror, ActorKind: audit.ActorSystem,
		Detail: map[string]any{"group": group, "member": member, "directoryAccount": directoryPK},
	}
	if userID != uuid.Nil {
		e.TargetKind, e.TargetID = "user", userID
	}
	return s.auditW.Write(ctx, s.q(), e)
}

// registryAccountAt is the registry account at an address, for the audit
// row of a removal; uuid.Nil when none is.
func (s *Server) registryAccountAt(ctx context.Context, q *storegen.Queries, email string) uuid.UUID {
	if u, err := q.GetUserByEmail(ctx, email); err == nil {
		return u.ID
	}
	return uuid.Nil
}

// registerStaffMirror wires the mirror's jobs on the worker, and seeds the
// periodic run and a run shortly after start. The staff hook that nudges
// the mirror is installed at construction, on every role (server.go). With
// no mirror configured the handlers are still registered, so a job queued
// before the key was removed drains as a no-op.
func (s *Server) registerStaffMirror(q queue.Client) {
	if q == nil {
		return
	}
	q.Register(jobStaffMirror, s.runStaffMirror)
	q.Register(jobStaffMirrorNudge, s.runStaffMirrorNudge)
	if s.cfg.Auth.IdPStaffMirrorGroup == "" || s.st == nil || s.dirGroups == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.nudgeStaffMirror()
	pending, err := s.q().CountPendingJobsOfKind(ctx, jobStaffMirror)
	if err != nil {
		s.log.WarnContext(ctx, "staff mirror: could not check for a pending run", "err", err)
		return
	}
	if pending > 0 {
		return
	}
	if _, err := q.Enqueue(ctx, jobStaffMirror, "core", struct{}{},
		queue.WithDelay(staffMirrorInterval), queue.WithMaxAttempts(3)); err != nil {
		s.log.WarnContext(ctx, "staff mirror: seed enqueue", "err", err)
	}
}

// nudgeStaffMirror queues a one-off run a few seconds out. It is called
// from inside the transaction that changed a flag, so the delay lets that
// transaction commit first; a run that still reads the old state is put
// right by the next periodic one. Best effort: a failed enqueue is logged.
func (s *Server) nudgeStaffMirror() {
	if s.jobs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.jobs.Enqueue(ctx, jobStaffMirrorNudge, "core", struct{}{},
		queue.WithDelay(staffMirrorNudgeDelay), queue.WithMaxAttempts(5)); err != nil {
		s.log.WarnContext(ctx, "staff mirror: nudge enqueue", "err", err)
	}
}

func (s *Server) runStaffMirror(ctx context.Context, _ queue.Job) error {
	// Reschedule first, so a run that fails still leaves a successor.
	defer s.scheduleNextStaffMirror(ctx)
	return s.logStaffMirror(ctx)
}

func (s *Server) runStaffMirrorNudge(ctx context.Context, _ queue.Job) error {
	return s.logStaffMirror(ctx)
}

func (s *Server) logStaffMirror(ctx context.Context) error {
	out, err := s.ReconcileStaffMirror(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "staff mirror: run failed", "group", s.cfg.Auth.IdPStaffMirrorGroup, "err", err)
		return err
	}
	if out.Added+out.Removed > 0 {
		s.log.InfoContext(ctx, "staff mirror: directory group updated", "group", s.cfg.Auth.IdPStaffMirrorGroup,
			"added", out.Added, "removed", out.Removed, "noDirectoryAccount", out.NoAccount)
	}
	return nil
}

func (s *Server) scheduleNextStaffMirror(ctx context.Context) {
	if s.jobs == nil || s.cfg.Auth.IdPStaffMirrorGroup == "" {
		return
	}
	if _, err := s.jobs.Enqueue(ctx, jobStaffMirror, "core", struct{}{},
		queue.WithDelay(staffMirrorInterval), queue.WithMaxAttempts(3)); err != nil {
		s.log.WarnContext(ctx, "staff mirror: reschedule", "err", err)
	}
}

// authentik's groups API, on the same admin token as erasure.

func (a *authentikEraser) doJSON(ctx context.Context, method, path string, body any, into any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := a.http.Do(req)
	if err != nil {
		// The URL can carry an address in its query: keep the method and
		// the path, drop the rest (as do does for erasure).
		var ue *url.Error
		if errors.As(err, &ue) {
			err = fmt.Errorf("%s %s: %w", method, pathOnly(path), ue.Err)
		}
		return err
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d", method, pathOnly(path), res.StatusCode)
	}
	if into != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, into); err != nil {
			return fmt.Errorf("%s %s: %w", method, pathOnly(path), err)
		}
	}
	return nil
}

// pathOnly drops a request path's query, which can carry an address.
func pathOnly(path string) string { return strings.SplitN(path, "?", 2)[0] }

type authentikUser struct {
	PK         int    `json:"pk"`
	UID        string `json:"uid"`
	Email      string `json:"email"`
	Type       string `json:"type"`
	IsActive   bool   `json:"is_active"`
	Attributes struct {
		// Kept by the account-flows blueprint's agentry-record-has-password
		// policy (agentry#706); absent on an account that has not signed in
		// or written a password since. Raw, so a value someone edited into
		// the wrong type reads as unknown instead of failing the lookup the
		// staff mirror shares.
		HasPassword json.RawMessage `json:"agentry_has_password"`
	} `json:"attributes"`
}

type authentikPage[T any] struct {
	Pagination struct {
		Next int `json:"next"`
	} `json:"pagination"`
	Results []T `json:"results"`
}

func (a *authentikEraser) GroupMembers(ctx context.Context, group string) (string, []directoryAccount, error) {
	var groups authentikPage[struct {
		PK   string `json:"pk"`
		Name string `json:"name"`
	}]
	if err := a.doJSON(ctx, http.MethodGet, "/api/v3/core/groups/?include_users=false&name="+url.QueryEscape(group), nil, &groups); err != nil {
		return "", nil, err
	}
	groupID := ""
	for _, g := range groups.Results {
		if g.Name == group {
			groupID = g.PK
		}
	}
	if groupID == "" {
		var created struct {
			PK string `json:"pk"`
		}
		if err := a.doJSON(ctx, http.MethodPost, "/api/v3/core/groups/", map[string]any{"name": group}, &created); err != nil {
			return "", nil, err
		}
		return created.PK, nil, nil
	}
	var members []directoryAccount
	for page := 1; page > 0; {
		var users authentikPage[authentikUser]
		path := fmt.Sprintf("/api/v3/core/users/?page_size=100&page=%d&groups_by_name=%s", page, url.QueryEscape(group))
		if err := a.doJSON(ctx, http.MethodGet, path, nil, &users); err != nil {
			return "", nil, err
		}
		for _, u := range users.Results {
			members = append(members, directoryAccount{PK: u.PK, Email: u.Email, UID: u.UID, Active: u.IsActive})
		}
		page = users.Pagination.Next
	}
	return groupID, members, nil
}

func (a *authentikEraser) AccountsByEmail(ctx context.Context, email string) ([]directoryAccount, error) {
	// authentik 2026.8's email= filter is exact and case-sensitive, so an
	// address the directory holds with capitals would never be found from
	// the registry's lower-cased one. search= is case-blind and matches
	// parts of the username, the name and the address: only exact,
	// case-blind address matches count here, and never a service account or
	// an inactive one.
	var out []directoryAccount
	for page := 1; page > 0; {
		var users authentikPage[authentikUser]
		path := fmt.Sprintf("/api/v3/core/users/?page_size=50&page=%d&search=%s", page, url.QueryEscape(email))
		if err := a.doJSON(ctx, http.MethodGet, path, nil, &users); err != nil {
			return nil, err
		}
		for _, u := range users.Results {
			if !strings.EqualFold(u.Email, email) || strings.Contains(u.Type, "service") || !u.IsActive {
				continue
			}
			out = append(out, directoryAccount{PK: u.PK, Email: u.Email, UID: u.UID, Active: true, HasPassword: jsonBool(u.Attributes.HasPassword)})
		}
		page = users.Pagination.Next
	}
	return out, nil
}

func (a *authentikEraser) SetMember(ctx context.Context, groupID string, accountPK int, member bool) error {
	op := "remove_user"
	if member {
		op = "add_user"
	}
	return a.doJSON(ctx, http.MethodPost, "/api/v3/core/groups/"+url.PathEscape(groupID)+"/"+op+"/", map[string]any{"pk": accountPK}, nil)
}

// jsonBool is a JSON true or false, and nil for anything else.
func jsonBool(raw json.RawMessage) *bool {
	var b bool
	if len(raw) == 0 || json.Unmarshal(raw, &b) != nil {
		return nil
	}
	return &b
}
