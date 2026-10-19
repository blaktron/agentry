package registry

// The registry's controls that answer without a database: what admission
// may refuse, which submissions skip the pipeline, the sentences an
// organization's state and a refusal are reported in, the seat count, the
// door a membership came through, the run modes an agent may carry and the
// entitlement subject a quota is read for.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
)

type fakeAdmitter struct {
	ticket   Ticket
	refusal  *Refusal
	err      error
	voidErr  error
	admitted []Admission
	voided   []Ticket
}

func (f *fakeAdmitter) Admit(_ context.Context, req Admission) (Ticket, *Refusal, error) {
	f.admitted = append(f.admitted, req)
	return f.ticket, f.refusal, f.err
}

func (f *fakeAdmitter) Void(_ context.Context, t Ticket) error {
	f.voided = append(f.voided, t)
	return f.voidErr
}

// A registry with no Admitter admits everything and has nothing to void; one
// with an Admitter carries its ticket, turns its refusal into an error that
// holds the refusal whole, and fails closed, naming ErrAdmissionUnavailable,
// when it cannot answer. A ticket is voided only when there is both an
// Admitter and a ticket, and a failed void is logged, not returned.
func TestAdmissionFailsClosedAndCarriesTheAdmittersAnswer(t *testing.T) {
	ctx := t.Context()
	req := Admission{Kind: AdmissionKindVersionSubmit, Visibility: "private", Source: "cli-upload"}

	none := &Service{}
	if none.HasAdmitter() {
		t.Error("a service with no Admitter says it has one")
	}
	if tk, err := none.admit(ctx, req); err != nil || tk != (Ticket{}) {
		t.Errorf("no Admitter: admit = %+v, %v; want an empty ticket and no error", tk, err)
	}
	none.void(ctx, Ticket{ID: "t-0"}) // nothing to ask: must not panic

	ok := &fakeAdmitter{ticket: Ticket{ID: "t-1"}}
	s := &Service{}
	s.SetAdmitter(ok)
	if !s.HasAdmitter() {
		t.Error("SetAdmitter did not wire the Admitter")
	}
	if tk, err := s.admit(ctx, req); err != nil || tk.ID != "t-1" {
		t.Errorf("admit = %+v, %v; want ticket t-1", tk, err)
	}
	if len(ok.admitted) != 1 || ok.admitted[0].Kind != AdmissionKindVersionSubmit || ok.admitted[0].Source != "cli-upload" {
		t.Errorf("the Admitter was asked %+v", ok.admitted)
	}
	s.SetAdmitter(nil)
	if s.HasAdmitter() {
		t.Error("SetAdmitter(nil) left an Admitter wired")
	}

	refusal := Refusal{Status: 402, Slug: "credits-spent", Title: "No credits", Detail: "The allowance is spent.", Fields: map[string]any{"resetsAt": "2026-11-01"}}
	refuse := &fakeAdmitter{ticket: Ticket{ID: "ignored"}, refusal: &refusal}
	s.SetAdmitter(refuse)
	tk, err := s.admit(ctx, req)
	var refused *ErrAdmissionRefused
	if !errors.As(err, &refused) || tk != (Ticket{}) {
		t.Fatalf("admit = %+v, %v; want an empty ticket and *ErrAdmissionRefused", tk, err)
	}
	if refused.Refusal.Status != 402 || refused.Refusal.Slug != "credits-spent" || refused.Refusal.Title != "No credits" ||
		refused.Refusal.Detail != "The allowance is spent." || refused.Refusal.Fields["resetsAt"] != "2026-11-01" {
		t.Errorf("the refusal came back as %+v", refused.Refusal)
	}
	if got := err.Error(); got != "registry: submission refused: credits-spent" {
		t.Errorf("the refusal reads %q", got)
	}

	down := &fakeAdmitter{err: errors.New("billing is down")}
	s.SetAdmitter(down)
	tk, err = s.admit(ctx, req)
	if !errors.Is(err, ErrAdmissionUnavailable) || !strings.Contains(err.Error(), "billing is down") || tk != (Ticket{}) {
		t.Errorf("admit with an Admitter that fails = %+v, %v; want ErrAdmissionUnavailable naming the cause", tk, err)
	}
	var asRefusal *ErrAdmissionRefused
	if errors.As(err, &asRefusal) {
		t.Error("an Admitter that could not answer was read as a refusal")
	}

	var logged bytes.Buffer
	voiding := &fakeAdmitter{voidErr: errors.New("void failed")}
	s.SetAdmitter(voiding)
	s.SetLogger(slog.New(slog.NewTextHandler(&logged, nil)))
	s.void(ctx, Ticket{})
	if len(voiding.voided) != 0 {
		t.Errorf("an empty ticket was voided: %v", voiding.voided)
	}
	s.void(ctx, Ticket{ID: "t-9"})
	if len(voiding.voided) != 1 || voiding.voided[0].ID != "t-9" {
		t.Errorf("voided %v, want t-9", voiding.voided)
	}
	if out := logged.String(); !strings.Contains(out, "admission void failed") || !strings.Contains(out, "t-9") || !strings.Contains(out, "void failed") {
		t.Errorf("a failed void was not logged with its ticket and cause: %q", out)
	}
}

type fakeResolver struct {
	features entitlements.Features
	err      error
	asked    []entitlements.Subject
}

func (f *fakeResolver) Limits(context.Context, entitlements.Subject) (entitlements.Limits, error) {
	return entitlements.Limits{}, f.err
}

func (f *fakeResolver) Features(_ context.Context, s entitlements.Subject) (entitlements.Features, error) {
	f.asked = append(f.asked, s)
	return f.features, f.err
}

// A submission skips the scan only for an agent that has the administrator's
// flag, is private and belongs to an organization, and only when the
// organization's tier includes unscanned agents; a resolver that cannot
// answer means "scan it". The tier is read for the organization.
func TestSkipsPipelineOnlyForAFlaggedPrivateOrgAgentOnATierThatAllowsIt(t *testing.T) {
	org := uuid.New()
	agent := func(mod func(a *Agent)) Agent {
		a := Agent{PipelineSkip: true, Visibility: "private", NamespaceKind: "org", NamespaceID: org, Namespace: "acme", Name: "x"}
		mod(&a)
		return a
	}
	allows := &fakeResolver{features: entitlements.Features{UnscannedAgents: true}}
	denies := &fakeResolver{features: entitlements.Features{}}
	s := &Service{}
	s.SetEntitlements(allows)
	for _, tc := range []struct {
		name string
		a    Agent
		want bool
	}{
		{"flagged, private, organization's", agent(func(*Agent) {}), true},
		{"not flagged", agent(func(a *Agent) { a.PipelineSkip = false }), false},
		{"public", agent(func(a *Agent) { a.Visibility = "public" }), false},
		{"personal namespace", agent(func(a *Agent) { a.NamespaceKind = "user" }), false},
	} {
		if got := s.skipsPipeline(t.Context(), tc.a); got != tc.want {
			t.Errorf("%s: skipsPipeline = %v, want %v", tc.name, got, tc.want)
		}
	}
	if len(allows.asked) != 1 || allows.asked[0] != entitlements.ForOrg(org) {
		t.Errorf("the tier was read for %+v, want the organization alone", allows.asked)
	}

	s.SetEntitlements(denies)
	if s.skipsPipeline(t.Context(), agent(func(*Agent) {})) {
		t.Error("an agent skipped the scan on a tier without unscanned agents")
	}
	var logged bytes.Buffer
	s.SetLogger(slog.New(slog.NewTextHandler(&logged, nil)))
	s.SetEntitlements(&fakeResolver{features: entitlements.Features{UnscannedAgents: true}, err: errors.New("resolver down")})
	if s.skipsPipeline(t.Context(), agent(func(*Agent) {})) {
		t.Error("an agent skipped the scan although the tier could not be read")
	}
	if out := logged.String(); !strings.Contains(out, "acme/x") || !strings.Contains(out, "resolver down") {
		t.Errorf("the unreadable tier was not logged with the agent and the cause: %q", out)
	}
}

// The quota subject of an agent is its organization for an organization's
// namespace and the user for a personal one, by the namespace's id; a service
// with no resolver wired reads the shipped defaults, never "no limits".
func TestQuotaSubjectIsTheNamespaceThatOwnsTheAgent(t *testing.T) {
	ns, id := uuid.New(), uuid.New()
	if got := subjectFor(Agent{ID: id, NamespaceKind: "org", NamespaceID: ns}); got != entitlements.ForOrg(ns) {
		t.Errorf("an organization's agent: %+v, want the organization", got)
	}
	if got := subjectFor(Agent{ID: id, NamespaceKind: "user", NamespaceID: ns}); got != entitlements.ForUser(ns) {
		t.Errorf("a personal agent: %+v, want the user", got)
	}

	unwired := &Service{}
	want, err := entitlements.Default().Limits(t.Context(), entitlements.ForUser(ns))
	if err != nil {
		t.Fatal(err)
	}
	got, err := unwired.Entitlements().Limits(t.Context(), entitlements.ForUser(ns))
	if err != nil || got != want || got.AgentsPerNamespace == 0 || got.VersionsPerDay == 0 {
		t.Errorf("an unwired service answers %+v, %v; want the shipped limits %+v", got, err, want)
	}
	custom := &fakeResolver{}
	unwired.SetEntitlements(custom)
	if unwired.Entitlements() != entitlements.Resolver(custom) {
		t.Error("the wired resolver is not the one used")
	}
}

// An organization is reported as it is: being decommissioned (read-only),
// decommissioned, or suspended, which is also what any other state reads as;
// only a decommissioning organization still answers its members.
func TestOrgGateErrorSaysWhatTheOrganizationIs(t *testing.T) {
	for _, tc := range []struct {
		state  string
		msg    string
		absent bool
	}{
		{OrgStateDecommissioning, "registry: this organization is being decommissioned and is read-only", false},
		{OrgStateDecommissioned, "registry: this organization has been decommissioned", true},
		{OrgStateSuspended, "registry: this organization is suspended", true},
		{"unheard-of", "registry: this organization is suspended", true},
	} {
		e := &OrgGateError{State: tc.state}
		if e.Error() != tc.msg {
			t.Errorf("%s: %q, want %q", tc.state, e.Error(), tc.msg)
		}
		if e.Absent() != tc.absent {
			t.Errorf("%s: Absent = %v, want %v", tc.state, e.Absent(), tc.absent)
		}
	}
	// The state names are what the database stores.
	if OrgStateActive != "active" || OrgStateSuspended != "suspended" || OrgStateDecommissioning != "decommissioning" || OrgStateDecommissioned != "decommissioned" {
		t.Error("an organization state changed its stored name")
	}
	// A personal namespace has no state and always passes the gate.
	if err := (&Service{}).OrgGateFor(t.Context(), Agent{NamespaceKind: "user", NamespaceID: uuid.New()}, auth.ActAgentRead); err != nil {
		t.Errorf("a personal namespace was gated: %v", err)
	}
}

// Seats spent are active members plus open invitations; a pending member
// holds none. A membership made by provisioning names the IdP's door before
// the domain's, and one an admin granted names none.
func TestSeatsAreSpentByMembersAndInvitationsAndDoorsAreNamed(t *testing.T) {
	for _, tc := range []struct {
		s    Seats
		want int64
	}{
		{Seats{}, 0},
		{Seats{Used: 3}, 3},
		{Seats{Invited: 2}, 2},
		{Seats{Used: 3, Invited: 2, Pending: 7, Max: 5}, 5},
	} {
		if got := tc.s.Taken(); got != tc.want {
			t.Errorf("%+v: Taken = %d, want %d", tc.s, got, tc.want)
		}
	}
	for _, tc := range []struct {
		scim, domain bool
		want         MembershipVia
	}{
		{false, false, ""},
		{true, false, ViaSCIM},
		{false, true, ViaDomain},
		{true, true, ViaSCIM},
	} {
		if got := DoorOf(tc.scim, tc.domain); got != tc.want {
			t.Errorf("DoorOf(%v, %v) = %q, want %q", tc.scim, tc.domain, got, tc.want)
		}
	}
	for via, name := range map[MembershipVia]string{ViaInvitation: "invitation", ViaApproval: "approval", ViaRoleChange: "role", ViaSCIM: "scim", ViaDomain: "domain"} {
		if string(via) != name {
			t.Errorf("the door %q is recorded as %q", name, via)
		}
	}
}

// The sentences the API reads out: every validation issue in order, the
// count of unscanned versions still standing, and the two constraint
// violations told apart by code and by constraint name, through a wrapping.
func TestRefusalSentencesAndConstraintViolations(t *testing.T) {
	v := &ErrValidation{Issues: []error{errors.New("name is missing"), errors.New("license is unknown")}}
	if got := v.Error(); got != "registry: validation failed: name is missing; license is unknown" {
		t.Errorf("ErrValidation reads %q", got)
	}
	if got := (&ErrValidation{}).Error(); got != "registry: validation failed: " {
		t.Errorf("an empty ErrValidation reads %q", got)
	}
	if got := (&UnscannedStandingError{N: 3}).Error(); got != "registry: 3 unscanned versions stand" {
		t.Errorf("UnscannedStandingError reads %q", got)
	}

	oneOrg := &pgconn.PgError{Code: "23505", ConstraintName: "memberships_one_active_per_user"}
	otherUnique := &pgconn.PgError{Code: "23505", ConstraintName: "agents_name_key"}
	otherCode := &pgconn.PgError{Code: "23503", ConstraintName: "memberships_one_active_per_user"}
	for _, tc := range []struct {
		name         string
		err          error
		unique, once bool
	}{
		{"the one-organization constraint", oneOrg, true, true},
		{"wrapped", fmt.Errorf("insert: %w", oneOrg), true, true},
		{"another unique constraint", otherUnique, true, false},
		{"another violation on that name", otherCode, false, false},
		{"not a database error", errors.New("unique"), false, false},
		{"nil", nil, false, false},
	} {
		if got := isUniqueViolationErr(tc.err); got != tc.unique {
			t.Errorf("%s: isUniqueViolationErr = %v, want %v", tc.name, got, tc.unique)
		}
		if got := isOneOrgPerPersonViolation(tc.err); got != tc.once {
			t.Errorf("%s: isOneOrgPerPersonViolation = %v, want %v", tc.name, got, tc.once)
		}
	}
}

// An agent's run modes are autonomous when none is given, each mode once in
// the order given, and only the two the vocabulary has; anything else is a
// denial that names it.
func TestNormalizeModesDefaultsDeduplicatesAndRefusesUnknownModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"none given", nil, "autonomous"},
		{"empty", []string{}, "autonomous"},
		{"interactive alone", []string{"interactive"}, "interactive"},
		{"persistent alone", []string{"persistent"}, "persistent"},
		{"all three", []string{"autonomous", "interactive", "persistent"}, "autonomous,interactive,persistent"},
		{"both, once each", []string{"interactive", "autonomous"}, "interactive,autonomous"},
		{"repeats dropped, order kept", []string{"interactive", "autonomous", "interactive", "autonomous"}, "interactive,autonomous"},
	} {
		got, err := normalizeModes(tc.in)
		if err != nil || strings.Join(got, ",") != tc.want {
			t.Errorf("%s: %v, %v; want %s", tc.name, got, err, tc.want)
		}
	}
	for _, bad := range []string{"batch", "", "Autonomous", "Persistent"} {
		got, err := normalizeModes([]string{"autonomous", bad})
		if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), fmt.Sprintf("unknown mode %q", bad)) || got != nil {
			t.Errorf("mode %q: %v, %v; want ErrDenied naming it", bad, got, err)
		}
	}
}

// A fork's first version is refused for good by the gates, the quotas and
// admission, and the fork's readers are told why in a sentence of the
// refusal's own words; an error that is not a refusal is retried.
func TestForkRefusalsAreRecognisedAndPutInWords(t *testing.T) {
	refusals := []error{
		&ErrValidation{Issues: []error{errors.New("x")}},
		&ErrAdmissionRefused{Refusal: Refusal{Slug: "s"}},
		fmt.Errorf("%w: the private-agent cap is reached", ErrDenied),
		ErrRetired,
		ErrTwoFactorRequired,
		ErrNotFound,
		fmt.Errorf("submit: %w", auth.ErrUnauthorized),
	}
	for _, err := range refusals {
		if !isForkSubmitRefusal(err) {
			t.Errorf("%v is a refusal and was not recognised", err)
		}
	}
	for _, err := range []error{nil, ErrAdmissionUnavailable, errors.New("disk full"), context.DeadlineExceeded, ErrNotRetired} {
		if isForkSubmitRefusal(err) {
			t.Errorf("%v is not a refusal and was recognised as one", err)
		}
	}

	const fallback = "Agentry could not take it."
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"admission with its detail", &ErrAdmissionRefused{Refusal: Refusal{Slug: "credits-spent", Detail: "your credits are spent"}}, "Your credits are spent."},
		{"admission without a detail", &ErrAdmissionRefused{Refusal: Refusal{Slug: "credits-spent"}}, fallback},
		{"validation issues", &ErrValidation{Issues: []error{errors.New("name is missing"), errors.New("license is unknown")}}, "Name is missing; license is unknown."},
		{"validation without issues", &ErrValidation{}, "No reason was given."},
		{"retired, wrapped", fmt.Errorf("submit: %w", ErrRetired), "The fork was retired before its first version."},
		{"two-factor", ErrTwoFactorRequired, "This needs two-factor authentication on the account that forked."},
		{"denied with its sentence", fmt.Errorf("%w: the private-agent cap is reached", ErrDenied), "The private-agent cap is reached."},
		{"not found", ErrNotFound, fallback},
		{"anything else", errors.New("disk full"), fallback},
	} {
		if got := refusalWords(tc.err); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}

	for _, tc := range []struct{ in, want string }{
		{"", "No reason was given."},
		{"   ", "No reason was given."},
		{"done", "Done."},
		{"  padded  ", "Padded."},
		{"stopped.", "Stopped."},
		{"Already fine.", "Already fine."},
		{"a; b", "A; b."},
	} {
		if got := sentenceOf(tc.in); got != tc.want {
			t.Errorf("sentenceOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := (&forkRefusal{detail: "the copy cannot succeed"}).Error(); got != "the copy cannot succeed" {
		t.Errorf("forkRefusal reads %q", got)
	}
}
