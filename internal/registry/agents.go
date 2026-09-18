// Package registry owns the agent/version domain (§2.1 L3): agent creation,
// resolution, effective-permission computation, and (from M3) the publication
// state machine.
package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/manifest"
)

// AgentNameRe is the §4.2 agent-name grammar.
var AgentNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,63}[a-z0-9])?$`)

// Namespace agent quotas come from the entitlements Resolver (§14.2, §19),
// not from constants here: an org on a larger plan raises the number without
// this package learning that plans exist.

// Service is the agent-domain service shared by the API and git layers.
// Bare repositories are NOT created here: the git layer initializes them
// lazily on first access (§13.3 — only the git role mounts repo storage).
type Service struct {
	st    *store.Store
	aud   *audit.Writer
	blobs BlobStore
	// pipeline receives submitted versions (M3 dev stub / M4 orchestrator).
	pipeline Pipeline
	// gitArchiver produces tag archives for git-tag submissions; nil on
	// roles without repo storage (SaaS api role — M7 routes via workers).
	gitArchiver GitArchiver
	// eventSink receives post-commit state transitions for webhook fan-out
	// (§9.3, M6). Set by the api layer; nil = no fan-out.
	eventSink EventSink
	// orgEventSink is the same fan-out for organization-scoped events
	// (membership.go). Set by the api layer; nil = no fan-out.
	orgEventSink OrgEventSink
	// policyGate enforces the §8.6 knobs that reject at V-validation time.
	// nil = platform baseline only (no submission-time policy rejections).
	policyGate PolicyGate
	// require2FAPublic turns on the §12.1/§19 gate for public publishes.
	require2FAPublic bool
	// ipClusterSecret keys the S8 IP-cluster hash (agentry#27); empty = off.
	ipClusterSecret []byte
	// entitlements resolves the §19 quotas (§14.2). nil = shipped defaults.
	entitlements entitlements.Resolver
	// admitter is the admission seam (admission.go); nil admits everything.
	admitter Admitter
	log      *slog.Logger
}

// PolicyGate evaluates the §8.6 policy knobs that reject a submission before
// it ever enters the state machine: blockedCapabilities, allowedLicenses and
// requireEvals. It is a seam because resolving the effective policy needs the
// scan package, which already depends on this one.
type PolicyGate interface {
	// CheckSubmission returns the blocking issues, or nil to allow.
	CheckSubmission(ctx context.Context, in PolicySubmission) []error
}

// PolicySubmission is what the policy gate judges.
type PolicySubmission struct {
	// NamespaceKind / NamespaceID select the org overlay ("org" only).
	NamespaceKind string
	NamespaceID   uuid.UUID
	// Public marks a public agent (allowedLicenses applies to those).
	Public bool
	// License is the manifest's SPDX id.
	License string
	// ManifestJSON is the canonical manifest (capability tokens).
	ManifestJSON []byte
	// Files is the workspace inventory (requireEvals looks for evals/).
	Files []manifest.FileInfo
}

// SetPolicyGate wires submission-time policy enforcement (§8.6).
func (s *Service) SetPolicyGate(g PolicyGate) { s.policyGate = g }

// SetPublicPublish2FA enables the §12.1/§19 gate: publishing to a public
// namespace requires TOTP on the submitting account.
func (s *Service) SetPublicPublish2FA(on bool) { s.require2FAPublic = on }

// SetLogger overrides the service logger (defaults to slog.Default).
func (s *Service) SetLogger(l *slog.Logger) { s.log = l }

func (s *Service) logger() *slog.Logger {
	if s.log == nil {
		return slog.Default()
	}
	return s.log
}

// EventSink receives a committed state transition so the caller can fan it out
// to webhooks (§9.3). It runs after the transition transaction commits, so a
// webhook failure never affects the state change. agentID lets the sink resolve
// the owning org; payload carries version/from/to.
type EventSink func(ctx context.Context, agentID uuid.UUID, event string, payload map[string]any)

// SetEventSink wires the post-commit transition fan-out (M6 webhooks).
func (s *Service) SetEventSink(sink EventSink) { s.eventSink = sink }

// NewService assembles the registry service. blobs may be nil for callers
// that never submit versions (the git role's read paths).
func NewService(st *store.Store, aud *audit.Writer) *Service {
	return &Service{st: st, aud: aud}
}

// SetBlobStore wires archive storage (required for submissions).
func (s *Service) SetBlobStore(b BlobStore) { s.blobs = b }

// SetEntitlements wires the §14.2 quota resolver.
func (s *Service) SetEntitlements(r entitlements.Resolver) { s.entitlements = r }

// Entitlements returns the wired resolver, or the shipped §19 defaults when
// none was set. Defaulting to the OSS resolver rather than to nil means a
// half-wired service still enforces quotas — an unwired seam must not read as
// "no limits".
func (s *Service) Entitlements() entitlements.Resolver {
	if s.entitlements == nil {
		return entitlements.Default()
	}
	return s.entitlements
}

// SetGitArchiver wires tag-archive production for git-tag submissions.
func (s *Service) SetGitArchiver(g GitArchiver) { s.gitArchiver = g }

// GitArchiver materializes the tree of a tag into a workspace directory and
// returns the peeled commit id (§6.5 step 1: git archive, never a
// working-tree checkout; export-ignore disabled — the manifest allowlist is
// the only filter).
type GitArchiver interface {
	MaterializeTag(ctx context.Context, repoID uuid.UUID, tag, dst string) (commitSHA string, err error)
}

// ErrNotFound is returned when an agent or namespace does not exist.
var ErrNotFound = errors.New("registry: not found")

// ErrDenied wraps authorization failures with domain context.
var ErrDenied = errors.New("registry: denied")

// ErrTwoFactorRequired reports the §12.1/§19 public-publish 2FA gate. It is
// distinct from ErrDenied so the API can answer 403 with an actionable
// message rather than folding it into a validation error.
var ErrTwoFactorRequired = errors.New("registry: two-factor authentication required")

// Agent is the resolved agent row with namespace context.
type Agent = storegen.GetAgentByPathRow

// Resolve loads an agent by namespace/name path.
func (s *Service) Resolve(ctx context.Context, namespace, name string) (Agent, error) {
	row, err := s.st.Queries().GetAgentByPath(ctx, storegen.GetAgentByPathParams{Handle: namespace, Name: name})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Agent{}, ErrNotFound
		}
		return Agent{}, fmt.Errorf("registry: resolve %s/%s: %w", namespace, name, err)
	}
	return row, nil
}

// EffectiveRole computes the caller's effective agent role (§12.2):
// max(namespace-derived, explicit user grant, explicit team grants).
func (s *Service) EffectiveRole(ctx context.Context, p *auth.Principal, a Agent) (auth.AgentRole, error) {
	if p == nil || p.Anonymous {
		return auth.AgentRoleNone, nil
	}
	role := auth.NamespaceDerivedAgentRole(p, a.NamespaceKind, a.NamespaceID, p.Role(a.NamespaceID))

	q := s.st.Queries()
	if g, err := q.GetAgentUserGrant(ctx, storegen.GetAgentUserGrantParams{AgentID: a.ID, UserID: p.UserID}); err == nil {
		role = auth.MaxAgentRole(role, auth.AgentRole(g))
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return auth.AgentRoleNone, fmt.Errorf("registry: user grant: %w", err)
	}
	teamRoles, err := q.ListAgentTeamGrantsForUser(ctx, storegen.ListAgentTeamGrantsForUserParams{AgentID: a.ID, UserID: p.UserID})
	if err != nil {
		return auth.AgentRoleNone, fmt.Errorf("registry: team grants: %w", err)
	}
	for _, tr := range teamRoles {
		role = auth.MaxAgentRole(role, auth.AgentRole(tr))
	}
	return role, nil
}

// CreateAgentInput is the validated input for CreateAgent.
type CreateAgentInput struct {
	Namespace  string
	Name       string
	Visibility string
	Summary    string
	// Modes are the run modes the agent supports (DEV-088); empty means
	// [autonomous], the mode every v1 package maps to.
	Modes []string
}

// Run modes an agent row may carry (DEV-088). The manifest package owns the
// vocabulary; this mirror keeps the store free of a pkg/manifest import.
var validModes = map[string]bool{"autonomous": true, "interactive": true}

// normalizeModes validates a caller-supplied mode set, deriving the v1
// default when none was given.
func normalizeModes(modes []string) ([]string, error) {
	if len(modes) == 0 {
		return []string{"autonomous"}, nil
	}
	seen := make(map[string]bool, len(modes))
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		if !validModes[m] {
			return nil, fmt.Errorf("%w: unknown mode %q (autonomous | interactive)", ErrDenied, m)
		}
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out, nil
}

// CreateAgent creates the agent row and its bare repository. The caller is
// authorized here: personal namespace = self; org namespace = any active
// member (D6, agentry#362 — a seat buys a share of the organization's
// namespace, and an admin is a member with more). A pending member is not
// one: their membership never reaches Principal.OrgRoles.
func (s *Service) CreateAgent(ctx context.Context, p *auth.Principal, in CreateAgentInput, actorEvent audit.Event) (Agent, error) {
	if p == nil || p.Anonymous {
		return Agent{}, auth.ErrUnauthorized
	}
	if !AgentNameRe.MatchString(in.Name) {
		return Agent{}, fmt.Errorf("%w: the agent name must be 1-65 lowercase letters, digits and hyphens, starting and ending with a letter or digit", ErrDenied)
	}
	modes, err := normalizeModes(in.Modes)
	if err != nil {
		return Agent{}, err
	}
	switch in.Visibility {
	case "public", "private":
	default:
		return Agent{}, fmt.Errorf("%w: visibility must be public or private", ErrDenied)
	}

	q := s.st.Queries()
	ns, err := q.GetHandle(ctx, in.Namespace)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Agent{}, ErrNotFound
		}
		return Agent{}, fmt.Errorf("registry: namespace: %w", err)
	}

	// Namespace authorization + quota (§19).
	subject := entitlements.ForUser(ns.ID)
	switch ns.Kind {
	case "user":
		if ns.ID != p.UserID {
			return Agent{}, auth.ErrForbidden
		}
	case "org":
		// Nothing is added to an organization that is suspended or in its
		// decommission hold (agentry#363) — asked first, so a suspended
		// organization is as absent to a stranger as to a member.
		if err := s.OrgGate(ctx, ns.ID, auth.ActAgentCreate); err != nil {
			return Agent{}, err
		}
		// The namespace-derived role is the one rule: whoever may release
		// an agent here may make one here.
		derived := auth.NamespaceDerivedAgentRole(p, ns.Kind, ns.ID, p.Role(ns.ID))
		if derived == auth.AgentRoleNone {
			return Agent{}, auth.ErrForbidden
		}
		// Putting the organization's name on something the world can see
		// is the same decision as making an existing agent public, and it
		// belongs to the same people (D19, agentry#362). Enforcing it only
		// on the transition would leave "create it public" as the way
		// round: the state is what matters, not how it was reached.
		if in.Visibility == "public" && derived != auth.AgentRoleAdmin {
			return Agent{}, fmt.Errorf("%w: creating a public BriefAgent in %s is for the organization's administrators; create it private and ask an admin to publish it", ErrDenied, in.Namespace)
		}
		subject = entitlements.ForOrg(ns.ID)
	}
	// Publishing requires verified email (§19); creating an agent is the
	// first step of that path, so gate here where the journey starts.
	if !p.EmailVerified {
		return Agent{}, fmt.Errorf("%w: verify this account's email address before creating a BriefAgent", ErrDenied)
	}
	lim, err := s.Entitlements().Limits(ctx, subject)
	if err != nil {
		// Fail closed: an unresolvable entitlement is not permission.
		return Agent{}, fmt.Errorf("registry: entitlements: %w", err)
	}
	n, err := q.CountAgentsInNamespace(ctx, ns.ID)
	if err != nil {
		return Agent{}, fmt.Errorf("registry: quota count: %w", err)
	}
	if n >= lim.AgentsPerNamespace {
		return Agent{}, fmt.Errorf("%w: namespace agent quota reached", ErrDenied)
	}
	if in.Visibility == "private" {
		if err := s.checkPrivateAgentCap(ctx, subject, ns.ID); err != nil {
			return Agent{}, err
		}
	}

	repoID := newUUID()
	agentID := newUUID()

	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if _, err := q.CreateRepo(ctx, repoID); err != nil {
			return err
		}
		if _, err := q.CreateAgent(ctx, storegen.CreateAgentParams{
			ID: agentID, NamespaceID: ns.ID, Name: in.Name,
			Visibility: in.Visibility, RepoID: repoID, Summary: in.Summary, Modes: modes,
		}); err != nil {
			return err
		}
		e := actorEvent
		e.Action = audit.ActionAgentCreate
		if ns.Kind == "org" {
			e.OrgID = ns.ID
		}
		e.TargetKind, e.TargetID = "agent", agentID
		e.Detail = map[string]any{"path": in.Namespace + "/" + in.Name, "modes": modes, "visibility": in.Visibility}
		return s.aud.Write(ctx, q, e)
	})
	if err != nil {
		return Agent{}, err
	}
	return s.Resolve(ctx, in.Namespace, in.Name)
}

func newUUID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return id
}

// ErrPrivateAgentCap reports that a namespace holds as many private agents
// as its subscription tier allows (plan subscription-tiers §5.3). The API
// answers 422 private-agent-cap. A cap never deletes: over it, nothing can
// be added and nothing already private is touched.
var ErrPrivateAgentCap = errors.New("registry: this namespace holds as many private agents as its tier allows")

// CheckPrivateAgentCap is checkPrivateAgentCap for the handler that flips
// an existing agent to private.
func (s *Service) CheckPrivateAgentCap(ctx context.Context, a Agent) error {
	return s.checkPrivateAgentCapFor(ctx, subjectFor(a), a.NamespaceID, 1)
}

// CheckPrivateAgentCapFor refuses adding n more private agents to an
// organization's namespace at once — an erased account's catalogue moving
// in (agentry#363: the transfer door respects the cap). n of zero always
// passes.
func (s *Service) CheckPrivateAgentCapFor(ctx context.Context, orgID uuid.UUID, n int64) error {
	if n <= 0 {
		return nil
	}
	return s.checkPrivateAgentCapFor(ctx, entitlements.ForOrg(orgID), orgID, n)
}

// checkPrivateAgentCap refuses one more private agent when the subject's
// Features cap is reached. An unresolvable entitlement is not permission.
func (s *Service) checkPrivateAgentCap(ctx context.Context, subject entitlements.Subject, nsID uuid.UUID) error {
	return s.checkPrivateAgentCapFor(ctx, subject, nsID, 1)
}

func (s *Service) checkPrivateAgentCapFor(ctx context.Context, subject entitlements.Subject, nsID uuid.UUID, adding int64) error {
	f, err := s.Entitlements().Features(ctx, subject)
	if err != nil {
		return fmt.Errorf("registry: entitlements: %w", err)
	}
	if !f.PrivateAgents.Enabled {
		return ErrPrivateAgentCap
	}
	if f.PrivateAgents.Max <= 0 {
		return nil
	}
	n, err := s.st.Queries().CountPrivateAgentsInNamespace(ctx, nsID)
	if err != nil {
		return fmt.Errorf("registry: private agent count: %w", err)
	}
	if n+adding > f.PrivateAgents.Max {
		return ErrPrivateAgentCap
	}
	return nil
}
