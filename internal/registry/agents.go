// Package registry owns the agent/version domain (§2.1 L3): agent creation,
// resolution, effective-permission computation, and (from M3) the publication
// state machine.
package registry

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// AgentNameRe is the §4.2 agent-name grammar.
var AgentNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,63}[a-z0-9])?$`)

// Namespace agent quotas (§19).
const (
	MaxAgentsUserNamespace = 200
	MaxAgentsOrgNamespace  = 500
)

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
	Kind       string
	Visibility string
	Summary    string
}

// CreateAgent creates the agent row and its bare repository. The caller is
// authorized here: personal namespace = self; org namespace = org admin+
// (org role admin gets maintain via NamespaceDerivedAgentRole, and creation
// requires at least that).
func (s *Service) CreateAgent(ctx context.Context, p *auth.Principal, in CreateAgentInput, actorEvent audit.Event) (Agent, error) {
	if p == nil || p.Anonymous {
		return Agent{}, auth.ErrUnauthorized
	}
	if !AgentNameRe.MatchString(in.Name) {
		return Agent{}, fmt.Errorf("%w: invalid agent name", ErrDenied)
	}
	switch in.Kind {
	case "skill", "prompt-agent", "mcp-server":
	default:
		return Agent{}, fmt.Errorf("%w: invalid kind", ErrDenied)
	}
	switch in.Visibility {
	case "public", "private":
	default:
		return Agent{}, fmt.Errorf("%w: invalid visibility", ErrDenied)
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
	var quota int64 = MaxAgentsUserNamespace
	switch ns.Kind {
	case "user":
		if ns.ID != p.UserID {
			return Agent{}, auth.ErrForbidden
		}
	case "org":
		if r := p.Role(ns.ID); r != auth.RoleOwner && r != auth.RoleAdmin {
			return Agent{}, auth.ErrForbidden
		}
		quota = MaxAgentsOrgNamespace
	}
	// Publishing requires verified email (§19); creating an agent is the
	// first step of that path, so gate here where the journey starts.
	if !p.EmailVerified {
		return Agent{}, fmt.Errorf("%w: email verification required", ErrDenied)
	}
	n, err := q.CountAgentsInNamespace(ctx, ns.ID)
	if err != nil {
		return Agent{}, fmt.Errorf("registry: quota count: %w", err)
	}
	if n >= quota {
		return Agent{}, fmt.Errorf("%w: namespace agent quota reached", ErrDenied)
	}

	repoID := newUUID()
	agentID := newUUID()

	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if _, err := q.CreateRepo(ctx, repoID); err != nil {
			return err
		}
		if _, err := q.CreateAgent(ctx, storegen.CreateAgentParams{
			ID: agentID, NamespaceID: ns.ID, Name: in.Name, Kind: in.Kind,
			Visibility: in.Visibility, RepoID: repoID, Summary: in.Summary,
		}); err != nil {
			return err
		}
		e := actorEvent
		e.Action = audit.ActionAgentCreate
		if ns.Kind == "org" {
			e.OrgID = ns.ID
		}
		e.TargetKind, e.TargetID = "agent", agentID
		e.Detail = map[string]any{"path": in.Namespace + "/" + in.Name, "kind": in.Kind, "visibility": in.Visibility}
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
