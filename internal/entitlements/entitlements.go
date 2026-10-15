// Package entitlements is the product seam: the one place that answers
// "how much of this may this subject have?" and "is this feature on?".
//
// The OSS default answers "everything on, limits from config". The hosted
// overlay swaps in a Resolver backed by the billing plan. Nothing in this
// repo may branch on "is this cloud?", so every quota consumer asks the
// Resolver instead of reading a constant, and the OSS answer happens to be
// constant.
//
// The seam is the deliverable: by design the default Resolver reproduces the
// default quota numbers exactly, so wiring it changes no behaviour.
package entitlements

import (
	"context"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
)

// NamespaceKind distinguishes the two namespace flavours that get different
// agent quotas.
type NamespaceKind string

const (
	NamespaceUser NamespaceKind = "user"
	NamespaceOrg  NamespaceKind = "org"
)

// Subject is whose entitlements are being resolved. Exactly one of OrgID or
// UserID is meaningful for a given lookup; both are carried because a SaaS
// Resolver may need the user (personal plan) or the org (team plan) depending
// on which namespace the request touches.
type Subject struct {
	// Kind selects the namespace quota row (200 agents for a user
	// namespace, 500 for an org). Empty is treated as NamespaceUser — the
	// stricter of the two, so a caller that forgets to set it is not handed
	// the larger budget by accident.
	Kind NamespaceKind
	// OrgID is the owning organisation, or uuid.Nil for a personal namespace.
	OrgID uuid.UUID
	// UserID is the acting user, when known.
	UserID uuid.UUID
}

// ForOrg builds a Subject for an org-owned resource.
func ForOrg(orgID uuid.UUID) Subject {
	return Subject{Kind: NamespaceOrg, OrgID: orgID}
}

// ForUser builds a Subject for a personal namespace.
func ForUser(userID uuid.UUID) Subject {
	return Subject{Kind: NamespaceUser, UserID: userID}
}

// Limits is the resolved quota set.
type Limits struct {
	// AgentsPerNamespace caps agents in one namespace.
	AgentsPerNamespace int64
	// VersionsPerDay caps submissions per agent per day.
	VersionsPerDay int64
	// WebhookEndpoints caps configured endpoints per org.
	WebhookEndpoints int64
	// WebhookDeliveriesPerSecond is the per-org delivery rate.
	WebhookDeliveriesPerSecond float64
	// GitPushesPerHour is the per-repo push budget.
	GitPushesPerHour int
	// RepoQuotaBytes / RepoMaxBlobBytes are the git-side size caps.
	RepoQuotaBytes   int64
	RepoMaxBlobBytes int64
	// Archive bounds the release archive (enforced by manifest rule V8).
	Archive ArchiveLimits
}

// ArchiveLimits mirrors pkg/manifest.Quotas. It is restated here rather than
// imported so that the entitlements contract does not drag the manifest
// package into every consumer; internal/registry converts between the two at
// the one place that needs both.
type ArchiveLimits struct {
	MaxBytes          int64
	MaxFiles          int
	MaxFileBytes      int64
	MaxImageFileBytes int64
	// MaxTextBytes caps the total of the text files in the include set
	// (the instruction-file total).
	MaxTextBytes int64
}

// Cap is a feature with a cap: Enabled says whether the subject may use
// it at all, Max how many it may hold (0 = no cap).
type Cap struct {
	Enabled bool
	Max     int64
}

// Features is what a subject may hold, as opposed to how fast it may act
// (Limits): the caps and switches a subscription tier sets. The core
// resolver answers every cap enabled with no maximum and every switch on
// (a self-hosted registry has no tiers and ships no crippled stub); a
// closed build's resolver answers by tier. A cap never deletes:
// over it, nothing can be added and nothing is lost.
type Features struct {
	// PrivateAgents caps the private agents a namespace holds.
	PrivateAgents Cap
	// Seats caps the people an organization may license — active members
	// plus open invitations (org subjects; meaningless for a user).
	Seats Cap
	// SSO and SCIM say whether the organization may create an SSO
	// connection or mint a SCIM token.
	SSO  bool
	SCIM bool
	// Branding says whether the organization may set a logo.
	Branding bool
	// AlertRouting says whether the organization may route dependency
	// alerts to a destination of its own.
	AlertRouting bool
	// UnscannedAgents says whether the organization's admins may mark a
	// private agent as skipping the pipeline.
	UnscannedAgents bool
	// SSHKeys says whether a person may register an SSH key for the git
	// transport (user subjects). It gates only the adding: a
	// key already held keeps working, stays listed and can be removed.
	SSHKeys bool
	// KnowledgeBytes caps the bytes of knowledge packs a subject keeps in
	// the registry: only what is stored here counts, and over the cap no
	// pack is added or grown, none deleted.
	KnowledgeBytes Cap
}

// Resolver answers entitlement questions.
type Resolver interface {
	// Limits returns the quota set for a subject. An error means "unknown" —
	// callers must fail closed rather than fall back to a default, or a
	// Resolver outage would silently lift every quota at once.
	Limits(ctx context.Context, s Subject) (Limits, error)
	// Features returns the caps for a subject; an error means "unknown" and
	// callers fail closed, as for Limits.
	Features(ctx context.Context, s Subject) (Features, error)
}

// ConfigResolver is the OSS default: limits come from config, every feature is
// on, and the answer does not depend on the subject beyond its namespace kind.
type ConfigResolver struct {
	limits config.Limits
}

// NewConfigResolver builds the default Resolver from the limits config block.
func NewConfigResolver(l config.Limits) *ConfigResolver {
	return &ConfigResolver{limits: l}
}

// Default is the Resolver used when none has been wired: the shipped
// defaults. It exists so a half-constructed server enforces quotas rather
// than none at all — an unwired seam must not be an open door.
func Default() *ConfigResolver {
	return NewConfigResolver(config.Default().Limits)
}

// Limits implements Resolver.
func (r *ConfigResolver) Limits(_ context.Context, s Subject) (Limits, error) {
	l := r.limits
	agents := int64(l.AgentsPerUserNamespace)
	if s.Kind == NamespaceOrg {
		agents = int64(l.AgentsPerOrgNamespace)
	}
	return Limits{
		AgentsPerNamespace:         agents,
		VersionsPerDay:             int64(l.VersionsPerDay),
		WebhookEndpoints:           int64(l.WebhookEndpointsPerOrg),
		WebhookDeliveriesPerSecond: float64(l.WebhookDeliveriesPerSecond),
		GitPushesPerHour:           l.GitPushesPerHour,
		RepoQuotaBytes:             int64(l.RepoQuotaBytes),
		RepoMaxBlobBytes:           int64(l.RepoMaxBlobBytes),
		Archive: ArchiveLimits{
			MaxBytes:          l.ArchiveMaxBytes,
			MaxFiles:          l.ArchiveMaxFiles,
			MaxFileBytes:      l.ArchiveMaxFileBytes,
			MaxImageFileBytes: l.ArchiveMaxImageFileBytes,
			MaxTextBytes:      l.ArchiveMaxTextBytes,
		},
	}, nil
}

// Features implements Resolver: the OSS build caps nothing and switches
// nothing off, but for the knowledge cap a self-hoster may set
// (limits.knowledgeBytesPerAccount; 0, the default, is none).
func (r *ConfigResolver) Features(context.Context, Subject) (Features, error) {
	on := Cap{Enabled: true, Max: 0}
	return Features{
		PrivateAgents: on, Seats: on,
		SSO: true, SCIM: true, Branding: true, AlertRouting: true, UnscannedAgents: true, SSHKeys: true,
		KnowledgeBytes: Cap{Enabled: true, Max: r.limits.KnowledgeBytesPerAccount},
	}, nil
}
