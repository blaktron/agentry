// Package entitlements is the §14.2 product seam: the one place that answers
// "how much of this may this subject have?" and "is this feature on?".
//
// The OSS default answers "everything on, limits from config" (§14.2). The
// SaaS overlay swaps in a Resolver backed by the billing plan. Nothing in this
// repo may branch on "is this cloud?" — §18.1 — so every quota consumer asks
// the Resolver instead of reading a constant, and the OSS answer happens to be
// constant.
//
// The seam is the deliverable: by design the default Resolver reproduces the
// §19 numbers exactly, so wiring it changes no behaviour.
package entitlements

import (
	"context"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
)

// NamespaceKind distinguishes the two namespace flavours §19 gives different
// agent quotas to.
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
	// Kind selects the namespace quota row (§19: 200 agents for a user
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

// Limits is the resolved quota set (§19).
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
	// (§19 "instruction-file total", agentry#44).
	MaxTextBytes int64
}

// Feature names a capability an overlay may gate. The OSS Resolver enables
// every one of them: §1.6.5 makes self-hosting first-class, and a crippled
// stub in the OSS tree would be exactly the thing §14.3 forbids.
type Feature string

const (
	FeatureEnforcedSSO       Feature = "enforced_sso"
	FeatureSCIM              Feature = "scim"
	FeaturePrivateNamespaces Feature = "private_namespaces"
	FeatureWebhooks          Feature = "webhooks"
	FeatureAuditExport       Feature = "audit_export"
	FeatureAuditStream       Feature = "audit_stream"
	FeaturePolicyOverrides   Feature = "policy_overrides"
	FeaturePriorityReview    Feature = "priority_review"
)

// Resolver answers entitlement questions.
type Resolver interface {
	// Limits returns the quota set for a subject. An error means "unknown" —
	// callers must fail closed rather than fall back to a default, or a
	// Resolver outage would silently lift every quota at once.
	Limits(ctx context.Context, s Subject) (Limits, error)
	// FeatureEnabled reports whether a feature is available to an org.
	// uuid.Nil asks about a personal namespace.
	FeatureEnabled(ctx context.Context, orgID uuid.UUID, f Feature) bool
}

// ConfigResolver is the OSS default: limits come from config, every feature is
// on, and the answer does not depend on the subject beyond its namespace kind.
type ConfigResolver struct {
	limits config.Limits
}

// NewConfigResolver builds the default Resolver from the §19 config block.
func NewConfigResolver(l config.Limits) *ConfigResolver {
	return &ConfigResolver{limits: l}
}

// Default is the Resolver used when none has been wired: the shipped §19
// defaults. It exists so a half-constructed server enforces quotas rather than
// none at all — an unwired seam must not be an open door.
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

// FeatureEnabled implements Resolver: the OSS build ships everything on.
func (r *ConfigResolver) FeatureEnabled(context.Context, uuid.UUID, Feature) bool {
	return true
}
