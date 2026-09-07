package entitlements

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
)

// The point of the seam is that wiring it changed nothing: these are the §19
// table values the hardcoded constants used to carry.
func TestDefaultResolverReproducesSection19(t *testing.T) {
	r := Default()
	ctx := t.Context()

	user, err := r.Limits(ctx, ForUser(uuid.New()))
	if err != nil {
		t.Fatalf("Limits(user): %v", err)
	}
	org, err := r.Limits(ctx, ForOrg(uuid.New()))
	if err != nil {
		t.Fatalf("Limits(org): %v", err)
	}

	if user.AgentsPerNamespace != 200 {
		t.Errorf("user agents/namespace = %d, want 200", user.AgentsPerNamespace)
	}
	if org.AgentsPerNamespace != 500 {
		t.Errorf("org agents/namespace = %d, want 500", org.AgentsPerNamespace)
	}
	if org.VersionsPerDay != 20 {
		t.Errorf("versions/day = %d, want 20", org.VersionsPerDay)
	}
	if org.WebhookEndpoints != 20 {
		t.Errorf("webhook endpoints = %d, want 20", org.WebhookEndpoints)
	}
	if org.WebhookDeliveriesPerSecond != 5 {
		t.Errorf("webhook deliveries/s = %v, want 5", org.WebhookDeliveriesPerSecond)
	}
	if org.GitPushesPerHour != 60 {
		t.Errorf("git pushes/h = %d, want 60", org.GitPushesPerHour)
	}
	if org.RepoQuotaBytes != 100<<20 {
		t.Errorf("repo quota = %d, want %d", org.RepoQuotaBytes, 100<<20)
	}
	want := ArchiveLimits{MaxBytes: 10 << 20, MaxFiles: 2000, MaxFileBytes: 2 << 20, MaxImageFileBytes: 5 << 20, MaxTextBytes: 1 << 20}
	if org.Archive != want {
		t.Errorf("archive limits = %+v, want %+v", org.Archive, want)
	}
}

// An unset Kind must not be the more generous of the two.
func TestZeroKindGetsTheStricterNamespaceQuota(t *testing.T) {
	got, err := Default().Limits(t.Context(), Subject{})
	if err != nil {
		t.Fatalf("Limits: %v", err)
	}
	if got.AgentsPerNamespace != 200 {
		t.Errorf("zero-Kind agents/namespace = %d, want the user quota 200", got.AgentsPerNamespace)
	}
}

func TestLimitsFollowConfig(t *testing.T) {
	l := config.Default().Limits
	l.AgentsPerOrgNamespace = 5000
	l.VersionsPerDay = 3
	r := NewConfigResolver(l)

	got, err := r.Limits(t.Context(), ForOrg(uuid.New()))
	if err != nil {
		t.Fatalf("Limits: %v", err)
	}
	if got.AgentsPerNamespace != 5000 {
		t.Errorf("agents/namespace = %d, want the configured 5000", got.AgentsPerNamespace)
	}
	if got.VersionsPerDay != 3 {
		t.Errorf("versions/day = %d, want the configured 3", got.VersionsPerDay)
	}
}

// §1.6.5/§14.3: the OSS build must not ship crippled stubs of paid features.
func TestOSSResolverEnablesEveryFeature(t *testing.T) {
	r := Default()
	for _, f := range []Feature{
		FeatureEnforcedSSO, FeatureSCIM, FeaturePrivateNamespaces, FeatureWebhooks,
		FeatureAuditExport, FeatureAuditStream, FeaturePolicyOverrides, FeaturePriorityReview,
	} {
		if !r.FeatureEnabled(t.Context(), uuid.New(), f) {
			t.Errorf("feature %q is off in the OSS resolver", f)
		}
	}
	if !r.FeatureEnabled(t.Context(), uuid.Nil, FeatureWebhooks) {
		t.Error("a personal namespace was refused a feature")
	}
}

// The interface must be satisfiable by an overlay implementation.
var _ Resolver = (*ConfigResolver)(nil)

// stubResolver stands in for the SaaS overlay in consumer tests.
type stubResolver struct {
	limits Limits
	off    map[Feature]bool
}

func (s stubResolver) Limits(context.Context, Subject) (Limits, error) { return s.limits, nil }
func (s stubResolver) FeatureEnabled(_ context.Context, _ uuid.UUID, f Feature) bool {
	return !s.off[f]
}

var _ Resolver = stubResolver{}
