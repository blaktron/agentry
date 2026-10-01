package entitlements

import (
	"context"
	"reflect"
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

// The core resolver caps nothing and switches nothing off: a self-hosted
// registry has no tiers, so every Cap is enabled with no maximum and every
// flag is on, for users and orgs alike (§1.6.5, §14.3: no crippled stubs).
// The walk is over the struct's fields, so a field added to Features fails
// here until the resolver answers it and this test knows its kind.
func TestOSSResolverCapsNothing(t *testing.T) {
	r := Default()
	for _, s := range []Subject{ForUser(uuid.New()), ForOrg(uuid.New()), {}} {
		f, err := r.Features(t.Context(), s)
		if err != nil {
			t.Fatal(err)
		}
		v := reflect.ValueOf(f)
		for i := 0; i < v.NumField(); i++ {
			name := v.Type().Field(i).Name
			switch field := v.Field(i).Interface().(type) {
			case Cap:
				if !field.Enabled || field.Max != 0 {
					t.Errorf("subject %+v: %s %+v, want enabled and uncapped", s, name, field)
				}
			case bool:
				if !field {
					t.Errorf("subject %+v: %s is off in the core resolver", s, name)
				}
			default:
				t.Fatalf("Features.%s has a kind this test does not know: %T", name, field)
			}
		}
		if v.NumField() != 9 {
			t.Fatalf("Features has %d fields, want 9 — add the new one to this test's expectations", v.NumField())
		}
	}
}

// The interface must be satisfiable by an overlay implementation.
var _ Resolver = (*ConfigResolver)(nil)

// stubResolver stands in for the SaaS overlay in consumer tests.
type stubResolver struct {
	limits Limits
}

func (s stubResolver) Limits(context.Context, Subject) (Limits, error) { return s.limits, nil }
func (s stubResolver) Features(context.Context, Subject) (Features, error) {
	return Features{PrivateAgents: Cap{Enabled: true}}, nil
}

var _ Resolver = stubResolver{}

func TestConfigResolverKnowledgeCapIsTheSelfHostersToSet(t *testing.T) {
	l := config.Default().Limits
	l.KnowledgeBytesPerAccount = 100 << 20
	f, err := NewConfigResolver(l).Features(context.Background(), ForUser(uuid.New()))
	if err != nil {
		t.Fatal(err)
	}
	if !f.KnowledgeBytes.Enabled || f.KnowledgeBytes.Max != 100<<20 {
		t.Fatalf("knowledge cap = %+v, want enabled at 100 MiB", f.KnowledgeBytes)
	}
}
