// Command seedgen writes the §17.6 performance seed dataset: N published
// agents with realistic names, summaries, manifests, capabilities and install
// counts, straight into the database through the store.
//
// §17.6 fixes the search baseline at "p95 < 300 ms at 10k-agent seed dataset
// (seed generator committed)". A baseline is only a baseline if the dataset it
// was measured against can be reproduced, so this generator is deterministic:
// the same -count and -seed always produce the same corpus, including the
// install-count distribution that drives search ranking.
//
// It is staging/dev tooling. It is not run by CI, it writes no archives, and
// it never invokes the scan pipeline — versions are inserted already
// published, because the point is to populate the read paths (search, resolve,
// listing), not to exercise the gate.
//
//	go run ./scripts/seed -dsn "$AGENTRY_DATABASE_URL" -count 10000
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("AGENTRY_DATABASE_URL"), "PostgreSQL DSN (default $AGENTRY_DATABASE_URL)")
	count := flag.Int("count", 10000, "number of agents to create (§17.6 baseline is 10000)")
	namespaces := flag.Int("namespaces", 200, "number of publisher namespaces to spread the agents across")
	seed := flag.Int64("seed", 1, "PRNG seed; the same seed reproduces the same corpus")
	prefix := flag.String("prefix", "seed", "handle/name prefix, so a seed run is identifiable and removable")
	batch := flag.Int("batch", 200, "agents per transaction")
	flag.Parse()

	if *dsn == "" {
		log.Fatal("seedgen: -dsn (or AGENTRY_DATABASE_URL) is required")
	}
	ctx := context.Background()
	st, err := store.Connect(ctx, *dsn)
	if err != nil {
		log.Fatalf("seedgen: connect: %v", err)
	}
	defer st.Close()

	g := &generator{
		rnd: rand.New(rand.NewSource(*seed)), //nolint:gosec // determinism is the point; not a security context
		pfx: *prefix,
	}
	start := time.Now()
	owners, err := g.seedNamespaces(ctx, st, *namespaces)
	if err != nil {
		log.Fatalf("seedgen: namespaces: %v", err)
	}
	log.Printf("seedgen: %d namespaces ready", len(owners))

	made := 0
	for made < *count {
		n := *batch
		if remaining := *count - made; remaining < n {
			n = remaining
		}
		if err := g.seedAgents(ctx, st, owners, made, n); err != nil {
			log.Fatalf("seedgen: agents at offset %d: %v", made, err)
		}
		made += n
		if made%2000 == 0 || made == *count {
			log.Printf("seedgen: %d/%d agents (%s elapsed)", made, *count, time.Since(start).Round(time.Second))
		}
	}
	log.Printf("seedgen: done — %d agents across %d namespaces in %s",
		made, len(owners), time.Since(start).Round(time.Second))
}

// owner is one seeded publisher: a user and the handle that is its namespace.
type owner struct {
	userID   uuid.UUID
	handleID uuid.UUID
	handle   string
}

type generator struct {
	rnd *rand.Rand
	pfx string
}

// seedNamespaces creates the publisher accounts. A user's handle IS its
// namespace (§4), so one row each in users and handles.
func (g *generator) seedNamespaces(ctx context.Context, st *store.Store, n int) ([]owner, error) {
	owners := make([]owner, 0, n)
	err := st.WithTx(ctx, func(q *storegen.Queries) error {
		for i := 0; i < n; i++ {
			handle := fmt.Sprintf("%s-pub-%04d", g.pfx, i)
			userID := uuid.Must(uuid.NewV7())
			handleID := userID // a user's handle row shares its id (§4 layout)
			if err := q.CreateHandle(ctx, storegen.CreateHandleParams{
				ID: handleID, Handle: handle, Kind: "user",
			}); err != nil {
				return fmt.Errorf("handle %s: %w", handle, err)
			}
			if _, err := q.CreateUser(ctx, storegen.CreateUserParams{
				ID:          userID,
				Email:       handle + "@seed.invalid",
				DisplayName: "Seed Publisher " + handle,
			}); err != nil {
				return fmt.Errorf("user %s: %w", handle, err)
			}
			owners = append(owners, owner{userID: userID, handleID: handleID, handle: handle})
		}
		return nil
	})
	return owners, err
}

// seedAgents creates one transaction's worth of agents, each with a single
// published version and an install count.
func (g *generator) seedAgents(ctx context.Context, st *store.Store, owners []owner, offset, n int) error {
	type statRow struct {
		agentID, versionID uuid.UUID
		installs           int32
	}
	stats := make([]statRow, 0, n)

	err := st.WithTx(ctx, func(q *storegen.Queries) error {
		for i := 0; i < n; i++ {
			idx := offset + i
			own := owners[idx%len(owners)]
			name := fmt.Sprintf("%s-%s-%05d", g.pfx, g.word(), idx)
			kind := kinds[g.rnd.Intn(len(kinds))]

			repo, err := q.CreateRepo(ctx, uuid.Must(uuid.NewV7()))
			if err != nil {
				return fmt.Errorf("repo: %w", err)
			}
			agent, err := q.CreateAgent(ctx, storegen.CreateAgentParams{
				ID: uuid.Must(uuid.NewV7()), NamespaceID: own.handleID,
				Name: name, Kind: kind, Visibility: "public",
				RepoID: repo.ID, Summary: g.summary(),
			})
			if err != nil {
				return fmt.Errorf("agent %s: %w", name, err)
			}

			caps := g.capabilities()
			version := fmt.Sprintf("%d.%d.%d", 1+g.rnd.Intn(3), g.rnd.Intn(10), g.rnd.Intn(20))
			manifest := fmt.Sprintf(
				`{"schemaVersion":"1","name":%q,"namespace":%q,"kind":%q,"version":%q,"summary":%q,"license":%q,"capabilities":%s}`,
				name, own.handle, kind, version, agent.Summary, licenses[g.rnd.Intn(len(licenses))], caps)

			v, err := q.CreateAgentVersion(ctx, storegen.CreateAgentVersionParams{
				ID: uuid.Must(uuid.NewV7()), AgentID: agent.ID, Version: version,
				CommitSha:    strings.Repeat(fmt.Sprintf("%x", idx%16), 40),
				Manifest:     []byte(manifest),
				Capabilities: []byte(caps),
				Channel:      "stable", SubmittedBy: own.userID, Source: "cli-upload",
			})
			if err != nil {
				return fmt.Errorf("version %s@%s: %w", name, version, err)
			}
			if err := q.SetVersionStatus(ctx, storegen.SetVersionStatusParams{
				ID: v.ID, Status: "published",
			}); err != nil {
				return fmt.Errorf("publish %s: %w", name, err)
			}
			vid := v.ID
			if err := q.SetAgentLatestPublished(ctx, storegen.SetAgentLatestPublishedParams{
				ID: agent.ID, LatestPublishedVersionID: &vid,
			}); err != nil {
				return fmt.Errorf("latest %s: %w", name, err)
			}
			stats = append(stats, statRow{agentID: agent.ID, versionID: v.ID, installs: g.installs()})
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Install counts go in with CopyFrom rather than one BumpDownloadStat per
	// row: at 10k agents the per-row round trips dominate the whole run. This
	// is the one place the generator steps outside sqlc (§18.1 coding
	// standards) — CopyFrom is a typed bulk API, not string-built SQL, and it
	// exists precisely for loading a table this way.
	rows := make([][]any, 0, len(stats))
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, s := range stats {
		rows = append(rows, []any{s.agentID, s.versionID, today, s.installs})
	}
	_, err = st.Pool().CopyFrom(ctx,
		pgx.Identifier{"download_stats"},
		[]string{"agent_id", "version_id", "day", "installs"},
		pgx.CopyFromRows(rows))
	return err
}

var (
	kinds    = []string{"skill", "prompt-agent"} // mcp-server is withdrawn (DEV-088)
	licenses = []string{"Apache-2.0", "MIT", "BSD-3-Clause", "MPL-2.0"}
	// Vocabulary for names and summaries. Kept small and domain-flavoured so
	// full-text search has realistic term frequencies rather than uniform
	// noise — a search benchmark against random strings measures nothing.
	nouns = []string{
		"incident", "changelog", "invoice", "schema", "release", "dependency",
		"ticket", "runbook", "dashboard", "migration", "digest", "review",
		"transcript", "roadmap", "postmortem", "contract", "inventory",
	}
	verbs = []string{
		"summarizer", "auditor", "linter", "reporter", "planner", "triager",
		"formatter", "explainer", "reviewer", "tracker", "generator",
	}
	adjectives = []string{
		"fast", "offline", "structured", "incremental", "streaming",
		"opinionated", "minimal", "batched",
	}
)

func (g *generator) word() string {
	return nouns[g.rnd.Intn(len(nouns))] + "-" + verbs[g.rnd.Intn(len(verbs))]
}

func (g *generator) summary() string {
	return fmt.Sprintf("A %s %s that turns %s data into a %s %s for your team.",
		adjectives[g.rnd.Intn(len(adjectives))], verbs[g.rnd.Intn(len(verbs))],
		nouns[g.rnd.Intn(len(nouns))], adjectives[g.rnd.Intn(len(adjectives))],
		nouns[g.rnd.Intn(len(nouns))])
}

// capabilities returns a manifest capability object. Two thirds of agents ask
// for nothing, matching the real distribution closely enough that the
// `capability=` facet has something to filter on.
func (g *generator) capabilities() string {
	switch g.rnd.Intn(6) {
	case 0:
		return `{"network":{"egress":["api.example.com"]}}`
	case 1:
		return `{"filesystem":{"read":{"paths":["."]}}}`
	default:
		return `{}`
	}
}

// installs draws from a long-tailed distribution: search ranking multiplies
// relevance by popularity, so a flat install count would hide any ordering
// bug the benchmark exists to catch.
func (g *generator) installs() int32 {
	switch n := g.rnd.Intn(100); {
	case n < 70:
		return int32(g.rnd.Intn(50))
	case n < 95:
		return int32(50 + g.rnd.Intn(2000))
	default:
		return int32(2000 + g.rnd.Intn(200000))
	}
}
