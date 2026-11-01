package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/manifestcaps"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/manifest"
)

// resolveSubagents resolves each subagent a persistent release declares
// against the registry, in the order it declares them: the newestProblem stable,
// published version its constraint admits that may be a subagent, and that
// version's reach, or the reason none does. A subagent must be public, or
// private in the parent's own organization, so that whoever can install the
// parent can run it. A database error is returned, never read as a subagent
// that does not resolve. Dependencies that do not decode resolve to one
// entry that says so.
func resolveSubagents(ctx context.Context, q *storegen.Queries, parent storegen.GetAgentByIDRow, manifestJSON []byte) ([]Subagent, error) {
	deps, ok := manifestcaps.Subagents(manifestJSON)
	if !ok {
		return []Subagent{{Ref: "dependencies.agents", Problem: "the manifest's dependencies do not read"}}, nil
	}
	out := make([]Subagent, 0, len(deps))
	for _, d := range deps {
		s := Subagent{Ref: d.Ref, Constraint: d.Version, Why: d.Why}
		problem, err := resolveSubagent(ctx, q, parent, d, &s)
		if err != nil {
			return nil, fmt.Errorf("scan: resolve subagent %s: %w", d.Ref, err)
		}
		s.Problem = problem
		out = append(out, s)
	}
	return out, nil
}

// resolveSubagent fills s with the version d resolves to and its reach, or
// returns why it does not resolve.
func resolveSubagent(ctx context.Context, q *storegen.Queries, parent storegen.GetAgentByIDRow, d manifest.AgentDependency, s *Subagent) (string, error) {
	ns, name, _ := strings.Cut(d.Ref, "/")
	a, err := q.GetAgentByPath(ctx, storegen.GetAgentByPathParams{Handle: ns, Name: name})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "it is not in the registry", nil
	case err != nil:
		return "", err
	}
	switch {
	case a.QuarantineState == "blocked":
		return "it is blocked", nil
	case a.QuarantineState != "none":
		return "it is quarantined", nil
	case a.RetiredAt != nil:
		return "it is retired", nil
	case a.Visibility != "public" && !sameOrganization(parent, a):
		return "it is private and not in this release's organization, so the people who install this release could not run it", nil
	}
	constraint, err := semver.NewConstraint(d.Version)
	if err != nil {
		return "its constraint does not parse", nil
	}
	rows, err := q.ListResolvableVersions(ctx, a.ID)
	if err != nil {
		return "", err
	}
	type candidate struct {
		v   *semver.Version
		row storegen.AgentVersion
	}
	var matching []candidate
	for _, row := range rows {
		if row.Status != "published" || row.Channel != string(manifest.ChannelStable) {
			continue
		}
		v, err := semver.StrictNewVersion(row.Version)
		if err != nil || !constraint.Check(v) {
			continue
		}
		matching = append(matching, candidate{v, row})
	}
	if len(matching) == 0 {
		return "no published version matches " + d.Version, nil
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].v.GreaterThan(matching[j].v) })
	newestProblem := ""
	for _, c := range matching {
		var m manifest.Manifest
		if err := json.Unmarshal(c.row.Manifest, &m); err != nil {
			continue
		}
		problem := subagentProblem(&m)
		if problem == "" {
			s.Version, s.Reach = c.row.Version, reachOf(&m)
			return "", nil
		}
		if newestProblem == "" {
			newestProblem = problem
		}
	}
	if newestProblem == "" {
		newestProblem = "its manifest does not read"
	}
	return "no version " + d.Version + " admits can be a subagent: " + newestProblem, nil
}

// sameOrganization reports whether the subagent a is in the organization
// that publishes parent.
func sameOrganization(parent storegen.GetAgentByIDRow, a storegen.GetAgentByPathRow) bool {
	return parent.NamespaceKind == "org" && a.NamespaceID == parent.NamespaceID
}
