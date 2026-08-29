package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"

	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// Resolution semantics (§5.5, §9.4): ranges resolve over PUBLISHED versions
// of the requested channel; yanked versions resolve only by exact pin (with
// a warning flag); quarantined versions never resolve; blocked agents 410
// at download.

// Ref is a parsed "ns/name[@range]" reference.
type Ref struct {
	Namespace string
	Name      string
	Range     string // "" = latest on channel
	Channel   string // stable | beta (from @beta shorthand or explicit param)
}

// ErrNoMatch means no published version satisfies the request.
var ErrNoMatch = errors.New("registry: no version matches")

// ParseRef parses "ns/name", "ns/name@^1.2", "ns/name@1.2.3", "ns/name@beta".
func ParseRef(ref string) (Ref, error) {
	path, rng, _ := strings.Cut(ref, "@")
	ns, name, ok := strings.Cut(path, "/")
	if !ok || ns == "" || name == "" {
		return Ref{}, fmt.Errorf("registry: invalid ref %q (want ns/name[@range])", ref)
	}
	out := Ref{Namespace: ns, Name: name, Range: rng, Channel: "stable"}
	switch rng {
	case "beta", "stable":
		out.Channel = rng
		out.Range = ""
	}
	return out, nil
}

// Resolved is the outcome of a resolution.
type Resolved struct {
	Version Version
	Yanked  bool
}

// ErrBlocked reports that trust & safety has disabled the agent (§7).
var ErrBlocked = errors.New("registry: agent blocked by trust & safety")

// ResolveVersion picks the version for a ref within an agent (§9.4 step 1).
func (s *Service) ResolveVersion(ctx context.Context, a Agent, rangeStr, channel string) (Resolved, error) {
	// A blocked agent resolves to nothing, whatever its version rows say.
	// Blocking walks the versions too, but this is the check that holds if a
	// scan finishes and publishes a version after the block landed.
	if a.QuarantineState == "blocked" {
		return Resolved{}, ErrBlocked
	}
	if channel == "" {
		channel = "stable"
	}
	rows, err := s.st.Queries().ListResolvableVersions(ctx, a.ID)
	if err != nil {
		return Resolved{}, err
	}

	// Exact pin? Yanked versions stay pinnable with a warning (§5.5).
	if exact, err := semver.StrictNewVersion(strings.TrimPrefix(rangeStr, "v")); err == nil {
		for _, row := range rows {
			if row.Version == exact.String() {
				switch Status(row.Status) {
				case StatusPublished:
					return Resolved{Version: row}, nil
				case StatusYanked:
					return Resolved{Version: row, Yanked: true}, nil
				}
			}
		}
		return Resolved{}, ErrNoMatch
	}

	var constraint *semver.Constraints
	if rangeStr != "" {
		c, err := semver.NewConstraint(rangeStr)
		if err != nil {
			return Resolved{}, fmt.Errorf("registry: invalid version range %q: %w", rangeStr, err)
		}
		constraint = c
	}

	var best *storegen.AgentVersion
	var bestV *semver.Version
	for i := range rows {
		row := &rows[i]
		if Status(row.Status) != StatusPublished || row.Channel != channel {
			continue
		}
		v, err := semver.StrictNewVersion(row.Version)
		if err != nil {
			continue
		}
		if constraint != nil && !constraint.Check(v) {
			continue
		}
		if bestV == nil || v.GreaterThan(bestV) {
			best, bestV = row, v
		}
	}
	if best == nil {
		return Resolved{}, ErrNoMatch
	}
	return Resolved{Version: *best}, nil
}
