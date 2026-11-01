package scan

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/pkg/manifest"
)

// adviseSubagentHolders is told of each version that leaves published. Every
// persistent release whose published versions name that release as a
// subagent, with a constraint that admits the version, gets an advisory on
// itself: its holders read it where they read every advisory, and the runner
// refuses a call to a subagent that no longer resolves. The parent's own
// verdict does not change. High for a quarantine or a block, medium for a
// yank, which withdraws a version without saying it is harmful. Best-effort:
// the transition has committed, and a failure is logged at error.
func (p *Pipeline) adviseSubagentHolders(ctx context.Context, res registry.TransitionResult) {
	var severity, happened string
	switch res.To {
	case registry.StatusQuarantined:
		severity, happened = "high", "was quarantined"
	case registry.StatusBlocked:
		severity, happened = "high", "was blocked"
	case registry.StatusYanked:
		severity, happened = "medium", "was withdrawn by its publisher"
	default:
		return
	}
	q := p.st.Queries()
	sub, err := q.GetAgentByID(ctx, res.AgentID)
	if err != nil {
		p.log.Error("subagent advisory: load agent", "agent", res.AgentID, "err", err)
		return
	}
	ref := sub.Namespace + "/" + sub.Name
	rows, err := q.ListSubagentDependents(ctx, ref)
	if err != nil {
		p.log.Error("subagent advisory: dependents", "subagent", ref, "err", err)
		return
	}
	// One advisory per parent, naming each of its published versions whose
	// constraint admits the version that left.
	affected := map[uuid.UUID][]string{}
	var order []uuid.UUID
	for _, row := range rows {
		var m manifest.Manifest
		if json.Unmarshal(row.Manifest, &m) != nil || row.AgentID == res.AgentID {
			continue
		}
		for _, d := range m.Subagents() {
			if d.Ref == ref && d.SubagentAllows(res.Version) {
				if _, seen := affected[row.AgentID]; !seen {
					order = append(order, row.AgentID)
				}
				affected[row.AgentID] = append(affected[row.AgentID], row.Version)
				break
			}
		}
	}
	for _, parent := range order {
		summary := "A subagent this release uses, " + ref + " " + res.Version + ", " + happened +
			"; calls to it are refused until a version the release's constraint admits resolves again"
		if err := p.PublishAdvisory(ctx, parent, strings.Join(affected[parent], " || "), severity, summary, res.Reason); err != nil {
			p.log.Error("subagent advisory: publish", "parent", parent, "subagent", ref, "err", err)
		}
	}
}
