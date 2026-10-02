package scan

import (
	"context"
	"fmt"
	"path"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/draftproof"
)

// SourceDrafterRevision is the source of a version the scan proved was a
// hosted Drafter revision of its agent's current release (plan
// drafter-revisions.md §6, R5; agentry#794).
const SourceDrafterRevision = "drafter-revision"

// DraftClaim is what the pipeline asks DraftProvenance about one version:
// the draft run the upload named, who submitted it, the agent, S9's
// baseline for it (the version and its archive digest), and the proof of
// the submitted files (pkg/draftproof). Every field is the registry's own
// reading; none is taken from the request but the run's id. It carries no
// tier and no balance: the verdict never reads either (ARCHITECTURE.md §9).
type DraftClaim struct {
	Run            uuid.UUID
	Account        uuid.UUID
	AgentID        uuid.UUID
	Namespace      string
	Name           string
	Baseline       string
	BaselineDigest string
	Proof          draftproof.Proof
}

// DraftProvenance answers whether a claimed draft holds: the account ran
// draft Run, it revised Namespace/Name at Baseline (whose archive is
// BaselineDigest), and the proof its sandbox host recorded is Proof. Any
// mismatch, an unknown run or another account's is false with no error;
// an error is a lookup that could not be made, and the scan is retried
// rather than read it as either answer. The core has none: without an
// extension that answers, no version is a Drafter revision.
type DraftProvenance interface {
	Revised(ctx context.Context, c DraftClaim) (bool, error)
}

// DraftRevision is what S9 reads of a version proved to be a Drafter
// revision: the draft, the baseline it revised, and the files the proof
// covers on each side (this version's manifest and instruction file, and
// the baseline's), which S9's content diff and escalation leave out. Every
// other file is diffed as for any version.
type DraftRevision struct {
	Run        string
	Baseline   string
	Proved     []string
	PrevProved []string
}

// SetDraftProvenance installs the extension's answer to a claimed draft.
func (p *Pipeline) SetDraftProvenance(d DraftProvenance) { p.drafts = d }

// draftRevision decides whether this scan reads v as a Drafter revision,
// and records the proof the first time it holds.
//
// A version recorded as one (its source is drafter-revision) is one at
// every later scan and is never asked about again, so the benefit lapses
// neither with the draft's record nor when a later release becomes the
// baseline a rescan diffs against. A version that only claims a draft is
// asked about once, at its publish scan while it is scanning, and only
// with a baseline to compare against: the claim's proof is computed here
// from the extracted files, never taken from the client. Anything else is
// the ordinary S9, and a lookup that cannot be made retries the scan.
func (p *Pipeline) draftRevision(ctx context.Context, v *storegen.AgentVersion, agent storegen.GetAgentByIDRow, dir string, prev *storegen.AgentVersion, prevDir string) (*DraftRevision, error) {
	if prev == nil || v.DraftRun == nil {
		return nil, nil
	}
	baseline := prev.Version
	switch v.Source {
	case SourceDrafterRevision:
		// Proved at its publish scan against the release it revised; the
		// proof is about the version's own bytes, which never change. A
		// rescan diffs against whatever release is newest then, which may
		// be a later one, and the benefit holds against it as well.
		if v.DraftBaseline == nil {
			return nil, nil
		}
		baseline = *v.DraftBaseline
	case "cli-upload":
		if p.drafts == nil || registry.Status(v.Status) != registry.StatusScanning {
			return nil, nil
		}
		proof, _, err := draftproof.OfDir(dir)
		if err != nil {
			// No manifest or instruction file the proof can read: nothing
			// a draft could have recorded.
			return nil, nil //nolint:nilerr // an unprovable package is the ordinary S9
		}
		baselineDigest := ""
		if prev.ArchiveDigest != nil {
			baselineDigest = *prev.ArchiveDigest
		}
		ok, err := p.drafts.Revised(ctx, DraftClaim{
			Run: *v.DraftRun, Account: v.SubmittedBy, AgentID: agent.ID,
			Namespace: agent.Namespace, Name: agent.Name,
			Baseline: prev.Version, BaselineDigest: baselineDigest, Proof: proof,
		})
		if err != nil {
			return nil, fmt.Errorf("scan: draft provenance: %w", err)
		}
		if !ok {
			return nil, nil
		}
		n, err := p.st.Queries().MarkVersionDrafterRevision(ctx, storegen.MarkVersionDrafterRevisionParams{
			ID: v.ID, DraftBaseline: &prev.Version,
		})
		if err != nil {
			return nil, fmt.Errorf("scan: record drafter revision: %w", err)
		}
		if n != 1 {
			return nil, nil
		}
		v.Source, v.DraftBaseline = SourceDrafterRevision, &prev.Version
	default:
		return nil, nil
	}
	return &DraftRevision{
		Run: v.DraftRun.String(), Baseline: baseline,
		Proved:     provedPaths(dir),
		PrevProved: provedPaths(prevDir),
	}, nil
}

// provedPaths are the files of a package the proof covers: its manifest
// and the instruction file the manifest names. A package the proof cannot
// read covers none, so all of its files are diffed.
func provedPaths(dir string) []string {
	if dir == "" {
		return nil
	}
	_, instruction, err := draftproof.OfDir(dir)
	if err != nil {
		return nil
	}
	return []string{draftproof.ManifestFile, path.Clean(instruction)}
}
