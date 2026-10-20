package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/manifest"
)

// A release that ships knowledge packs makes their contents readable by
// everyone who can download it. The publisher confirms that when the
// release is uploaded through the API, naming each pack and, when the
// pack was laid down from a store, where it came from; the registry keeps
// the confirmation with the version. A release published by a tag push has
// no request to carry a confirmation, so its record says so.

// How a version's shipped packs came to be released.
const (
	// ShippedViaClient: the upload carried the publisher's confirmation.
	ShippedViaClient = "client"
	// ShippedViaTagPush: the release was built from a pushed or submitted
	// tag, which carries no confirmation.
	ShippedViaTagPush = "tag-push"
	// ShippedViaFork: the release is a fork's first version, copied from
	// the release it forks.
	ShippedViaFork = "fork"
)

// The kinds of store a shipped pack can be laid down from.
const (
	ShippedOriginOwn = "own"
	ShippedOriginOrg = "org"
)

// Problem slugs of a refused shipping confirmation.
const (
	SlugKnowledgeShippingUnacknowledged = "knowledge-shipping-unacknowledged"
	SlugKnowledgeShippingInvalid        = "knowledge-shipping-invalid"
)

// ShippedPackOrigin is the store pack a shipped pack was laid down from.
type ShippedPackOrigin struct {
	Kind   string    `json:"kind"`
	Org    string    `json:"org,omitempty"`
	PackID uuid.UUID `json:"packId"`
}

// ShippedPack is one pack of a release's shipped knowledge, as confirmed
// and as recorded. A pack with no origin is the publisher's own files.
type ShippedPack struct {
	Name   string             `json:"name"`
	Origin *ShippedPackOrigin `json:"origin,omitempty"`
}

// KnowledgeShipping is a publisher's confirmation that the packs a release
// ships become readable with it: one entry per shipped pack.
type KnowledgeShipping struct {
	Packs []ShippedPack
}

// ShippedKnowledgeRecord is what a version keeps of that confirmation.
// By is the account that confirmed; a release with no request to carry a
// confirmation has none.
type ShippedKnowledgeRecord struct {
	By    *uuid.UUID    `json:"by,omitempty"`
	At    time.Time     `json:"at"`
	Via   string        `json:"via"`
	Packs []ShippedPack `json:"packs"`
}

// ErrKnowledgeShipping reports a release whose shipped packs are not
// confirmed, or whose confirmation is wrong. Slug is the problem the API
// answers; Packs names the packs it is about.
type ErrKnowledgeShipping struct {
	Slug   string
	Packs  []string
	Detail string
}

func (e *ErrKnowledgeShipping) Error() string {
	return "registry: knowledge shipping: " + e.Detail
}

func shippingInvalid(pack, format string, args ...any) error {
	return &ErrKnowledgeShipping{
		Slug:   SlugKnowledgeShippingInvalid,
		Packs:  []string{pack},
		Detail: fmt.Sprintf("Pack %q: %s", pack, fmt.Sprintf(format, args...)),
	}
}

// shippedKnowledge is a submission's shipped packs after they are checked:
// the record the version keeps, and the organization packs that were
// shipped, each of which is audited with the version.
type shippedKnowledge struct {
	record   []byte
	orgPacks []orgShippedPack
}

type orgShippedPack struct {
	shippedAs string
	pack      storegen.KnowledgePack
}

// checkKnowledgeShipping decides whether a submission may ship the packs
// its manifest names. A tag-built release is recorded as such. An upload
// needs a confirmation naming exactly the packs shipped, and every origin
// it claims must be true: the pack is a ready one of the submitter's own,
// or of the organization that owns the agent's namespace and has the
// submitter as an administrator, and its digest is that of the tree the
// release carries. It returns nil when the release ships nothing.
func (s *Service) checkKnowledgeShipping(ctx context.Context, p *auth.Principal, a Agent, m *manifest.Manifest, in SubmitInput, now time.Time) (*shippedKnowledge, error) {
	ships := m.ShippedPacks()
	if in.Source == SourceGitTag {
		if len(ships) == 0 {
			return nil, nil
		}
		via := ShippedViaTagPush
		if in.shippedVia != "" {
			via = in.shippedVia
		}
		packs := make([]ShippedPack, 0, len(ships))
		for _, n := range ships {
			packs = append(packs, ShippedPack{Name: n})
		}
		raw, err := json.Marshal(ShippedKnowledgeRecord{At: now, Via: via, Packs: packs})
		if err != nil {
			return nil, err
		}
		return &shippedKnowledge{record: raw}, nil
	}

	claim := in.KnowledgeShipping
	if claim == nil {
		if len(ships) == 0 {
			return nil, nil
		}
		return nil, &ErrKnowledgeShipping{
			Slug:  SlugKnowledgeShippingUnacknowledged,
			Packs: ships,
			Detail: fmt.Sprintf("This release ships %s, which anyone who can download it can read. "+
				"Confirm that with knowledgeShipping, one entry for each pack shipped.", quoteList(ships)),
		}
	}

	byName := map[string]ShippedPack{}
	for _, c := range claim.Packs {
		if _, dup := byName[c.Name]; dup {
			return nil, shippingInvalid(c.Name, "it is confirmed twice.")
		}
		byName[c.Name] = c
		if !slices.Contains(ships, c.Name) {
			return nil, shippingInvalid(c.Name, "the release does not ship it.")
		}
	}
	var missing []string
	for _, n := range ships {
		if _, ok := byName[n]; !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrKnowledgeShipping{
			Slug:   SlugKnowledgeShippingUnacknowledged,
			Packs:  missing,
			Detail: fmt.Sprintf("This release ships %s without confirming it in knowledgeShipping.", quoteList(missing)),
		}
	}
	if len(ships) == 0 {
		return nil, nil
	}

	out := &shippedKnowledge{}
	packs := make([]ShippedPack, 0, len(ships))
	for _, n := range ships {
		c := byName[n]
		packs = append(packs, c)
		if c.Origin == nil {
			continue
		}
		stored, err := s.checkShippedOrigin(ctx, p, a, in.Workspace, n, *c.Origin)
		if err != nil {
			return nil, err
		}
		if c.Origin.Kind == ShippedOriginOrg {
			out.orgPacks = append(out.orgPacks, orgShippedPack{shippedAs: n, pack: stored})
		}
	}
	by := p.UserID
	raw, err := json.Marshal(ShippedKnowledgeRecord{By: &by, At: now, Via: ShippedViaClient, Packs: packs})
	if err != nil {
		return nil, err
	}
	out.record = raw
	return out, nil
}

// checkShippedOrigin holds one claimed origin to the facts and returns the
// store pack it names.
func (s *Service) checkShippedOrigin(ctx context.Context, p *auth.Principal, a Agent, workspace, name string, o ShippedPackOrigin) (storegen.KnowledgePack, error) {
	var ownerKind string
	var ownerID uuid.UUID
	switch o.Kind {
	case ShippedOriginOwn:
		if o.Org != "" {
			return storegen.KnowledgePack{}, shippingInvalid(name, "an origin of kind own names no organization.")
		}
		ownerKind, ownerID = "user", p.UserID
	case ShippedOriginOrg:
		// An organization's pack ships into that organization's namespace
		// and only from its administrators: the namespace is compared by
		// handle, so no other organization's roles or packs are consulted.
		if a.NamespaceKind != "org" || o.Org != a.Namespace {
			return storegen.KnowledgePack{}, shippingInvalid(name, "an organization's pack ships only into that organization's own namespace.")
		}
		if p.Role(a.NamespaceID) != auth.RoleAdmin {
			return storegen.KnowledgePack{}, shippingInvalid(name, "only an administrator of %s can ship its pack.", a.Namespace)
		}
		ownerKind, ownerID = "org", a.NamespaceID
	default:
		return storegen.KnowledgePack{}, shippingInvalid(name, "an origin is of kind own or org.")
	}
	stored, err := s.st.Queries().GetKnowledgePack(ctx, storegen.GetKnowledgePackParams{ID: o.PackID, OwnerKind: ownerKind, OwnerID: ownerID})
	if errors.Is(err, pgx.ErrNoRows) {
		return storegen.KnowledgePack{}, shippingInvalid(name, "its origin is not a pack you can ship.")
	}
	if err != nil {
		return storegen.KnowledgePack{}, fmt.Errorf("registry: shipped pack origin: %w", err)
	}
	if stored.State != "ready" {
		return storegen.KnowledgePack{}, shippingInvalid(name, "its origin is not ready; a pack ships once its scan has finished.")
	}
	shipped, err := shippedTreeDigest(workspace, name)
	if err != nil {
		return storegen.KnowledgePack{}, err
	}
	if stored.Digest == "" || stored.Digest != shipped {
		return storegen.KnowledgePack{}, shippingInvalid(name, "its files are not the origin pack's current content.")
	}
	return stored, nil
}

// shippedTreeDigest is the tree digest the shipped pack's own manifest.json
// states. The version's validation has already held the tree to it.
func shippedTreeDigest(workspace, name string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(workspace, manifest.KnowledgeDir, name, "manifest.json")) //nolint:gosec // server-created workspace; the name is a validated pack name
	if err != nil {
		return "", &ErrValidation{Issues: []error{fmt.Errorf("pack %q: manifest.json could not be read", name)}}
	}
	var pm struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &pm); err != nil {
		return "", &ErrValidation{Issues: []error{fmt.Errorf("pack %q: manifest.json does not parse", name)}}
	}
	return pm.SHA256, nil
}

// auditShippedOrgPacks writes org.knowledge_ship to each shipping
// organization's audit log, in the transaction that creates the version.
// The detail names the pack, the agent, the version and the submitter,
// never a byte of the pack.
func (s *Service) auditShippedOrgPacks(ctx context.Context, q *storegen.Queries, actorEvent audit.Event, a Agent, v Version, packs []orgShippedPack) error {
	for _, op := range packs {
		e := actorEvent
		e.Action = audit.ActionOrgKnowledgeShip
		e.OrgID = a.NamespaceID
		e.TargetKind, e.TargetID = "knowledge_pack", op.pack.ID
		e.Detail = map[string]any{
			"name": op.pack.Name, "shippedAs": op.shippedAs,
			"agent": a.Namespace + "/" + a.Name, "version": v.Version, "versionId": v.ID.String(),
			"submitter": actorEvent.Actor.String(),
		}
		if err := s.aud.Write(ctx, q, e); err != nil {
			return err
		}
	}
	return nil
}

// quoteList is names as a sentence fragment: "a", "a and b", "a, b and c".
func quoteList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = fmt.Sprintf("%q", n)
	}
	switch len(q) {
	case 0:
		return ""
	case 1:
		return "the pack " + q[0]
	}
	return "the packs " + strings.Join(q[:len(q)-1], ", ") + " and " + q[len(q)-1]
}

// ShippingVersion is a version of an agent that ships packs and has not
// been yanked or rejected.
type ShippingVersion struct {
	Version string
	Packs   []string
}

// VersionsShippingKnowledge lists the versions of an agent, other than
// yanked or rejected ones, that ship knowledge packs.
func VersionsShippingKnowledge(ctx context.Context, q *storegen.Queries, agentID uuid.UUID) ([]ShippingVersion, error) {
	rows, err := q.ListVersionsShippingKnowledge(ctx, agentID)
	if err != nil {
		return nil, err
	}
	out := make([]ShippingVersion, 0, len(rows))
	for _, r := range rows {
		var packs []string
		if err := json.Unmarshal(r.Packs, &packs); err != nil {
			return nil, fmt.Errorf("registry: version %s contract: %w", r.Version, err)
		}
		sort.Strings(packs)
		out = append(out, ShippingVersion{Version: r.Version, Packs: packs})
	}
	return out, nil
}

// ShippedKnowledgeOf reads a version's record; nil when it has none.
func ShippedKnowledgeOf(v Version) *ShippedKnowledgeRecord {
	if len(v.KnowledgeShipping) == 0 {
		return nil
	}
	var rec ShippedKnowledgeRecord
	if json.Unmarshal(v.KnowledgeShipping, &rec) != nil {
		return nil
	}
	return &rec
}
