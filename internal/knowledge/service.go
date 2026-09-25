package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/packseal"
)

// The states a pack is in.
const (
	StateEmpty    = "empty"
	StateScanning = "scanning"
	StateReady    = "ready"
	StateFailed   = "failed"
)

// JobScan is the pack scan's job kind; it runs on the sandbox queue, as a
// version's scan does, because it reads what an account uploaded.
const JobScan = "knowledge.scan"

// scanAttempts is the scan job's retry budget: a judge that fails on a
// chunk is retried until the last attempt, which records what it read.
const scanAttempts = 3

// MaxUpload bounds the body of a tree upload: a sealed tree of the largest
// tar a pack can be.
var MaxUpload = packseal.MaxSealedSize(MaxTreeBytes)

var (
	// ErrNotFound is a pack the caller does not own, or that does not
	// exist: the two are one answer.
	ErrNotFound = errors.New("knowledge: no such pack")
	// ErrNameTaken is a second pack of one name for one owner.
	ErrNameTaken = errors.New("knowledge: the owner already has a pack of this name")
	// ErrName is a name that is not a pack's.
	ErrName = errors.New("knowledge: a pack name is 1-64 lowercase letters, digits, '.', '-' or '_', starting with a letter or a digit")
)

// AllocationError is an upload past the owner's allocation: what they
// would keep and the cap (D5, D25).
type AllocationError struct {
	Bytes int64
	Max   int64
}

func (e *AllocationError) Error() string {
	return fmt.Sprintf("knowledge: %d bytes of knowledge would pass the allocation of %d", e.Bytes, e.Max)
}

// Scanner is what reads a pack: the scan orchestrator.
type Scanner interface {
	ScanPack(ctx context.Context, files []scan.PackFile) scan.PackReport
}

// Service is the registry's knowledge store.
type Service struct {
	st      *store.Store
	blobs   registry.BlobStore
	wrapper KeyWrapper
	scanner Scanner
	jobs    queue.Client
	ents    func() entitlements.Resolver
	log     *slog.Logger
}

// Deps is what the service is built from.
type Deps struct {
	Store   *store.Store
	Blobs   registry.BlobStore
	Wrapper KeyWrapper
	Scanner Scanner
	Jobs    queue.Client
	// Entitlements answers the owner's allocation; read on every upload,
	// so a resolver swapped in later (an extension's) is the one asked.
	Entitlements func() entitlements.Resolver
	Log          *slog.Logger
}

// NewService builds the store. A nil Wrapper leaves it off: every call
// answers ErrUnconfigured.
func NewService(d Deps) *Service {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Service{st: d.Store, blobs: d.Blobs, wrapper: d.Wrapper, scanner: d.Scanner, jobs: d.Jobs, ents: d.Entitlements, log: log}
}

// SetWrapper replaces the key wrapper: an extension's (pkg/extension
// WrapsKeys) in place of the deployment key.
func (s *Service) SetWrapper(w KeyWrapper) { s.wrapper = w }

// Wrapper is the key wrapper in use, nil when the store is off.
func (s *Service) Wrapper() KeyWrapper { return s.wrapper }

// Configured says whether the store is on.
func (s *Service) Configured() bool {
	return s != nil && s.wrapper != nil && s.st != nil && s.blobs != nil
}

func (s *Service) ready() error {
	if !s.Configured() {
		return ErrUnconfigured
	}
	return nil
}

// ValidName is the CLI's rule for a pack name (agentry-cli
// pkg/knowledge.ValidName): the name is the pack's directory.
func ValidName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '-' || r == '_'):
		default:
			return false
		}
	}
	return true
}

// Wrap wraps a data key for owner.
func (s *Service) Wrap(ctx context.Context, owner Owner, dataKey []byte) (WrappedKey, error) {
	if err := s.ready(); err != nil {
		return WrappedKey{}, err
	}
	return s.wrapper.Wrap(ctx, owner, dataKey)
}

// Unwrap opens a wrapped key for owner, or refuses with ErrNotOwner.
func (s *Service) Unwrap(ctx context.Context, owner Owner, w WrappedKey) ([]byte, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	key, err := s.wrapper.Unwrap(ctx, owner, w)
	if err != nil {
		return nil, err
	}
	if len(key) != packseal.KeySize {
		return nil, ErrNotOwner
	}
	return key, nil
}

func wrappedOf(p storegen.KnowledgePack) WrappedKey {
	return WrappedKey{Kind: p.WrapperKind, Recipient: p.WrapperRecipient, Blob: p.WrappedKey}
}

// Create makes an empty pack whose data key is w, which must open for
// owner: a pack is never created with a key its owner cannot use.
func (s *Service) Create(ctx context.Context, owner Owner, name string, w WrappedKey) (storegen.KnowledgePack, error) {
	if err := s.ready(); err != nil {
		return storegen.KnowledgePack{}, err
	}
	if !ValidName(name) {
		return storegen.KnowledgePack{}, ErrName
	}
	if _, err := s.Unwrap(ctx, owner, w); err != nil {
		return storegen.KnowledgePack{}, err
	}
	p, err := s.st.Queries().CreateKnowledgePack(ctx, storegen.CreateKnowledgePackParams{
		OwnerKind: string(owner.Kind), OwnerID: owner.ID, Name: name,
		WrapperKind: w.Kind, WrapperRecipient: w.Recipient, WrappedKey: w.Blob,
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return storegen.KnowledgePack{}, ErrNameTaken
	}
	return p, err
}

// List is owner's packs, by name.
func (s *Service) List(ctx context.Context, owner Owner) ([]storegen.KnowledgePack, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.st.Queries().ListKnowledgePacks(ctx, storegen.ListKnowledgePacksParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID})
}

// Get is one of owner's packs.
func (s *Service) Get(ctx context.Context, owner Owner, id uuid.UUID) (storegen.KnowledgePack, error) {
	if err := s.ready(); err != nil {
		return storegen.KnowledgePack{}, err
	}
	p, err := s.st.Queries().GetKnowledgePack(ctx, storegen.GetKnowledgePackParams{ID: id, OwnerKind: string(owner.Kind), OwnerID: owner.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// Sizes is what platform staff see of owner's packs: names and sizes.
func (s *Service) Sizes(ctx context.Context, owner Owner) ([]storegen.ListKnowledgePackSizesRow, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.st.Queries().ListKnowledgePackSizes(ctx, storegen.ListKnowledgePackSizesParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID})
}

// Usage is what an owner keeps in the registry against their allocation.
type Usage struct {
	Bytes int64
	// Max is the allocation; 0 is no cap.
	Max   int64
	Packs int
}

// Usage is owner's meter.
func (s *Service) Usage(ctx context.Context, owner Owner) (Usage, error) {
	rows, err := s.List(ctx, owner)
	if err != nil {
		return Usage{}, err
	}
	u := Usage{Packs: len(rows)}
	for _, p := range rows {
		u.Bytes += p.Bytes
	}
	c, err := s.allocation(ctx, owner)
	if err != nil {
		return Usage{}, err
	}
	u.Max = c.Max
	return u, nil
}

// allocation is owner's knowledge cap. An unknown answer is not permission.
func (s *Service) allocation(ctx context.Context, owner Owner) (entitlements.Cap, error) {
	res := entitlements.Default()
	var r entitlements.Resolver = res
	if s.ents != nil && s.ents() != nil {
		r = s.ents()
	}
	subject := entitlements.ForUser(owner.ID)
	if owner.Kind == OwnerOrg {
		subject = entitlements.ForOrg(owner.ID)
	}
	f, err := r.Features(ctx, subject)
	if err != nil {
		return entitlements.Cap{}, fmt.Errorf("knowledge: entitlements: %w", err)
	}
	return f.KnowledgeBytes, nil
}

// objectKey is where a sealed tree lives: under its owner's prefix.
func objectKey(owner Owner, pack uuid.UUID) string {
	return fmt.Sprintf("knowledge/%s/%s/%s/%s.sealed", owner.Kind, owner.ID, pack, uuid.New())
}

// Upload stores a pack's new sealed tree and queues its scan. The registry
// opens it first — the data key unwrapped for owner, the tree read and its
// digest checked — so that what it keeps is always a pack, and counts it
// against the owner's allocation under a lock on the owner, then stores it
// sealed as it came.
func (s *Service) Upload(ctx context.Context, owner Owner, id uuid.UUID, sealed []byte) (storegen.KnowledgePack, error) {
	p, err := s.Get(ctx, owner, id)
	if err != nil {
		return p, err
	}
	tree, err := s.open(ctx, owner, p, bytes.NewReader(sealed))
	if err != nil {
		return p, err
	}
	key := objectKey(owner, id)
	// The blob first: a row never names an object that is not there. An
	// upload refused below leaves a sealed blob nothing names, which is
	// deleted before returning.
	if err := s.blobs.Put(ctx, key, bytes.NewReader(sealed)); err != nil {
		return p, fmt.Errorf("knowledge: store tree: %w", err)
	}
	var replaced []string
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if err := q.LockKey(ctx, "knowledge:"+owner.String()); err != nil {
			return err
		}
		cur, err := q.GetKnowledgePackForUpdate(ctx, storegen.GetKnowledgePackForUpdateParams{ID: id, OwnerKind: string(owner.Kind), OwnerID: owner.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		c, err := s.allocation(ctx, owner)
		if err != nil {
			return err
		}
		others, err := q.SumKnowledgeBytes(ctx, storegen.SumKnowledgeBytesParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID, ExceptID: id})
		if err != nil {
			return err
		}
		// A cap never deletes (D25): a tree no larger than the one it
		// replaces is always taken; one that grows must fit.
		if tree.Bytes > cur.Bytes && (!c.Enabled || (c.Max > 0 && others+tree.Bytes > c.Max)) {
			return &AllocationError{Bytes: others + tree.Bytes, Max: c.Max}
		}
		if err := q.CreateKnowledgeObject(ctx, storegen.CreateKnowledgeObjectParams{
			Key: key, PackID: id, OwnerKind: string(owner.Kind), OwnerID: owner.ID, Bytes: int64(len(sealed)),
		}); err != nil {
			return err
		}
		keys, err := q.ListKnowledgeObjectsOfPack(ctx, id)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if k != key {
				replaced = append(replaced, k)
				if err := q.DeleteKnowledgeObject(ctx, k); err != nil {
					return err
				}
			}
		}
		p, err = q.SetKnowledgeTree(ctx, storegen.SetKnowledgeTreeParams{
			ID: id, Bytes: tree.Bytes, Files: int32(len(tree.Files)), Pages: int32(tree.Pages), Digest: tree.Digest, ObjectKey: key,
		})
		if err != nil {
			return err
		}
		if s.jobs == nil {
			return errors.New("knowledge: no queue to scan the pack on")
		}
		_, err = s.jobs.Enqueue(ctx, JobScan, "sandbox", ScanArgs{Pack: id, Object: key}, queue.WithMaxAttempts(scanAttempts))
		return err
	})
	if err != nil {
		s.deleteBlobs(ctx, key)
		return p, err
	}
	s.deleteBlobs(ctx, replaced...)
	return p, nil
}

// open reads a sealed tree of p: the header names the pack's digest, the
// data key opens it, and the tree inside is that digest.
func (s *Service) open(ctx context.Context, owner Owner, p storegen.KnowledgePack, r io.Reader) (*Tree, error) {
	key, err := s.Unwrap(ctx, owner, wrappedOf(p))
	if err != nil {
		return nil, err
	}
	h, plain, err := packseal.Open(r, key)
	if err != nil {
		return nil, err
	}
	return ReadTree(plain, h.Digest)
}

// SealedTree is the stored sealed tree of one of owner's packs.
func (s *Service) SealedTree(ctx context.Context, owner Owner, id uuid.UUID) (storegen.KnowledgePack, io.ReadCloser, error) {
	p, err := s.Get(ctx, owner, id)
	if err != nil {
		return p, nil, err
	}
	if p.ObjectKey == "" {
		return p, nil, ErrNotFound
	}
	rc, err := s.blobs.Get(ctx, p.ObjectKey)
	return p, rc, err
}

// Export writes one of owner's packs' tree, decrypted: the canonical tar
// whose digest is the pack's. It is opened and checked in full before a
// byte is written, so a tree that does not open writes nothing.
func (s *Service) Export(ctx context.Context, owner Owner, id uuid.UUID) (storegen.KnowledgePack, *Tree, error) {
	p, rc, err := s.SealedTree(ctx, owner, id)
	if err != nil {
		return p, nil, err
	}
	defer func() { _ = rc.Close() }()
	tree, err := s.open(ctx, owner, p, rc)
	return p, tree, err
}

// Delete removes one of owner's packs, its objects and their blobs.
func (s *Service) Delete(ctx context.Context, owner Owner, id uuid.UUID) error {
	if err := s.ready(); err != nil {
		return err
	}
	var keys []string
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		var err error
		if keys, err = q.ListKnowledgeObjectsOfPack(ctx, id); err != nil {
			return err
		}
		_, err = q.DeleteKnowledgePack(ctx, storegen.DeleteKnowledgePackParams{ID: id, OwnerKind: string(owner.Kind), OwnerID: owner.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return err
	}
	s.deleteBlobs(ctx, keys...)
	return nil
}

// EraseOwner deletes every pack of owner on q, the caller's transaction:
// the account erasure, a data clear, an organization's decommission. It
// returns the blob keys, which Destroyed takes once the transaction has
// committed. It runs whether or not the store is on, so that turning it off
// strands nothing an erasure should remove.
func EraseOwner(ctx context.Context, q *storegen.Queries, owner Owner) ([]string, error) {
	keys, err := q.DeleteKnowledgeObjectsOfOwner(ctx, storegen.DeleteKnowledgeObjectsOfOwnerParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID})
	if err != nil {
		return nil, err
	}
	if _, err := q.DeleteKnowledgePacksOfOwner(ctx, storegen.DeleteKnowledgePacksOfOwnerParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID}); err != nil {
		return nil, err
	}
	return keys, nil
}

// Destroyed finishes an owner's erasure after its transaction committed:
// the wrapper destroys what opens the owner's keys, then the blobs go.
// Either failing is logged, never hidden, and undoes nothing: a blob left
// behind is sealed under a data key no one can unwrap any more.
func (s *Service) Destroyed(ctx context.Context, owner Owner, keys []string) error {
	var err error
	if s != nil && s.wrapper != nil {
		if err = s.wrapper.Destroy(ctx, owner); err != nil {
			s.log.ErrorContext(ctx, "knowledge: destroy the owner's keys", "owner", owner.String(), "err", err)
		}
	}
	if s != nil {
		s.deleteBlobs(ctx, keys...)
	}
	return err
}

func (s *Service) deleteBlobs(ctx context.Context, keys ...string) {
	if s.blobs == nil {
		return
	}
	for _, k := range keys {
		if err := s.blobs.Delete(ctx, k); err != nil {
			s.log.ErrorContext(ctx, "knowledge: delete a sealed tree", "key", k, "err", err)
		}
	}
}

// ScanArgs names the tree a scan job reads.
type ScanArgs struct {
	Pack   uuid.UUID `json:"pack"`
	Object string    `json:"object"`
}

// RegisterHandlers wires the scan job.
func (s *Service) RegisterHandlers(q queue.Client) {
	q.Register(JobScan, func(ctx context.Context, job queue.Job) error {
		var args ScanArgs
		if err := json.Unmarshal(job.Args, &args); err != nil {
			return fmt.Errorf("%s: bad args: %w", JobScan, err)
		}
		return s.scanPack(ctx, args, job.Attempt >= scanAttempts)
	})
}

// scanPack reads the tree the job names and records its report. A tree
// since replaced is not scanned: its successor has a job of its own. A
// review that failed on a chunk is retried until the last attempt, which
// records what it read (D27: the report is a record, never a gate).
func (s *Service) scanPack(ctx context.Context, args ScanArgs, last bool) error {
	if err := s.ready(); err != nil {
		return err
	}
	if s.scanner == nil {
		return errors.New("knowledge: no scanner on this role")
	}
	q := s.st.Queries()
	p, err := q.GetKnowledgePackByObject(ctx, storegen.GetKnowledgePackByObjectParams{ID: args.Pack, ObjectKey: args.Object})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.State != StateScanning {
		return nil
	}
	owner := Owner{Kind: OwnerKind(p.OwnerKind), ID: p.OwnerID}
	rc, err := s.blobs.Get(ctx, p.ObjectKey)
	if err != nil {
		return s.failScan(ctx, p, last, fmt.Errorf("read the stored tree: %w", err))
	}
	tree, err := s.open(ctx, owner, p, rc)
	_ = rc.Close()
	if err != nil {
		return s.failScan(ctx, p, last, err)
	}
	if tree.Digest != p.Digest {
		return s.failScan(ctx, p, last, ErrDigest)
	}
	report := s.scanner.ScanPack(ctx, tree.Files)
	if !report.Complete() && !last {
		return fmt.Errorf("knowledge: AI Review of pack %s is incomplete (%d chunks failed); retrying", p.ID, report.Review.Failed)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = q.FinishKnowledgeScan(ctx, storegen.FinishKnowledgeScanParams{State: StateReady, Report: raw, ID: p.ID, ObjectKey: p.ObjectKey})
	return err
}

// failScan retries a tree that could not be read, and on the last attempt
// records the pack as failed, with no report: nothing was read.
func (s *Service) failScan(ctx context.Context, p storegen.KnowledgePack, last bool, cause error) error {
	s.log.ErrorContext(ctx, "knowledge: scan could not read the pack", "pack", p.ID, "err", cause)
	if !last {
		return cause
	}
	_, err := s.st.Queries().FinishKnowledgeScan(ctx, storegen.FinishKnowledgeScanParams{State: StateFailed, Report: nil, ID: p.ID, ObjectKey: p.ObjectKey})
	return err
}
