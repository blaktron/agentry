package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/manifest"
	"github.com/blaktron/agentry/pkg/packseal"
)

// State is where a pack is in its life.
type State string

// The states a pack is in: empty until a tree is uploaded, scanning from
// each upload until its scan ends, ready after it whatever it found,
// failed when the stored tree could not be read to scan.
const (
	StateEmpty    State = "empty"
	StateScanning State = "scanning"
	StateReady    State = "ready"
	StateFailed   State = "failed"
)

// The job kinds: the pack scan runs on the sandbox queue, as a version's
// scan does, because it reads what an account uploaded; the retry of an
// erasure's last step and the sweep that queues a lost scan again on the
// core queue, since they read no content.
const (
	JobScan      = "knowledge.scan"
	JobErase     = "knowledge.erase"
	JobScanSweep = "knowledge.scan.sweep"
)

// ScanStallAfter is how long a pack waits scanning since its tree was
// stored, or since the sweep last queued its scan, before the sweep
// queues the scan again: well past a scan job's whole retry budget, so a
// scan still being tried is not doubled.
const ScanStallAfter = time.Hour

// scanAttempts is the scan job's retry budget: a scan that did not finish
// (a stage failed, the judge failed on a chunk) is retried until the last
// attempt, which records what it read.
const scanAttempts = 3

// MaxUpload bounds the body of a tree upload: a sealed tree of the largest
// tar a pack can be.
func MaxUpload() int64 { return packseal.MaxSealedSize(MaxTreeBytes) }

var (
	// ErrNotFound is a pack the caller does not own, or that does not
	// exist: the two are one answer.
	ErrNotFound = errors.New("knowledge: no such pack")
	// ErrNameTaken is a second pack of one name for one owner.
	ErrNameTaken = errors.New("knowledge: the owner already has a pack of this name")
	// ErrName is a name that is not a pack's.
	ErrName = errors.New("knowledge: a pack name is 1-64 lowercase letters, digits, '.', '-' or '_', starting with a letter or a digit")
	// ErrScanning is a pack whose tree is being scanned: a pack is
	// unusable only then.
	ErrScanning = errors.New("knowledge: the pack is being scanned")
)

// AllocationError is an upload past the owner's allocation: what they
// would keep and the cap.
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
func ValidName(name string) bool { return manifest.ValidKnowledgePackName(name) }

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

// WrappedKeyOf is a pack's data key as its row holds it.
func WrappedKeyOf(p storegen.KnowledgePack) WrappedKey {
	return WrappedKey{Kind: p.WrapperKind, Recipient: p.WrapperRecipient, Blob: p.WrappedKey}
}

// Also is what a caller records in the same transaction as a change to a
// pack — an organization's audit event — so the change and its record
// commit or roll back together. It sees the pack as the change left it.
type Also func(q *storegen.Queries, p storegen.KnowledgePack) error

// Create makes an empty pack whose data key is w, which must open for
// owner: a pack is never created with a key its owner cannot use. also,
// when given, runs in the same transaction.
func (s *Service) Create(ctx context.Context, owner Owner, name string, w WrappedKey, also Also) (storegen.KnowledgePack, error) {
	if err := s.ready(); err != nil {
		return storegen.KnowledgePack{}, err
	}
	if !ValidName(name) {
		return storegen.KnowledgePack{}, ErrName
	}
	if _, err := s.Unwrap(ctx, owner, w); err != nil {
		return storegen.KnowledgePack{}, err
	}
	var p storegen.KnowledgePack
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		var err error
		p, err = q.CreateKnowledgePack(ctx, storegen.CreateKnowledgePackParams{
			OwnerKind: string(owner.Kind), OwnerID: owner.ID, Name: name,
			WrapperKind: w.Kind, WrapperRecipient: w.Recipient, WrappedKey: w.Blob,
		})
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrNameTaken
		}
		if err != nil {
			return fmt.Errorf("knowledge: create pack: %w", err)
		}
		if also != nil {
			return also(q, p)
		}
		return nil
	})
	if err != nil {
		return storegen.KnowledgePack{}, err
	}
	return p, nil
}

// SetExportable marks whether one of an organization's packs may be
// exported by its members, with also run in its transaction. A
// person's own pack has no such mark: its owner exports it.
func (s *Service) SetExportable(ctx context.Context, owner Owner, id uuid.UUID, exportable bool, also Also) (storegen.KnowledgePack, error) {
	if err := s.ready(); err != nil {
		return storegen.KnowledgePack{}, err
	}
	if owner.Kind != OwnerOrg {
		return storegen.KnowledgePack{}, ErrNotFound
	}
	var p storegen.KnowledgePack
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		var err error
		p, err = q.SetKnowledgePackExportable(ctx, storegen.SetKnowledgePackExportableParams{ID: id, OwnerKind: string(owner.Kind), OwnerID: owner.ID, Exportable: exportable})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("knowledge: mark the pack: %w", err)
		}
		if also != nil {
			return also(q, p)
		}
		return nil
	})
	if err != nil {
		return storegen.KnowledgePack{}, err
	}
	return p, nil
}

// List is owner's packs, by name.
func (s *Service) List(ctx context.Context, owner Owner) ([]storegen.KnowledgePack, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	rows, err := s.st.Queries().ListKnowledgePacks(ctx, storegen.ListKnowledgePacksParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID})
	if err != nil {
		return nil, fmt.Errorf("knowledge: list packs: %w", err)
	}
	return rows, nil
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
	if err != nil {
		return p, fmt.Errorf("knowledge: read pack: %w", err)
	}
	return p, nil
}

// Sizes is what platform staff see of owner's packs: names and sizes.
func (s *Service) Sizes(ctx context.Context, owner Owner) ([]storegen.ListKnowledgePackSizesRow, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	rows, err := s.st.Queries().ListKnowledgePackSizes(ctx, storegen.ListKnowledgePackSizesParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID})
	if err != nil {
		return nil, fmt.Errorf("knowledge: list pack sizes: %w", err)
	}
	return rows, nil
}

// Usage is an owner's meter: what the owner keeps, and the allocation it
// draws on — the owner's own, or a pool an extension shares among owners,
// whose total every owner in it sees.
type Usage struct {
	// Bytes and Packs are the owner's own packs.
	Bytes int64
	Packs int
	// Used is what counts against the allocation: Bytes, or the pool's
	// total when Pooled.
	Used int64
	// Max is the allocation; 0 is no cap.
	Max    int64
	Pooled bool
}

// Usage is owner's meter.
func (s *Service) Usage(ctx context.Context, owner Owner) (Usage, error) {
	rows, err := s.List(ctx, owner)
	if err != nil {
		return Usage{}, err
	}
	pool, err := s.pool(ctx, owner)
	if err != nil {
		return Usage{}, err
	}
	used, err := s.st.Queries().SumKnowledgeBytesOfPool(ctx, pool.sumParams(uuid.Nil))
	if err != nil {
		return Usage{}, fmt.Errorf("knowledge: count the allocation: %w", err)
	}
	u := Usage{Packs: len(rows), Used: used, Max: pool.Cap.Max, Pooled: pool.pooled(owner)}
	for _, p := range rows {
		u.Bytes += p.Bytes
	}
	return u, nil
}

// resolver is the entitlements resolver the server holds now.
func (s *Service) resolver() entitlements.Resolver {
	if s.ents != nil && s.ents() != nil {
		return s.ents()
	}
	return entitlements.Default()
}

// pool is the allocation owner's packs draw on: an extension's answer when
// its resolver pools owners (Pools), else the owner alone under
// Features.KnowledgeBytes. An unknown answer is not permission, and neither
// is a pool with no key or one that does not count its own owner.
func (s *Service) pool(ctx context.Context, owner Owner) (Pool, error) {
	r := s.resolver()
	if p, ok := r.(Pools); ok {
		pool, err := p.KnowledgePool(ctx, owner)
		if err != nil {
			return Pool{}, fmt.Errorf("knowledge: entitlements: %w", err)
		}
		if pool.Key == "" {
			return Pool{}, fmt.Errorf("knowledge: entitlements: the pool for %s has no key", owner)
		}
		if !slices.Contains(pool.Owners, owner) {
			return Pool{}, fmt.Errorf("knowledge: entitlements: the pool for %s does not count its owner", owner)
		}
		return pool, nil
	}
	subject := entitlements.ForUser(owner.ID)
	if owner.Kind == OwnerOrg {
		subject = entitlements.ForOrg(owner.ID)
	}
	f, err := r.Features(ctx, subject)
	if err != nil {
		return Pool{}, fmt.Errorf("knowledge: entitlements: %w", err)
	}
	return Pool{Key: owner.String(), Owners: []Owner{owner}, Cap: f.KnowledgeBytes}, nil
}

// lockPool reserves owner's pool on q and answers it as it stands under the
// lock: the pool is resolved, its key locked, and the pool read again, so
// its owners and cap are the ones the lock serialises. A pool whose key
// moved in between (an owner joining or leaving) is locked under its new key
// as well.
func (s *Service) lockPool(ctx context.Context, q *storegen.Queries, owner Owner) (Pool, error) {
	locked := map[string]bool{}
	for {
		pool, err := s.pool(ctx, owner)
		if err != nil {
			return Pool{}, err
		}
		if locked[pool.Key] {
			return pool, nil
		}
		if err := q.LockKey(ctx, "knowledge:"+pool.Key); err != nil {
			return Pool{}, fmt.Errorf("knowledge: lock the allocation: %w", err)
		}
		locked[pool.Key] = true
		if len(locked) > 3 {
			return Pool{}, errors.New("knowledge: the allocation kept moving; retry")
		}
	}
}

// objectKey is where a sealed tree lives: under its owner's prefix.
func objectKey(owner Owner, pack uuid.UUID) string {
	return fmt.Sprintf("knowledge/%s/%s/%s/%s.sealed", owner.Kind, owner.ID, pack, uuid.New())
}

// Upload stores a pack's new sealed tree and queues its scan. The registry
// opens it first — the data key unwrapped for owner, the tree read and its
// digest checked — so that what it keeps is always a pack, and counts it
// against the allocation owner's packs draw on, under a lock on that pool,
// then stores it sealed as it came.
func (s *Service) Upload(ctx context.Context, owner Owner, id uuid.UUID, sealed []byte) (storegen.KnowledgePack, error) {
	return s.UploadAdmitted(ctx, owner, id, sealed, nil)
}

// UploadAdmission is what an upload that will queue a scan is admitted
// on: the pack and the tree read from the body.
type UploadAdmission struct {
	Owner Owner
	Pack  uuid.UUID
	Bytes int64
	Files int
}

// Admit admits an upload that will queue a scan. It is asked once, after
// the tree is read and checked against the allocation, and before anything
// is stored; an error refuses the upload with nothing stored. ticket, when
// not empty, is recorded as stored (admitted_stores, kind "knowledge") in
// the transaction that stores the tree. release is called once with
// whether that transaction committed, so a ticket for an upload the core
// then refused (the allocation cap, a lost race, a panic) can be voided.
type Admit func(ctx context.Context, a UploadAdmission) (ticket string, release func(stored bool), err error)

// UploadAdmitted is Upload with admit asked first. An upload of the tree
// the pack already holds, scanned or being scanned, stores nothing and
// queues no scan, so it is never admitted; one that failed to scan is
// scanned again unadmitted, since the failure was the registry's.
func (s *Service) UploadAdmitted(ctx context.Context, owner Owner, id uuid.UUID, sealed []byte, admit Admit) (storegen.KnowledgePack, error) {
	return s.upload(ctx, owner, id, sealed, nil, admit)
}

// upload is the one path a tree is stored by, through the route and
// through an extension's Replace alike; check, when given, is asked about
// the pack as it stands under its row lock, and its error refuses the
// upload with nothing stored.
func (s *Service) upload(ctx context.Context, owner Owner, id uuid.UUID, sealed []byte, check func(storegen.KnowledgePack) error, admit Admit) (storegen.KnowledgePack, error) {
	p, err := s.Get(ctx, owner, id)
	if err != nil {
		return p, err
	}
	tree, err := s.open(ctx, owner, p, bytes.NewReader(sealed))
	if err != nil {
		return p, err
	}
	// ticket is the admission this upload stores under, recorded with the
	// tree; stored turns true only once the tree's transaction committed,
	// so a refusal, an error and a panic alike release the admission as
	// not stored.
	var (
		ticket string
		stored bool
	)
	if admit != nil {
		held := p.ObjectKey != "" && p.Digest == tree.Digest
		switch {
		case held && State(p.State) != StateFailed:
			return p, nil
		case !held:
			// The allocation first, read without the lock: an upload it
			// refuses is refused for that, not for whatever the admission
			// would answer, and nothing is charged for it. The reservation
			// under the lock below stays the authority, so an upload that
			// passes here and loses a race to the cap is still refused,
			// and its ticket voided.
			if err := s.precheckAllocation(ctx, owner, p, tree.Bytes); err != nil {
				return p, err
			}
			t, release, aerr := admit(ctx, UploadAdmission{Owner: owner, Pack: id, Bytes: tree.Bytes, Files: len(tree.Files)})
			if aerr != nil {
				return p, aerr
			}
			ticket = t
			defer func() { release(stored) }()
		}
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
		pool, err := s.lockPool(ctx, q, owner)
		if err != nil {
			return err
		}
		cur, err := q.GetKnowledgePackForUpdate(ctx, storegen.GetKnowledgePackForUpdateParams{ID: id, OwnerKind: string(owner.Kind), OwnerID: owner.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("knowledge: lock pack: %w", err)
		}
		if check != nil {
			if err := check(cur); err != nil {
				return err
			}
		}
		others, err := q.SumKnowledgeBytesOfPool(ctx, pool.sumParams(id))
		if err != nil {
			return fmt.Errorf("knowledge: count the allocation: %w", err)
		}
		if err := pool.fits(others, cur.Bytes, tree.Bytes); err != nil {
			return err
		}
		if err := q.CreateKnowledgeObject(ctx, storegen.CreateKnowledgeObjectParams{
			Key: key, PackID: id, OwnerKind: string(owner.Kind), OwnerID: owner.ID, Bytes: int64(len(sealed)),
		}); err != nil {
			return fmt.Errorf("knowledge: record the tree: %w", err)
		}
		keys, err := q.ListKnowledgeObjectsOfPack(ctx, id)
		if err != nil {
			return fmt.Errorf("knowledge: list the pack's trees: %w", err)
		}
		for _, k := range keys {
			if k != key {
				replaced = append(replaced, k)
				if err := q.DeleteKnowledgeObject(ctx, k); err != nil {
					return fmt.Errorf("knowledge: drop the tree replaced: %w", err)
				}
			}
		}
		p, err = q.SetKnowledgeTree(ctx, storegen.SetKnowledgeTreeParams{
			ID: id, Bytes: tree.Bytes, Files: int32(len(tree.Files)), Pages: int32(tree.Pages), Digest: tree.Digest, ObjectKey: key, //nolint:gosec // bounded by MaxFiles
		})
		if err != nil {
			return fmt.Errorf("knowledge: set the tree: %w", err)
		}
		if ticket != "" {
			if err := q.RecordAdmittedStore(ctx, storegen.RecordAdmittedStoreParams{Ticket: ticket, Kind: admittedKind}); err != nil {
				return fmt.Errorf("knowledge: record the admission: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		s.deleteBlobs(ctx, key)
		return p, err
	}
	stored = true
	s.deleteBlobs(ctx, replaced...)
	// The scan is queued once the tree has committed: a worker can take a
	// job at once, on another connection, and a scan queued inside the
	// transaction could run first, find no tree and end with the pack
	// scanning for good. A scan that cannot be queued now is logged, and
	// the sweep queues it.
	if qerr := s.queueScan(ctx, id, key); qerr != nil {
		s.log.ErrorContext(ctx, "knowledge: queue a scan; the sweep will", "pack", id, "err", qerr)
	}
	return p, nil
}

// queueScan queues the scan of the tree key holds for pack id.
func (s *Service) queueScan(ctx context.Context, id uuid.UUID, key string) error {
	if s.jobs == nil {
		return errors.New("knowledge: no queue to scan the pack on")
	}
	_, err := s.jobs.Enqueue(ctx, JobScan, "sandbox", ScanArgs{Pack: id, Object: key}, queue.WithMaxAttempts(scanAttempts))
	return err
}

// SweepScans queues the scan again of every pack still scanning since
// before cutoff, its tree stored or its scan last queued then, and
// reports how many. It is how a pack whose scan was never queued, or whose
// job was lost, reaches ready or failed: a scan's own last attempt fails
// the pack rather than leave it scanning.
func (s *Service) SweepScans(ctx context.Context, cutoff time.Time) (int, error) {
	if !s.Configured() {
		return 0, nil
	}
	q := s.st.Queries()
	rows, err := q.ListStalledKnowledgeScans(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("knowledge: list stalled scans: %w", err)
	}
	n := 0
	for _, r := range rows {
		// Touched first, so a sweep that fails after it does not queue the
		// same scan again on its next pass before this one has run.
		touched, err := q.TouchKnowledgeScan(ctx, storegen.TouchKnowledgeScanParams(r))
		if err != nil {
			return n, fmt.Errorf("knowledge: touch a stalled scan: %w", err)
		}
		if touched == 0 {
			continue // its scan ended, or a new tree replaced it, meanwhile
		}
		if err := s.queueScan(ctx, r.ID, r.ObjectKey); err != nil {
			return n, fmt.Errorf("knowledge: queue a stalled scan: %w", err)
		}
		n++
	}
	if n > 0 {
		s.log.InfoContext(ctx, "knowledge: scans queued again", "count", n)
	}
	return n, nil
}

// admittedKind is a knowledge upload's kind in admitted_stores.
const admittedKind = "knowledge"

// precheckAllocation is the allocation rule on the pool as it stands,
// read without its lock: the pack p's tree of next bytes would replace the
// one it holds. It answers the AllocationError the locked reservation
// would, so an upload past the allocation is refused before anything is
// admitted or charged.
func (s *Service) precheckAllocation(ctx context.Context, owner Owner, p storegen.KnowledgePack, next int64) error {
	pool, err := s.pool(ctx, owner)
	if err != nil {
		return err
	}
	others, err := s.st.Queries().SumKnowledgeBytesOfPool(ctx, pool.sumParams(p.ID))
	if err != nil {
		return fmt.Errorf("knowledge: count the allocation: %w", err)
	}
	return pool.fits(others, p.Bytes, next)
}

// open reads a sealed tree of p: the header names the pack's digest, the
// data key opens it, and the tree inside is that digest.
func (s *Service) open(ctx context.Context, owner Owner, p storegen.KnowledgePack, r io.Reader) (*Tree, error) {
	key, err := s.Unwrap(ctx, owner, WrappedKeyOf(p))
	if err != nil {
		return nil, err
	}
	h, plain, err := packseal.Open(r, key)
	if err != nil {
		return nil, err
	}
	return ReadTree(plain, h.Digest)
}

// usable is one of owner's packs with a tree that is not being scanned.
func (s *Service) usable(ctx context.Context, owner Owner, id uuid.UUID) (storegen.KnowledgePack, error) {
	p, err := s.Get(ctx, owner, id)
	if err != nil {
		return p, err
	}
	if State(p.State) == StateScanning {
		return p, ErrScanning
	}
	if p.ObjectKey == "" {
		return p, ErrNotFound
	}
	return p, nil
}

// SealedTree is the stored sealed tree of one of owner's packs.
func (s *Service) SealedTree(ctx context.Context, owner Owner, id uuid.UUID) (storegen.KnowledgePack, io.ReadCloser, error) {
	p, err := s.usable(ctx, owner, id)
	if err != nil {
		return p, nil, err
	}
	rc, err := s.blobs.Get(ctx, p.ObjectKey)
	if err != nil {
		return p, nil, fmt.Errorf("knowledge: read the stored tree: %w", err)
	}
	return p, rc, nil
}

// Export is one of owner's packs' tree, decrypted: the canonical tar
// whose digest is the pack's. It is opened and checked in full before a
// byte is written, so a tree that does not open writes nothing.
func (s *Service) Export(ctx context.Context, owner Owner, id uuid.UUID) (storegen.KnowledgePack, *Tree, error) {
	return s.ExportIf(ctx, owner, id, nil)
}

// ErrNotExportable is an organization's shared pack its admins have not
// marked exportable, exported by a member.
var ErrNotExportable = errors.New("knowledge: the pack is not marked exportable")

// ExportIf is Export, refused when allow answers an error for the pack as
// the export read it (nil: always allowed), so that the rule and the tree
// come from one read of the row.
func (s *Service) ExportIf(ctx context.Context, owner Owner, id uuid.UUID, allow func(storegen.KnowledgePack) error) (storegen.KnowledgePack, *Tree, error) {
	p, err := s.usable(ctx, owner, id)
	if err != nil {
		return p, nil, err
	}
	if allow != nil {
		if err := allow(p); err != nil {
			return p, nil, err
		}
	}
	rc, err := s.blobs.Get(ctx, p.ObjectKey)
	if err != nil {
		return p, nil, fmt.Errorf("knowledge: read the stored tree: %w", err)
	}
	defer func() { _ = rc.Close() }()
	tree, err := s.open(ctx, owner, p, rc)
	return p, tree, err
}

// Delete removes one of owner's packs, its objects and their blobs. The
// pack row is locked first, so an upload racing the delete either lands
// before it (and its object goes with the pack) or finds no pack.
// also, when given, runs in the same transaction with the pack as it stood
// before it went.
func (s *Service) Delete(ctx context.Context, owner Owner, id uuid.UUID, also Also) error {
	if err := s.ready(); err != nil {
		return err
	}
	var keys []string
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		p, err := q.GetKnowledgePackForUpdate(ctx, storegen.GetKnowledgePackForUpdateParams{ID: id, OwnerKind: string(owner.Kind), OwnerID: owner.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("knowledge: lock pack: %w", err)
		}
		if keys, err = q.ListKnowledgeObjectsOfPack(ctx, id); err != nil {
			return fmt.Errorf("knowledge: list the pack's trees: %w", err)
		}
		if _, err = q.DeleteKnowledgePack(ctx, storegen.DeleteKnowledgePackParams{ID: id, OwnerKind: string(owner.Kind), OwnerID: owner.ID}); err != nil {
			return fmt.Errorf("knowledge: delete pack: %w", err)
		}
		if also != nil {
			return also(q, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.deleteBlobs(ctx, keys...)
	return nil
}

// EraseOwner deletes every pack of owner on q, the caller's transaction —
// the account erasure, a data clear, an organization's decommission — and
// the salt the core's wrapper derives the owner's keys from, so that the
// crypto-erasure commits with the erasure itself. It returns the blob keys,
// which FinishErasure takes once the transaction has committed. It runs
// whether or not the store is on, so that turning it off strands nothing an
// erasure should remove.
func EraseOwner(ctx context.Context, q *storegen.Queries, owner Owner) ([]string, error) {
	keys, err := q.DeleteKnowledgeObjectsOfOwner(ctx, storegen.DeleteKnowledgeObjectsOfOwnerParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID})
	if err != nil {
		return nil, fmt.Errorf("knowledge: erase the owner's trees: %w", err)
	}
	if _, err := q.DeleteKnowledgePacksOfOwner(ctx, storegen.DeleteKnowledgePacksOfOwnerParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID}); err != nil {
		return nil, fmt.Errorf("knowledge: erase the owner's packs: %w", err)
	}
	if err := q.DeleteKnowledgeOwnerSalt(ctx, storegen.DeleteKnowledgeOwnerSaltParams{OwnerKind: string(owner.Kind), OwnerID: owner.ID}); err != nil {
		return nil, fmt.Errorf("knowledge: erase the owner's key: %w", err)
	}
	return keys, nil
}

// EraseArgs names an erasure's last step: the owner whose keys the wrapper
// destroys, and the sealed blobs to delete.
type EraseArgs struct {
	Kind OwnerKind `json:"kind"`
	ID   uuid.UUID `json:"id"`
	Keys []string  `json:"keys,omitempty"`
}

// FinishErasure is an erasure's last step, after its transaction
// committed: the wrapper destroys what opens the owner's keys (an
// extension's wrapper holds its own; the core's salt is already gone),
// then the sealed blobs go. A step that fails is handed to a retrying job
// and logged, never hidden, and undoes nothing: a blob left behind is
// sealed under a data key no one can unwrap any more.
func (s *Service) FinishErasure(ctx context.Context, owner Owner, keys []string) {
	if s == nil {
		return
	}
	if err := s.finishErasure(ctx, EraseArgs{Kind: owner.Kind, ID: owner.ID, Keys: keys}); err != nil {
		s.log.ErrorContext(ctx, "knowledge: the erasure's last step failed; retrying as a job", "owner", owner.String(), "err", err)
		if s.jobs != nil {
			if _, qerr := s.jobs.Enqueue(ctx, JobErase, "core", EraseArgs{Kind: owner.Kind, ID: owner.ID, Keys: keys}); qerr != nil {
				s.log.ErrorContext(ctx, "knowledge: queue the erasure's retry", "owner", owner.String(), "err", qerr)
			}
		}
	}
}

func (s *Service) finishErasure(ctx context.Context, a EraseArgs) error {
	var errs []error
	if s.wrapper != nil {
		if err := s.wrapper.Destroy(ctx, Owner{Kind: a.Kind, ID: a.ID}); err != nil {
			errs = append(errs, fmt.Errorf("knowledge: destroy the owner's keys: %w", err))
		}
	}
	if s.blobs != nil {
		for _, k := range a.Keys {
			if err := s.blobs.Delete(ctx, k); err != nil {
				errs = append(errs, fmt.Errorf("knowledge: delete a sealed tree: %w", err))
			}
		}
	}
	return errors.Join(errs...)
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

// RegisterHandlers wires the scan job, the sweep of stalled scans and the
// erasure's retry.
func (s *Service) RegisterHandlers(q queue.Client) {
	q.Register(JobScan, func(ctx context.Context, job queue.Job) error {
		var args ScanArgs
		if err := json.Unmarshal(job.Args, &args); err != nil {
			return fmt.Errorf("%s: bad args: %w", JobScan, err)
		}
		last := job.Attempt >= scanAttempts
		err := s.scanPack(ctx, args, last)
		if err != nil && last {
			// The last attempt never leaves a pack scanning: whatever
			// stopped it, the pack is failed, with nothing claimed read.
			// The queue's job timeout cancels ctx, so the write
			// must not ride it.
			s.failPack(context.WithoutCancel(ctx), args)
		}
		return err
	})
	q.Register(JobScanSweep, func(ctx context.Context, _ queue.Job) error {
		_, err := s.SweepScans(ctx, time.Now().Add(-ScanStallAfter))
		return err
	})
	q.Register(JobErase, func(ctx context.Context, job queue.Job) error {
		var args EraseArgs
		if err := json.Unmarshal(job.Args, &args); err != nil {
			return fmt.Errorf("%s: bad args: %w", JobErase, err)
		}
		return s.finishErasure(ctx, args)
	})
}

// scanPack reads the tree the job names and records its report. A tree
// since replaced is not scanned: its successor has a job of its own. A
// scan that did not finish is retried until the last attempt, which
// records what it read (the report is a record, never a gate).
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
		return fmt.Errorf("knowledge: read the pack to scan: %w", err)
	}
	if State(p.State) != StateScanning {
		return nil
	}
	owner := Owner{Kind: OwnerKind(p.OwnerKind), ID: p.OwnerID}
	rc, err := s.blobs.Get(ctx, p.ObjectKey)
	if err != nil {
		s.log.ErrorContext(ctx, "knowledge: scan could not read the stored tree", "pack", p.ID, "err", err)
		return fmt.Errorf("knowledge: read the stored tree: %w", err)
	}
	tree, err := s.open(ctx, owner, p, rc)
	_ = rc.Close()
	if err == nil && tree.Digest != p.Digest {
		err = ErrDigest
	}
	if err != nil {
		s.log.ErrorContext(ctx, "knowledge: scan could not open the stored tree", "pack", p.ID, "err", err)
		return err
	}
	report := s.scanner.ScanPack(ctx, tree.Files)
	if !report.Complete() && !last {
		return fmt.Errorf("knowledge: the scan of pack %s did not finish; retrying", p.ID)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("knowledge: record the report: %w", err)
	}
	if _, err := q.FinishKnowledgeScan(ctx, storegen.FinishKnowledgeScanParams{State: string(StateReady), Report: raw, ID: p.ID, ObjectKey: p.ObjectKey}); err != nil {
		return fmt.Errorf("knowledge: record the report: %w", err)
	}
	return nil
}

// failPack records a pack whose last scan attempt failed as failed, with no
// report: nothing was read.
func (s *Service) failPack(ctx context.Context, args ScanArgs) {
	if s.st == nil {
		return
	}
	if _, err := s.st.Queries().FinishKnowledgeScan(ctx, storegen.FinishKnowledgeScanParams{State: string(StateFailed), Report: nil, ID: args.Pack, ObjectKey: args.Object}); err != nil {
		s.log.ErrorContext(ctx, "knowledge: record a failed scan", "pack", args.Pack, "err", err)
	}
}
