package voice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/packseal"
)

// The job kinds: the review runs on the sandbox queue, as a pack's scan
// does, because it reads what a person wrote; the sweep that queues a
// stalled review again reads nothing and runs on the core queue.
const (
	JobReview = "voice.review"
	JobSweep  = "voice.review.sweep"
)

// reviewAttempts is one review job's retry budget, with the queue's
// backoff between tries (about a quarter of an hour in all). A version
// still in review after it is queued again by the sweep: a judge that
// cannot answer leaves it in review, never live.
const reviewAttempts = 5

// StallAfter is how long a version waits in review since its last try
// before the sweep queues its review again.
const StallAfter = time.Hour

// Version is one version of a person's voice, its text opened.
type Version struct {
	ID          uuid.UUID
	Slot        Slot
	ReviewState ReviewState
	Source      Source
	Digest      string
	Bytes       int
	Text        []byte
	// Report is the review's, nil while the first try is to come.
	Report      *Report
	QuestionSet string
	CreatedAt   time.Time
	ReviewedAt  *time.Time
}

// State is a person's voice: the account's flags and its versions.
type State struct {
	AlwaysAttach bool
	WentLive     bool
	Live         *Version
	Pending      *Version
	Previous     *Version
	UpdatedAt    time.Time
}

// Service is the registry's store of Writing Voices.
type Service struct {
	st       *store.Store
	wrapper  func() knowledge.KeyWrapper
	rules    ProseScanner
	reviewer *Reviewer
	jobs     queue.Client
	log      *slog.Logger
}

// Deps is what the service is built from.
type Deps struct {
	Store *store.Store
	// Wrapper is the knowledge store's key wrapper as it stands when asked,
	// so an extension's, set after the server is built, is the one used.
	Wrapper func() knowledge.KeyWrapper
	// Rules runs the pack scan's rule stages; Judge asks the voice question
	// set, nil when the deployment's judge is not Jev, which leaves the
	// store off.
	Rules ProseScanner
	Judge Judge
	Jobs  queue.Client
	Log   *slog.Logger
}

// NewService builds the store.
func NewService(d Deps) *Service {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Service{st: d.Store, wrapper: d.Wrapper, rules: d.Rules, reviewer: NewReviewer(d.Rules, d.Judge), jobs: d.Jobs, log: log}
}

// SetJudge replaces the judge a review asks: at start, or a test's stub.
func (s *Service) SetJudge(j Judge) {
	if s != nil {
		s.reviewer = NewReviewer(s.rules, j)
	}
}

func (s *Service) keyWrapper() knowledge.KeyWrapper {
	if s == nil || s.wrapper == nil {
		return nil
	}
	return s.wrapper()
}

// Configured says whether the store is on: a database, a key wrapper,
// and a judge to review with.
func (s *Service) Configured() bool {
	return s != nil && s.st != nil && s.keyWrapper() != nil && s.reviewer != nil && s.jobs != nil
}

func (s *Service) ready() error {
	if !s.Configured() {
		return ErrUnconfigured
	}
	return nil
}

// QuestionSet is the hash of the voice question set a review asks now.
func (s *Service) QuestionSet() string {
	if s == nil || s.reviewer == nil {
		return ""
	}
	return s.reviewer.QuestionSet()
}

// dataKey is the voice's data key, unwrapped for its person.
func (s *Service) dataKey(ctx context.Context, v storegen.Voice) ([]byte, error) {
	key, err := s.keyWrapper().Unwrap(ctx, knowledge.User(v.UserID), knowledge.WrappedKey{Kind: v.WrapperKind, Recipient: v.WrapperRecipient, Blob: v.WrappedKey})
	if err != nil {
		return nil, fmt.Errorf("voice: unwrap the data key: %w", err)
	}
	if len(key) != packseal.KeySize {
		return nil, fmt.Errorf("voice: unwrap the data key: %w", knowledge.ErrNotOwner)
	}
	return key, nil
}

// seal is text sealed under key, its header naming the person's voice and
// the text's digest.
func seal(key []byte, user uuid.UUID, text []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := packseal.Seal(&buf, key, packseal.Header{Pack: "voice/" + user.String(), Digest: Digest(text)}, bytes.NewReader(text)); err != nil {
		return nil, fmt.Errorf("voice: seal: %w", err)
	}
	return buf.Bytes(), nil
}

// open is a sealed version's text, held to the digest its row records.
func open(key []byte, v storegen.VoiceVersion) ([]byte, error) {
	h, plain, err := packseal.Open(bytes.NewReader(v.Sealed), key)
	if err != nil {
		return nil, fmt.Errorf("voice: open version %s: %w", v.ID, err)
	}
	text, err := io.ReadAll(io.LimitReader(plain, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("voice: open version %s: %w", v.ID, err)
	}
	if h.Digest != v.Digest || Digest(text) != v.Digest {
		return nil, fmt.Errorf("voice: version %s is not the digest its row records", v.ID)
	}
	return text, nil
}

func versionOf(v storegen.VoiceVersion, text []byte) (*Version, error) {
	out := &Version{
		ID: v.ID, Slot: Slot(v.Slot), ReviewState: ReviewState(v.ReviewState), Source: Source(v.Source),
		Digest: v.Digest, Bytes: int(v.Bytes), Text: text, QuestionSet: v.QuestionSet,
		CreatedAt: v.CreatedAt, ReviewedAt: v.ReviewedAt,
	}
	if len(v.Review) > 0 {
		var rep Report
		if err := json.Unmarshal(v.Review, &rep); err != nil {
			return nil, fmt.Errorf("voice: read the review of %s: %w", v.ID, err)
		}
		out.Report = &rep
	}
	return out, nil
}

// Get is a person's voice with every version's text, or ErrNotFound.
func (s *Service) Get(ctx context.Context, user uuid.UUID) (State, error) {
	if err := s.ready(); err != nil {
		return State{}, err
	}
	return s.get(ctx, s.st.Queries(), user)
}

func (s *Service) get(ctx context.Context, q *storegen.Queries, user uuid.UUID) (State, error) {
	v, err := q.GetVoice(ctx, user)
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, ErrNotFound
	}
	if err != nil {
		return State{}, fmt.Errorf("voice: read: %w", err)
	}
	rows, err := q.ListVoiceVersions(ctx, user)
	if err != nil {
		return State{}, fmt.Errorf("voice: read the versions: %w", err)
	}
	st := State{AlwaysAttach: v.AlwaysAttach, WentLive: v.WentLive, UpdatedAt: v.UpdatedAt}
	if len(rows) == 0 {
		return st, nil
	}
	key, err := s.dataKey(ctx, v)
	if err != nil {
		return State{}, err
	}
	for _, row := range rows {
		text, err := open(key, row)
		if err != nil {
			return State{}, err
		}
		ver, err := versionOf(row, text)
		if err != nil {
			return State{}, err
		}
		switch ver.Slot {
		case SlotLive:
			st.Live = ver
		case SlotPending:
			st.Pending = ver
		case SlotPrevious:
			st.Previous = ver
		}
	}
	return st, nil
}

// Live is a person's live version, the one a run attaches, or ErrNotFound.
func (s *Service) Live(ctx context.Context, user uuid.UUID) (*Version, error) {
	st, err := s.Get(ctx, user)
	if err != nil {
		return nil, err
	}
	if st.Live == nil {
		return nil, ErrNotFound
	}
	return st.Live, nil
}

// Put makes text a person's pending version and queues its review: the
// pending version it replaces, if any, goes, and the live one stays live
// until this one passes. The person's voice row, and its data key wrapped
// for them, is made with their first version.
func (s *Service) Put(ctx context.Context, user uuid.UUID, text []byte, source Source) (State, error) {
	if err := s.ready(); err != nil {
		return State{}, err
	}
	if !source.Valid() {
		return State{}, fmt.Errorf("voice: %q is not a source a version may have", source)
	}
	if err := Check(text); err != nil {
		return State{}, err
	}
	var (
		st     State
		queued uuid.UUID
	)
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		v, err := s.lockOrCreate(ctx, q, user)
		if err != nil {
			return err
		}
		key, err := s.dataKey(ctx, v)
		if err != nil {
			return err
		}
		sealed, err := seal(key, user, text)
		if err != nil {
			return err
		}
		if queued, err = s.queuePending(ctx, q, user, source, sealed, Digest(text), len(text)); err != nil {
			return err
		}
		st, err = s.get(ctx, q, user)
		return err
	})
	if err == nil {
		s.queueAfter(ctx, queued)
	}
	return st, err
}

// lockOrCreate locks a person's voice row, making it, with a fresh data
// key wrapped for them, when they have none.
func (s *Service) lockOrCreate(ctx context.Context, q *storegen.Queries, user uuid.UUID) (storegen.Voice, error) {
	v, err := q.GetVoiceForUpdate(ctx, user)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return v, fmt.Errorf("voice: lock: %w", err)
	}
	key, err := packseal.NewKey()
	if err != nil {
		return v, fmt.Errorf("voice: data key: %w", err)
	}
	w, err := s.keyWrapper().Wrap(ctx, knowledge.User(user), key)
	if err != nil {
		return v, fmt.Errorf("voice: wrap the data key: %w", err)
	}
	if _, err := q.CreateVoice(ctx, storegen.CreateVoiceParams{UserID: user, WrapperKind: w.Kind, WrapperRecipient: w.Recipient, WrappedKey: w.Blob}); err != nil {
		return v, fmt.Errorf("voice: create: %w", err)
	}
	// Locked as made, or as a racing caller made it first.
	v, err = q.GetVoiceForUpdate(ctx, user)
	if err != nil {
		return v, fmt.Errorf("voice: lock: %w", err)
	}
	return v, nil
}

// queuePending replaces the pending version with a new one on q, the
// caller's transaction, and answers its id. The caller queues its review
// once the transaction has committed (queueAfter): a worker can take a job
// at once, on another connection, and a review queued inside the
// transaction would find no version and end with nothing reviewed.
func (s *Service) queuePending(ctx context.Context, q *storegen.Queries, user uuid.UUID, source Source, sealed []byte, digest string, size int) (uuid.UUID, error) {
	if _, err := q.DeleteVoiceVersionInSlot(ctx, storegen.DeleteVoiceVersionInSlotParams{UserID: user, Slot: string(SlotPending)}); err != nil {
		return uuid.Nil, fmt.Errorf("voice: drop the pending version: %w", err)
	}
	ver, err := q.InsertPendingVoiceVersion(ctx, storegen.InsertPendingVoiceVersionParams{
		UserID: user, Source: string(source), Sealed: sealed, Digest: digest, Bytes: int32(size), //nolint:gosec // bounded by MaxBytes
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("voice: store the version: %w", err)
	}
	if err := q.TouchVoice(ctx, user); err != nil {
		return uuid.Nil, fmt.Errorf("voice: touch: %w", err)
	}
	return ver.ID, nil
}

// queueAfter queues the review of a version its caller committed. The
// version is stored either way: a review that could not be queued is
// logged, and the sweep queues it once it has waited StallAfter.
func (s *Service) queueAfter(ctx context.Context, id uuid.UUID) {
	if id == uuid.Nil {
		return
	}
	if err := s.enqueueReview(ctx, id); err != nil {
		s.log.ErrorContext(ctx, "voice: queue a review; the sweep will", "version", id, "err", err)
	}
}

func (s *Service) enqueueReview(ctx context.Context, id uuid.UUID) error {
	if _, err := s.jobs.Enqueue(ctx, JobReview, "sandbox", ReviewArgs{Version: id}, queue.WithMaxAttempts(reviewAttempts)); err != nil {
		return fmt.Errorf("voice: queue the review: %w", err)
	}
	return nil
}

// RestoreNeedsReview says whether a Restore of a person's previous version
// is a new version to review — it was reviewed under a question set other
// than the one in use — or a swap of live and previous. ErrNoPrevious when
// there is none.
func (s *Service) RestoreNeedsReview(ctx context.Context, user uuid.UUID) (bool, error) {
	if err := s.ready(); err != nil {
		return false, err
	}
	prev, err := s.st.Queries().GetVoiceVersionInSlot(ctx, storegen.GetVoiceVersionInSlotParams{UserID: user, Slot: string(SlotPrevious)})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNoPrevious
	}
	if err != nil {
		return false, fmt.Errorf("voice: read the previous version: %w", err)
	}
	return prev.QuestionSet != s.QuestionSet(), nil
}

// ErrRestoreNeedsReview is a Restore its caller did not admit for review
// although the previous version needs one: the question set moved between
// the caller's look and the restore.
var ErrRestoreNeedsReview = errors.New("voice: the previous version needs a review under the current question set")

// Restore puts a person's previous version back. Reviewed under the set
// in use now, it and the live one trade places at once; reviewed under
// another, it becomes the pending version, source restore, and is
// reviewed like any other, which the caller must have admitted
// (review).
func (s *Service) Restore(ctx context.Context, user uuid.UUID, review bool) (State, error) {
	if err := s.ready(); err != nil {
		return State{}, err
	}
	var (
		st     State
		queued uuid.UUID
	)
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		v, err := q.GetVoiceForUpdate(ctx, user)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoPrevious
		}
		if err != nil {
			return fmt.Errorf("voice: lock: %w", err)
		}
		prev, err := q.GetVoiceVersionInSlot(ctx, storegen.GetVoiceVersionInSlotParams{UserID: user, Slot: string(SlotPrevious)})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoPrevious
		}
		if err != nil {
			return fmt.Errorf("voice: read the previous version: %w", err)
		}
		if prev.QuestionSet == s.QuestionSet() {
			if _, err := q.SwapLiveAndPreviousVoice(ctx, user); err != nil {
				return fmt.Errorf("voice: restore: %w", err)
			}
			if err := q.TouchVoice(ctx, user); err != nil {
				return fmt.Errorf("voice: touch: %w", err)
			}
		} else {
			if !review {
				return ErrRestoreNeedsReview
			}
			key, err := s.dataKey(ctx, v)
			if err != nil {
				return err
			}
			// The sealed bytes are put back as they are; opening them first
			// holds them to their digest, so a version that no longer opens
			// is refused here rather than failed by its review.
			if _, err := open(key, prev); err != nil {
				return err
			}
			if queued, err = s.queuePending(ctx, q, user, SourceRestore, prev.Sealed, prev.Digest, int(prev.Bytes)); err != nil {
				return err
			}
		}
		st, err = s.get(ctx, q, user)
		return err
	})
	if err == nil {
		s.queueAfter(ctx, queued)
	}
	return st, err
}

// DiscardPending drops a person's pending version, flagged or in review;
// ErrNotFound when there is none.
func (s *Service) DiscardPending(ctx context.Context, user uuid.UUID) (State, error) {
	if err := s.ready(); err != nil {
		return State{}, err
	}
	var st State
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if _, err := q.GetVoiceForUpdate(ctx, user); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("voice: lock: %w", err)
		}
		n, err := q.DeleteVoiceVersionInSlot(ctx, storegen.DeleteVoiceVersionInSlotParams{UserID: user, Slot: string(SlotPending)})
		if err != nil {
			return fmt.Errorf("voice: drop the pending version: %w", err)
		}
		if n == 0 {
			return ErrNotFound
		}
		if err := q.TouchVoice(ctx, user); err != nil {
			return fmt.Errorf("voice: touch: %w", err)
		}
		st, err = s.get(ctx, q, user)
		return err
	})
	return st, err
}

// SetAlwaysAttach sets the account's always-attach flag.
func (s *Service) SetAlwaysAttach(ctx context.Context, user uuid.UUID, on bool) (State, error) {
	if err := s.ready(); err != nil {
		return State{}, err
	}
	var st State
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if _, err := q.SetVoiceAlwaysAttach(ctx, storegen.SetVoiceAlwaysAttachParams{UserID: user, AlwaysAttach: on}); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("voice: set always-attach: %w", err)
		}
		var err error
		st, err = s.get(ctx, q, user)
		return err
	})
	return st, err
}

// Delete removes a person's voice, every version of it and its data key.
func (s *Service) Delete(ctx context.Context, user uuid.UUID) error {
	if err := s.ready(); err != nil {
		return err
	}
	n, err := s.st.Queries().DeleteVoice(ctx, user)
	if err != nil {
		return fmt.Errorf("voice: delete: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Erase deletes a person's voice on q, the caller's transaction: the
// account erasure and a data clear. It runs whether or not the store is
// on, so turning it off strands nothing an erasure should remove. The key
// that opened it goes with the knowledge store's erasure of the same
// person (its salt, or an extension wrapper's Destroy).
func Erase(ctx context.Context, q *storegen.Queries, user uuid.UUID) (int64, error) {
	n, err := q.DeleteVoice(ctx, user)
	if err != nil {
		return 0, fmt.Errorf("voice: erase: %w", err)
	}
	return n, nil
}

// ReviewArgs names the version a review job reads.
type ReviewArgs struct {
	Version uuid.UUID `json:"version"`
}

// RegisterHandlers wires the review and the sweep onto a queue worker.
func (s *Service) RegisterHandlers(q queue.Client) {
	q.Register(JobReview, func(ctx context.Context, job queue.Job) error {
		var args ReviewArgs
		if err := json.Unmarshal(job.Args, &args); err != nil {
			return fmt.Errorf("%s: bad args: %w", JobReview, err)
		}
		return s.review(ctx, args.Version)
	})
	q.Register(JobSweep, func(ctx context.Context, _ queue.Job) error {
		_, err := s.Sweep(ctx, time.Now().Add(-StallAfter))
		return err
	})
}

// review reads one version and decides it. A version since replaced,
// discarded or decided is not reviewed: the job finds nothing to do. A
// review that did not finish is kept on the version, which stays in
// review, and the job is retried; the sweep queues it again after the
// job's last try.
func (s *Service) review(ctx context.Context, id uuid.UUID) error {
	if err := s.ready(); err != nil {
		return err
	}
	q := s.st.Queries()
	// Counting the try is also the claim: it answers the version only while
	// it is still pending and in review.
	ver, err := q.CountVoiceReviewAttempt(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("voice: read the version to review: %w", err)
	}
	v, err := q.GetVoice(ctx, ver.UserID)
	if err != nil {
		return fmt.Errorf("voice: read the voice to review: %w", err)
	}
	key, err := s.dataKey(ctx, v)
	if err != nil {
		return err
	}
	text, err := open(key, ver)
	if err != nil {
		s.log.ErrorContext(ctx, "voice: the review could not open the version", "version", id, "err", err)
		return err
	}
	rep := s.reviewer.Review(ctx, string(text))
	// A version flagged by a rule stage while the judge did not answer is
	// still recorded under the set a review asks now.
	set := rep.AIReview.QuestionSet
	if set == "" {
		set = s.reviewer.QuestionSet()
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("voice: record the review: %w", err)
	}
	switch rep.Verdict {
	case VerdictIncomplete:
		// The report says which stage or the judge did not finish; the
		// judge's own words are not kept, since they can echo the text.
		if err := q.NoteVoiceReview(context.WithoutCancel(ctx), storegen.NoteVoiceReviewParams{ID: id, Review: raw}); err != nil {
			s.log.ErrorContext(ctx, "voice: note an unfinished review", "version", id, "err", err)
		}
		return fmt.Errorf("voice: the review of version %s did not finish (AI Review %q); it stays in review", id, rep.AIReview.Failure)
	case VerdictFlagged:
		if _, err := q.FlagVoiceVersion(ctx, storegen.FlagVoiceVersionParams{ID: id, Review: raw, QuestionSet: set}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("voice: record the flag: %w", err)
		}
		return nil
	}
	return s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if _, err := q.GetVoiceForUpdate(ctx, ver.UserID); err != nil {
			return fmt.Errorf("voice: lock: %w", err)
		}
		cur, err := q.GetVoiceVersion(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (Slot(cur.Slot) != SlotPending || ReviewState(cur.ReviewState) != ReviewReviewing)) {
			return nil // replaced, discarded or decided while it was read
		}
		if err != nil {
			return fmt.Errorf("voice: read the version: %w", err)
		}
		if _, err := q.DeleteVoiceVersionInSlot(ctx, storegen.DeleteVoiceVersionInSlotParams{UserID: ver.UserID, Slot: string(SlotPrevious)}); err != nil {
			return fmt.Errorf("voice: drop the previous version: %w", err)
		}
		if _, err := q.MoveVoiceVersionSlot(ctx, storegen.MoveVoiceVersionSlotParams{UserID: ver.UserID, FromSlot: string(SlotLive), ToSlot: string(SlotPrevious)}); err != nil {
			return fmt.Errorf("voice: keep the live version as previous: %w", err)
		}
		if _, err := q.PassVoiceVersion(ctx, storegen.PassVoiceVersionParams{ID: id, Review: raw, QuestionSet: set}); err != nil {
			return fmt.Errorf("voice: make the version live: %w", err)
		}
		if _, err := q.SetVoiceWentLive(ctx, ver.UserID); err != nil {
			return fmt.Errorf("voice: record the voice live: %w", err)
		}
		return nil
	})
}

// Sweep queues a review again for every version still in review whose last
// try is older than cutoff, and reports how many. It is how a review whose
// job ran out of tries, while the judge could not answer, is tried again.
func (s *Service) Sweep(ctx context.Context, cutoff time.Time) (int, error) {
	if !s.Configured() {
		return 0, nil
	}
	rows, err := s.st.Queries().ListStalledVoiceReviews(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("voice: list stalled reviews: %w", err)
	}
	for _, r := range rows {
		if err := s.enqueueReview(ctx, r.ID); err != nil {
			return 0, err
		}
	}
	if len(rows) > 0 {
		s.log.InfoContext(ctx, "voice: reviews queued again", "count", len(rows))
	}
	return len(rows), nil
}
