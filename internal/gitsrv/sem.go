package gitsrv

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// §6.2 requires a "concurrency semaphore per repo and global". The global cap
// protects the host (git subprocesses are the expensive resource); the
// per-repo cap keeps one hot repository — a CI fleet hammering one agent, or
// a clone storm on a popular one — from occupying every global slot and
// starving the rest of the instance.
const (
	globalGitConcurrency  = 32
	perRepoGitConcurrency = 4
)

// repoSemaphores hands out per-repo slots. A repo's semaphore is created on
// first use and dropped once nobody holds or waits on it, so the map tracks
// live traffic rather than every repo ever served.
type repoSemaphores struct {
	capacity int
	mu       sync.Mutex
	live     map[uuid.UUID]*repoSlots
}

type repoSlots struct {
	ch   chan struct{}
	refs int // holders + waiters; the entry lives while this is > 0
}

func newRepoSemaphores(capacity int) *repoSemaphores {
	return &repoSemaphores{capacity: capacity, live: make(map[uuid.UUID]*repoSlots)}
}

// acquire blocks until a slot on repoID is free or ctx ends. The returned
// release func must be called exactly once, and only when err is nil.
func (s *repoSemaphores) acquire(ctx context.Context, repoID uuid.UUID) (func(), error) {
	s.mu.Lock()
	slot, ok := s.live[repoID]
	if !ok {
		slot = &repoSlots{ch: make(chan struct{}, s.capacity)}
		s.live[repoID] = slot
	}
	slot.refs++
	s.mu.Unlock()

	select {
	case slot.ch <- struct{}{}:
		return func() {
			<-slot.ch
			s.drop(repoID)
		}, nil
	case <-ctx.Done():
		s.drop(repoID)
		return nil, ctx.Err()
	}
}

// drop releases one reference to a repo's semaphore, forgetting it when the
// last holder or waiter leaves.
func (s *repoSemaphores) drop(repoID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot, ok := s.live[repoID]
	if !ok {
		return
	}
	slot.refs--
	if slot.refs <= 0 {
		delete(s.live, repoID)
	}
}

// tracked reports how many repos currently hold or await slots (tests).
func (s *repoSemaphores) tracked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

// acquireGit takes a per-repo slot and then a global one — always in that
// order, so a saturated repo queues on its own semaphore instead of sitting
// on global slots while it waits.
func (h *Handler) acquireGit(ctx context.Context, repoID uuid.UUID) (func(), error) {
	releaseRepo, err := h.perRepo.acquire(ctx, repoID)
	if err != nil {
		return nil, err
	}
	select {
	case h.sem <- struct{}{}:
		return func() {
			<-h.sem
			releaseRepo()
		}, nil
	case <-ctx.Done():
		releaseRepo()
		return nil, ctx.Err()
	}
}
