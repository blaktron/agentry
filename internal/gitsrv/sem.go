package gitsrv

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/logevent"
)

// §6.2 requires a "concurrency semaphore per repo and global". The global cap
// protects the host (git subprocesses are the expensive resource); the
// per-repo cap keeps one hot repository — a CI fleet hammering one agent, or
// a clone storm on a popular one — from occupying every global slot and
// starving the rest of the instance. §19's per-address budget
// (limits.gitConcurrentPerIP, default 20; agentry#454) keeps one client
// spread across many repositories from doing the same.
const (
	globalGitConcurrency  = 32
	perRepoGitConcurrency = 4
)

// keyedSemaphores hands out slots per key: per repository (perRepo) and per
// client address (perClient). A key's semaphore is created on first use and
// dropped once nobody holds or waits on it, so the map tracks live traffic
// rather than every repository or address ever served.
type keyedSemaphores[K comparable] struct {
	capacity int
	mu       sync.Mutex
	live     map[K]*keyedSlots
}

type keyedSlots struct {
	ch   chan struct{}
	refs int // holders + waiters; the entry lives while this is > 0
}

// repoSemaphores is the per-repository cap of §6.2.
type repoSemaphores = keyedSemaphores[uuid.UUID]

func newRepoSemaphores(capacity int) *repoSemaphores {
	return &repoSemaphores{capacity: capacity, live: make(map[uuid.UUID]*keyedSlots)}
}

// clientSemaphores is §19's per-address budget, keyed by the trusted client
// address (agentry#454).
type clientSemaphores = keyedSemaphores[string]

func newClientSemaphores(capacity int) *clientSemaphores {
	return &clientSemaphores{capacity: capacity, live: make(map[string]*keyedSlots)}
}

func (s *keyedSemaphores[K]) enter(key K) *keyedSlots {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot, ok := s.live[key]
	if !ok {
		slot = &keyedSlots{ch: make(chan struct{}, s.capacity)}
		s.live[key] = slot
	}
	slot.refs++
	return slot
}

// acquire blocks until a slot on key is free or ctx ends. The returned
// release func must be called exactly once, and only when err is nil.
func (s *keyedSemaphores[K]) acquire(ctx context.Context, key K) (func(), error) {
	slot := s.enter(key)
	select {
	case slot.ch <- struct{}{}:
		return func() {
			<-slot.ch
			s.drop(key)
		}, nil
	case <-ctx.Done():
		s.drop(key)
		return nil, ctx.Err()
	}
}

// tryAcquire takes a slot on key if one is free now, without waiting. The
// release func must be called exactly once, and only when ok is true.
func (s *keyedSemaphores[K]) tryAcquire(key K) (release func(), ok bool) {
	slot := s.enter(key)
	select {
	case slot.ch <- struct{}{}:
		return func() {
			<-slot.ch
			s.drop(key)
		}, true
	default:
		s.drop(key)
		return nil, false
	}
}

// drop releases one reference to a key's semaphore, forgetting it when the
// last holder or waiter leaves.
func (s *keyedSemaphores[K]) drop(key K) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot, ok := s.live[key]
	if !ok {
		return
	}
	slot.refs--
	if slot.refs <= 0 {
		delete(s.live, key)
	}
}

// tracked reports how many keys currently hold or await slots (tests).
func (s *keyedSemaphores[K]) tracked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

// errClientBusy refuses an operation whose client address already holds
// its §19 budget of concurrent git operations (agentry#454).
var errClientBusy = errors.New("too many concurrent git operations from this address; try again shortly")

// acquireGit admits one git operation for client (the trusted client
// address; "" for work the server starts itself) on repoID.
//
// The client's budget is checked first and never waited on: an address at
// its budget is refused at once, so it holds no repository's slot and no
// global slot while it would have waited, and nothing it does can make an
// unrelated caller wait longer. Then a per-repo slot and then a global one —
// always in that order, so a saturated repo queues on its own semaphore
// instead of sitting on global slots while it waits.
//
// Without the per-address budget, one address spread over eight
// repositories at four operations each held all 32 global slots, and every
// other clone, fetch and push on the instance waited behind it.
func (h *Handler) acquireGit(ctx context.Context, repoID uuid.UUID, client string) (func(), error) {
	releaseClient := func() {}
	if client != "" && h.perClient != nil {
		rel, ok := h.perClient.tryAcquire(client)
		if !ok {
			if h.log != nil {
				h.log.InfoContext(ctx, "rate limited", logevent.HTTPRateLimited.Attr(), "class", rateClassGitConcurrent, "source", client)
			}
			return nil, errClientBusy
		}
		releaseClient = rel
	}
	releaseRepo, err := h.perRepo.acquire(ctx, repoID)
	if err != nil {
		releaseClient()
		return nil, err
	}
	select {
	case h.sem <- struct{}{}:
		return func() {
			<-h.sem
			releaseRepo()
			releaseClient()
		}, nil
	case <-ctx.Done():
		releaseRepo()
		releaseClient()
		return nil, ctx.Err()
	}
}

// rateClassGitConcurrent names the per-address budget in the
// http.rate_limited line (docs/logging.md) and in the git routes' §19
// declarations.
const rateClassGitConcurrent = "git-concurrent"

// clientHost is the address part of a net.Addr's string ("host:port" or a
// bare host), the key the per-address budget and ssh-key-offer use.
func clientHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
