package gitsrv

import (
	"context"

	"github.com/google/uuid"
)

// ClientOpsHeld reports how many git operations the client address key holds
// against its concurrent-operation budget right now. The black-box budget
// tests wait on it instead of probing with a request of their own: a probe
// from the budgeted address takes that address's slot while it runs, so with
// a budget of one it can refuse the very operation the test is trying to hold.
func (h *Handler) ClientOpsHeld(key string) int {
	s := h.perClient
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot, ok := s.live[key]; ok {
		return len(slot.ch)
	}
	return 0
}

// CopyHistoryVia copies commit's history through the tag via as
// CopyHistory does once it has chosen that tag, so a test can name a tag
// that no longer points at commit, as one moved between the listing and
// the fetch would.
func (s *RepoStore) CopyHistoryVia(ctx context.Context, src, dst uuid.UUID, defaultBranch, commit, via string) error {
	if err := s.InitBare(ctx, dst, defaultBranch); err != nil {
		return err
	}
	return s.copyVia(ctx, src, dst, defaultBranch, commit, via)
}
