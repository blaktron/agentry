package knowledge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/packseal"
)

// What an extension may do with the store (pkg/extension.Knowledge): a hosted
// build of the built-in Creator makes a pack, reads its tree to stage it for
// the sandbox host, and puts back the tree the build made. The data key never
// leaves the registry: the extension hands over plaintext files and reads
// metadata, and the tree it puts back is sealed here and stored through the
// upload's own path, so the allocation, the bookkeeping and the scan are the
// same for both doors.

// ErrChanged is a replace whose pack no longer holds the tree it was read
// with: another upload or build landed in between.
var ErrChanged = errors.New("knowledge: the pack's tree changed since it was read")

// Info is what an extension reads of a pack: never a key.
type Info struct {
	ID     uuid.UUID
	Name   string
	State  State
	Digest string // "" for an empty pack
	Bytes  int64
	Files  int
	Pages  int
}

func infoOf(p storegen.KnowledgePack) Info {
	return Info{ID: p.ID, Name: p.Name, State: State(p.State), Digest: p.Digest, Bytes: p.Bytes, Files: int(p.Files), Pages: int(p.Pages)}
}

// CreateSealed makes an empty pack for owner under a data key the registry
// makes and its wrapper wraps for owner; the key is kept only wrapped.
func (s *Service) CreateSealed(ctx context.Context, owner Owner, name string) (Info, error) {
	if err := s.ready(); err != nil {
		return Info{}, err
	}
	key, err := packseal.NewKey()
	if err != nil {
		return Info{}, err
	}
	w, err := s.Wrap(ctx, owner, key)
	if err != nil {
		return Info{}, fmt.Errorf("knowledge: wrap a new pack's key: %w", err)
	}
	p, err := s.Create(ctx, owner, name, w, nil)
	if err != nil {
		return Info{}, err
	}
	return infoOf(p), nil
}

// Info is one of owner's packs as an extension reads it.
func (s *Service) Info(ctx context.Context, owner Owner, id uuid.UUID) (Info, error) {
	p, err := s.Get(ctx, owner, id)
	if err != nil {
		return Info{}, err
	}
	return infoOf(p), nil
}

// TreeOf is one of owner's packs' tree, decrypted, as the canonical tar
// whose SHA-256 is the pack's digest. A pack being scanned is ErrScanning,
// an empty one ErrNotFound, as the export answers.
func (s *Service) TreeOf(ctx context.Context, owner Owner, id uuid.UUID) (Info, []byte, error) {
	p, tree, err := s.Export(ctx, owner, id)
	if err != nil {
		return infoOf(p), nil, err
	}
	var b bytes.Buffer
	if err := WriteTree(&b, tree.Files); err != nil {
		return infoOf(p), nil, err
	}
	return infoOf(p), b.Bytes(), nil
}

// Replace makes files the tree of one of owner's packs, provided the pack
// still holds the tree whose digest is from ("" for an empty pack): the
// files written as the canonical tar, sealed under the pack's own data key
// with the stored header's pack id kept, and stored as an upload is —
// opened and checked, counted against its pool under the pool's lock, the
// tree it replaces deleted, its scan queued. It answers ErrChanged when
// the pack moved on, the upload's errors otherwise (ErrTree, ErrTooLarge,
// *AllocationError). A tree the pack already holds is not stored again,
// and changed is false, whatever from says: the pack is already what the
// caller asked for, so a replace retried after it landed is not a
// conflict.
func (s *Service) Replace(ctx context.Context, owner Owner, id uuid.UUID, from string, files []scan.PackFile) (info Info, changed bool, err error) {
	p, err := s.Get(ctx, owner, id)
	if err != nil {
		return Info{}, false, err
	}
	var plain bytes.Buffer
	if err := WriteTree(&plain, files); err != nil {
		return infoOf(p), false, ErrTree
	}
	sum := sha256.Sum256(plain.Bytes())
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest == p.Digest && p.ObjectKey != "" {
		return infoOf(p), false, nil
	}
	if p.Digest != from {
		return infoOf(p), false, ErrChanged
	}
	key, err := s.Unwrap(ctx, owner, WrappedKeyOf(p))
	if err != nil {
		return infoOf(p), false, err
	}
	packID, err := s.sealedPackID(ctx, p)
	if err != nil {
		return infoOf(p), false, err
	}
	var sealed bytes.Buffer
	if err := packseal.Seal(&sealed, key, packseal.Header{Pack: packID, Digest: digest}, &plain); err != nil {
		return infoOf(p), false, fmt.Errorf("knowledge: seal the tree: %w", err)
	}
	stored, err := s.upload(ctx, owner, id, sealed.Bytes(), func(cur storegen.KnowledgePack) error {
		if cur.Digest != from {
			return ErrChanged
		}
		return nil
	})
	if err != nil {
		return infoOf(p), false, err
	}
	return infoOf(stored), true, nil
}

// sealedPackID is the pack id a resealed tree's header carries: the one
// the stored tree's header names, so a copy a client keeps under that id
// still recognises the pack, or, for a pack with no tree yet, the
// registry's id in the CLI's "kp_" form.
func (s *Service) sealedPackID(ctx context.Context, p storegen.KnowledgePack) (string, error) {
	if p.ObjectKey == "" {
		return "kp_" + hex.EncodeToString(p.ID[:]), nil
	}
	rc, err := s.blobs.Get(ctx, p.ObjectKey)
	if err != nil {
		return "", fmt.Errorf("knowledge: read the stored tree: %w", err)
	}
	defer func() { _ = rc.Close() }()
	h, err := packseal.ReadHeader(rc)
	if err != nil {
		return "", fmt.Errorf("knowledge: read the stored tree's header: %w", err)
	}
	return h.Pack, nil
}
