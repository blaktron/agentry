package knowledge

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/pkg/packseal"
)

// memSalts is an in-memory OwnerSalts.
type memSalts struct {
	mu sync.Mutex
	m  map[Owner][]byte
}

func (s *memSalts) Salt(_ context.Context, o Owner, create bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[Owner][]byte{}
	}
	if b, ok := s.m[o]; ok {
		return b, nil
	}
	if !create {
		return nil, ErrNotOwner
	}
	b := make([]byte, SaltSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	s.m[o] = b
	return b, nil
}

func (s *memSalts) DeleteSalt(_ context.Context, o Owner) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, o)
	return nil
}

func wrapper(t *testing.T, key byte) *DeploymentWrapper {
	t.Helper()
	w, err := NewDeploymentWrapper(bytes.Repeat([]byte{key}, 32), &memSalts{})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestDeploymentWrapperOpensForTheOwnerAlone(t *testing.T) {
	ctx := context.Background()
	w := wrapper(t, 7)
	alice, bob := User(uuid.New()), User(uuid.New())
	data, _ := packseal.NewKey()

	wk, err := w.Wrap(ctx, alice, data)
	if err != nil {
		t.Fatal(err)
	}
	if wk.Kind != DeploymentKind || wk.Recipient != w.Recipient() || bytes.Contains(wk.Blob, data) {
		t.Fatalf("wrapped = %+v", wk)
	}
	got, err := w.Unwrap(ctx, alice, wk)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the owner's unwrap: %v", err)
	}

	if _, err := w.Wrap(ctx, bob, data); err != nil { // bob has a salt too
		t.Fatal(err)
	}
	flipped := wk
	flipped.Blob = bytes.Clone(wk.Blob)
	flipped.Blob[len(flipped.Blob)-1] ^= 1
	other := wk
	other.Recipient = "deployment:0000000000000000"
	for name, tc := range map[string]struct {
		owner Owner
		w     WrappedKey
	}{
		"another person":           {bob, wk},
		"an organization, same id": {Org(alice.ID), wk},
		"an altered blob":          {alice, flipped},
		"another deployment's key": {alice, other},
		"another wrapper's kind":   {alice, WrappedKey{Kind: "certificate", Recipient: wk.Recipient, Blob: wk.Blob}},
	} {
		if _, err := w.Unwrap(ctx, tc.owner, tc.w); !errors.Is(err, ErrNotOwner) {
			t.Fatalf("%s: err = %v, want ErrNotOwner", name, err)
		}
	}
	if _, err := wrapper(t, 8).Unwrap(ctx, alice, wk); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("under another sealing key: err = %v", err)
	}
}

func TestDeploymentWrapperDestroyKillsEveryCopy(t *testing.T) {
	ctx := context.Background()
	w := wrapper(t, 7)
	alice := User(uuid.New())
	data, _ := packseal.NewKey()
	wk, err := w.Wrap(ctx, alice, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Destroy(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Unwrap(ctx, alice, wk); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("a key wrapped before the destroy still opens: %v", err)
	}
	// A new wrap after it gets a new salt, and the old copy stays dead.
	if _, err := w.Wrap(ctx, alice, data); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Unwrap(ctx, alice, wk); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("a key wrapped before the destroy opens under the new salt: %v", err)
	}
	if err := w.Destroy(ctx, alice); err != nil {
		t.Fatalf("destroy twice: %v", err)
	}
}

func TestDeploymentWrapperRefusesBadInput(t *testing.T) {
	ctx := context.Background()
	w := wrapper(t, 7)
	if _, err := w.Wrap(ctx, User(uuid.New()), make([]byte, 16)); !errors.Is(err, packseal.ErrKey) {
		t.Fatalf("a short data key: %v", err)
	}
	if _, err := w.Wrap(ctx, Owner{}, make([]byte, 32)); err == nil {
		t.Fatal("wrapped for no owner")
	}
	if _, err := NewDeploymentWrapper(make([]byte, 16), &memSalts{}); err == nil {
		t.Fatal("a 16-byte sealing key was accepted")
	}
	if _, err := DecodeSealingKey("c2hvcnQ="); err == nil {
		t.Fatal("a short base64 key was accepted")
	}
}
