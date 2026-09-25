package knowledge

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/blaktron/agentry/pkg/packseal"
)

// WrappedKey is a pack's data key as its owner's wrapper sealed it: which
// wrapper (Kind), to which key (Recipient: the deployment key's id, or on
// SecureAgentry a certificate's serial), and the sealed bytes. It is what
// a client keeps beside a sealed pack and what a pack's row holds.
type WrappedKey struct {
	Kind      string
	Recipient string
	Blob      []byte
}

// KeyWrapper wraps a pack's data key for its owner and unwraps it again,
// and destroys what makes an owner's wrapped keys open (plan knowledge.md
// §4.3, D4, D22). The registry is the only party that unwraps: a data key
// leaves it over TLS to its owner, and no route ever returns what wraps it.
type KeyWrapper interface {
	// Wrap seals dataKey for owner.
	Wrap(ctx context.Context, owner Owner, dataKey []byte) (WrappedKey, error)
	// Unwrap opens a wrapped key for owner, or refuses with ErrNotOwner.
	Unwrap(ctx context.Context, owner Owner, wrapped WrappedKey) ([]byte, error)
	// Destroy makes every key ever wrapped for owner unopenable, wherever
	// a copy of it is kept. It is the owner's erasure, a data clear, or an
	// organization's decommission; it is idempotent.
	Destroy(ctx context.Context, owner Owner) error
}

// DeploymentKind is the core wrapper's kind.
const DeploymentKind = "deployment"

// OwnerSalts keeps the random salt each owner's key-encryption key is
// derived with. Deleting an owner's salt is what destroys their keys.
type OwnerSalts interface {
	// Salt returns the owner's salt, creating it first when create is set;
	// with create unset, an owner with none gets ErrNotOwner.
	Salt(ctx context.Context, owner Owner, create bool) ([]byte, error)
	// DeleteSalt removes the owner's salt, if any.
	DeleteSalt(ctx context.Context, owner Owner) error
}

// SaltSize is an owner salt's length.
const SaltSize = 32

// DeploymentWrapper is the core's KeyWrapper: AES-256-GCM under a key
// derived, per owner, from the deployment's knowledge sealing key
// (AGENTRY_KNOWLEDGE_SEALING_KEY, a key of its own) and the owner's random
// salt, with the owner named in the additional data. A core-only registry
// so stores trees it can open only for their owners, and an owner's
// erasure deletes the salt, after which no copy of their wrapped keys —
// not the pack rows', not one on a laptop — opens again.
type DeploymentWrapper struct {
	key   []byte
	id    string
	salts OwnerSalts
}

// DecodeSealingKey decodes a base64 knowledge sealing key: 32 bytes.
func DecodeSealingKey(b64 string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("knowledge: sealing key: %w", err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("knowledge: sealing key must be 32 bytes, got %d", len(k))
	}
	return k, nil
}

// NewDeploymentWrapper builds the core wrapper over a 32-byte key.
func NewDeploymentWrapper(key []byte, salts OwnerSalts) (*DeploymentWrapper, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("knowledge: sealing key must be 32 bytes, got %d", len(key))
	}
	if salts == nil {
		return nil, errors.New("knowledge: the deployment wrapper needs a salt store")
	}
	sum := sha256.Sum256(append([]byte("agentry-knowledge/key-id/v1\x00"), key...))
	return &DeploymentWrapper{key: append([]byte(nil), key...), id: "deployment:" + hex.EncodeToString(sum[:8]), salts: salts}, nil
}

// Recipient is the id the wrapper names its wrapped keys with: a digest of
// the key, never the key.
func (d *DeploymentWrapper) Recipient() string { return d.id }

func (d *DeploymentWrapper) aead(salt []byte) (cipher.AEAD, error) {
	kek, err := hkdf.Key(sha256.New, d.key, salt, "agentry-knowledge/kek/v1", 32)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func ownerAAD(owner Owner) []byte {
	return []byte("agentry-knowledge/data-key/v1/" + string(owner.Kind) + "/" + owner.ID.String())
}

// Wrap implements KeyWrapper.
func (d *DeploymentWrapper) Wrap(ctx context.Context, owner Owner, dataKey []byte) (WrappedKey, error) {
	if !owner.Valid() {
		return WrappedKey{}, errors.New("knowledge: wrap for no owner")
	}
	if len(dataKey) != packseal.KeySize {
		return WrappedKey{}, packseal.ErrKey
	}
	salt, err := d.salts.Salt(ctx, owner, true)
	if err != nil {
		return WrappedKey{}, err
	}
	aead, err := d.aead(salt)
	if err != nil {
		return WrappedKey{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{Kind: DeploymentKind, Recipient: d.id, Blob: aead.Seal(nonce, nonce, dataKey, ownerAAD(owner))}, nil
}

// Unwrap implements KeyWrapper.
func (d *DeploymentWrapper) Unwrap(ctx context.Context, owner Owner, w WrappedKey) ([]byte, error) {
	if !owner.Valid() || w.Kind != DeploymentKind || w.Recipient != d.id {
		return nil, ErrNotOwner
	}
	salt, err := d.salts.Salt(ctx, owner, false)
	if err != nil {
		return nil, err
	}
	aead, err := d.aead(salt)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(w.Blob) < ns {
		return nil, ErrNotOwner
	}
	key, err := aead.Open(nil, w.Blob[:ns], w.Blob[ns:], ownerAAD(owner))
	if err != nil {
		return nil, ErrNotOwner
	}
	return key, nil
}

// Destroy implements KeyWrapper: the owner's salt goes, and with it every
// key-encryption key their wrapped keys need.
func (d *DeploymentWrapper) Destroy(ctx context.Context, owner Owner) error {
	return d.salts.DeleteSalt(ctx, owner)
}
