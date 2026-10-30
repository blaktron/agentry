package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Sealer encrypts small secrets at rest (for example webhook secrets and
// sign-in state). AES-256-GCM with a key from configuration; SaaS wraps the key with KMS
// (envelope encryption is an operational concern, not a code path change).
type Sealer struct {
	aead cipher.AEAD
	key  []byte
}

// NewSealer builds a Sealer from a base64 key (32 bytes decoded). An empty
// key is only permitted in dev, where a fixed insecure key keeps local
// setups friction-free; config validation rejects that in prod.
func NewSealer(base64Key string, devMode bool) (*Sealer, error) {
	var key []byte
	switch {
	case base64Key != "":
		k, err := base64.StdEncoding.DecodeString(base64Key)
		if err != nil {
			return nil, fmt.Errorf("auth: sealing key: %w", err)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("auth: sealing key must be 32 bytes, got %d", len(k))
		}
		key = k
	case devMode:
		sum := sha256.Sum256([]byte("agentry-dev-insecure-sealing-key"))
		key = sum[:]
	default:
		return nil, fmt.Errorf("auth: sealing key required outside dev mode")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: sealer cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: sealer gcm: %w", err)
	}
	return &Sealer{aead: aead, key: key}, nil
}

// Seal encrypts plaintext; output is nonce||ciphertext.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("auth: seal nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a Seal output.
func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return nil, fmt.Errorf("auth: sealed blob too short")
	}
	pt, err := s.aead.Open(nil, sealed[:ns], sealed[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("auth: unseal: %w", err)
	}
	return pt, nil
}

// For is a sealer under a key of its own, derived from this one's for one
// purpose (HKDF-SHA256). What it seals this sealer cannot open, nor can a
// sealer for another purpose, and it opens nothing they sealed: the server
// hands one to each extension, so an extension's values and the server's
// own (webhook secrets, sign-in state) never share a key.
func (s *Sealer) For(purpose string) (*Sealer, error) {
	key, err := hkdf.Key(sha256.New, s.key, nil, "agentry sealer: "+purpose, 32)
	if err != nil {
		return nil, fmt.Errorf("auth: derive a sealing key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: sealer cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: sealer gcm: %w", err)
	}
	return &Sealer{aead: aead, key: key}, nil
}

// MAC is HMAC-SHA256 of msg under a key derived from this sealer's for one
// purpose (HKDF-SHA256), distinct from every sealing key For derives: a
// value keyed this way can be compared to another keyed the same way, and
// cannot be turned back into msg without the server's sealing key.
func (s *Sealer) MAC(purpose string, msg []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, s.key, nil, "agentry mac: "+purpose, 32)
	if err != nil {
		return nil, fmt.Errorf("auth: derive a mac key: %w", err)
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(msg)
	return m.Sum(nil), nil
}
