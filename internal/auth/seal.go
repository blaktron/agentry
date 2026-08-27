package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Sealer encrypts small secrets at rest (TOTP seeds today; webhook secrets in
// M6). AES-256-GCM with a key from configuration; SaaS wraps the key with KMS
// (envelope encryption is an operational concern, not a code path change).
type Sealer struct {
	aead cipher.AEAD
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
	return &Sealer{aead: aead}, nil
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
