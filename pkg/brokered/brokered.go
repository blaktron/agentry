// Package brokered is the sealed answer of a sign-in the registry
// completes for a person's own machine: the tokens of a vendor whose token
// endpoint needs a client secret, which the registry adds to the exchange
// or the refresh and never keeps.
//
// The machine makes a key pair for the one request and sends the public
// half with it. The registry's worker, which alone holds the secret, seals
// the tokens to that key with HPKE (RFC 9180), binding in what the request
// was for: the registry, the account, the kind of request and its id. The
// registry hands the sealed value over once and keeps nothing it can open;
// only the private half, which never leaves the machine and is used once,
// opens it, and only for that request.
package brokered

import (
	"crypto/hpke"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Suite names the HPKE suite an answer is sealed with: ML-KEM-768 with
// X25519 (X-Wing), HKDF-SHA256 and ChaCha20-Poly1305.
const Suite = "hpke-mlkem768x25519-hkdfsha256-chacha20poly1305"

// infoPrefix starts the info bound into every seal, so a seal made for
// anything else never opens as a brokered answer.
const infoPrefix = "agentry brokered sign-in v1\n"

// The bounds of a request and its answer.
const (
	// MaxPublicKey is the longest public key a request may carry.
	MaxPublicKey = 4096
	// MaxTokens is the longest answer, as JSON, a seal carries.
	MaxTokens = 32 << 10
)

// The kinds of request an answer is for.
const (
	// KindConsent answers a sign-in: the tokens its exchange gave.
	KindConsent = "consent"
	// KindRefresh answers a refresh of a connection already made.
	KindRefresh = "refresh"
)

func kem() hpke.KEM   { return hpke.MLKEM768X25519() }
func kdf() hpke.KDF   { return hpke.HKDFSHA256() }
func aead() hpke.AEAD { return hpke.ChaCha20Poly1305() }

// Binding is what one answer is for. Every field is bound into the seal.
type Binding struct {
	// Registry is the registry's origin.
	Registry string `json:"registry"`
	// Account is the account id the request was made as.
	Account string `json:"account"`
	// Kind is KindConsent or KindRefresh, and Request that request's id.
	Kind    string `json:"kind"`
	Request string `json:"request"`
}

// info is the HPKE info of b: a fixed prefix and b as JSON, whose field
// order is fixed by the struct.
func (b Binding) info() ([]byte, error) {
	switch {
	case b.Registry == "" || b.Account == "" || b.Request == "":
		return nil, errors.New("brokered: an answer names its registry, account and request")
	case b.Kind != KindConsent && b.Kind != KindRefresh:
		return nil, fmt.Errorf("brokered: unknown kind %q", b.Kind)
	}
	j, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return append([]byte(infoPrefix), j...), nil
}

// Tokens is what an answer carries: the vendor's tokens, and the client
// they were made with, so the machine refreshes through the registry with
// the same one.
type Tokens struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt,omitzero"`
	Scopes       []string  `json:"scopes,omitempty"`
	// Issuer and ClientID are the authorization server and the
	// deployment's client the tokens belong to.
	Issuer   string `json:"issuer"`
	ClientID string `json:"clientId"`
}

// Key is a machine's key pair for one request. Its private half stays in
// memory and is dropped after the one Open.
type Key struct {
	priv hpke.PrivateKey
}

// NewKey makes a fresh key pair for one request.
func NewKey() (*Key, error) {
	priv, err := kem().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("brokered: make a key: %w", err)
	}
	return &Key{priv: priv}, nil
}

// PublicKey is the public half the machine sends with its request.
func (k *Key) PublicKey() []byte { return k.priv.PublicKey().Bytes() }

// Open opens an answer sealed for b with this key pair.
func (k *Key) Open(b Binding, sealed []byte) (*Tokens, error) {
	info, err := b.info()
	if err != nil {
		return nil, err
	}
	pt, err := hpke.Open(k.priv, kdf(), aead(), info, sealed)
	if err != nil {
		return nil, errors.New("brokered: the answer does not open for this request")
	}
	defer clear(pt)
	var t Tokens
	if err := json.Unmarshal(pt, &t); err != nil || t.AccessToken == "" || t.Issuer == "" || t.ClientID == "" {
		return nil, errors.New("brokered: the answer is not a sign-in's tokens")
	}
	return &t, nil
}

// CheckPublicKey reports whether publicKey is one of Suite's, for a
// registry to refuse a request it could never answer.
func CheckPublicKey(publicKey []byte) error {
	if len(publicKey) == 0 || len(publicKey) > MaxPublicKey {
		return errors.New("brokered: the public key is missing or too long")
	}
	if _, err := kem().NewPublicKey(publicKey); err != nil {
		return errors.New("brokered: the public key is not a " + Suite + " key")
	}
	return nil
}

// Seal seals t to the machine's public key for b. A public key that is not
// one of Suite's, or tokens without an access token, an issuer or a client,
// are refused before anything is sealed.
func Seal(publicKey []byte, b Binding, t Tokens) ([]byte, error) {
	info, err := b.info()
	if err != nil {
		return nil, err
	}
	if t.AccessToken == "" || t.Issuer == "" || t.ClientID == "" {
		return nil, errors.New("brokered: an answer carries an access token, its issuer and its client")
	}
	pt, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	if len(pt) > MaxTokens {
		return nil, fmt.Errorf("brokered: an answer is at most %d bytes", MaxTokens)
	}
	if err := CheckPublicKey(publicKey); err != nil {
		return nil, err
	}
	pk, err := kem().NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return hpke.Seal(pk, kdf(), aead(), info, pt)
}
