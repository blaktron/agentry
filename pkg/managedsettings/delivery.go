package managedsettings

// A delivered key. A document names an organization's key by its id and
// revision (KeyRef); the member's client exchanges that reference for the
// key. The client makes a key pair for the one request, sends the public
// half, and the registry seals the key to it with HPKE (RFC 9180), binding
// in what the request was for: the registry, the organization, the
// account, the key and its revision. Only the private half, which never
// leaves the client and is used once, opens it, and only for that request:
// a sealed key replayed to another account, another organization or
// another revision does not open.

import (
	"crypto/hpke"
	"encoding/json"
	"errors"
	"fmt"
)

// DeliverySuite names the HPKE suite a delivered key is sealed with:
// ML-KEM-768 with X25519 (X-Wing), HKDF-SHA256 and ChaCha20-Poly1305.
const DeliverySuite = "hpke-mlkem768x25519-hkdfsha256-chacha20poly1305"

// deliveryInfoPrefix starts the info bound into every seal, so a seal made
// for anything else never opens as a delivered key.
const deliveryInfoPrefix = "agentry managed key delivery v1\n"

// MaxDeliveredKey is the longest key a seal carries.
const MaxDeliveredKey = 8192

func deliveryKEM() hpke.KEM   { return hpke.MLKEM768X25519() }
func deliveryKDF() hpke.KDF   { return hpke.HKDFSHA256() }
func deliveryAEAD() hpke.AEAD { return hpke.ChaCha20Poly1305() }

// Delivery is what one delivered key answers. Every field is bound into
// the seal.
type Delivery struct {
	// Registry is the registry's origin, as the document names it.
	Registry string `json:"registry"`
	// Org is the organization's handle.
	Org string `json:"org"`
	// Account is the member's account id.
	Account string `json:"account"`
	// Key and Rev are the document's KeyRef.
	Key string `json:"key"`
	Rev int64  `json:"rev"`
}

// info is the HPKE info of d: a fixed prefix and d as JSON, whose field
// order is fixed by the struct.
func (d Delivery) info() ([]byte, error) {
	switch {
	case d.Registry == "" || d.Org == "" || d.Account == "":
		return nil, errors.New("managed settings: a delivery names its registry, organization and account")
	case !keyIDPattern.MatchString(d.Key) || d.Rev < 1:
		return nil, errors.New("managed settings: a delivery names a key's id and a revision of 1 or more")
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return append([]byte(deliveryInfoPrefix), b...), nil
}

// DeliveryKey is a client's key pair for one delivery. Its private half
// stays in memory and is dropped after the one Open.
type DeliveryKey struct {
	priv hpke.PrivateKey
}

// NewDeliveryKey makes a fresh key pair for one delivery.
func NewDeliveryKey() (*DeliveryKey, error) {
	priv, err := deliveryKEM().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("managed settings: make a delivery key: %w", err)
	}
	return &DeliveryKey{priv: priv}, nil
}

// PublicKey is the public half the client sends with its request.
func (k *DeliveryKey) PublicKey() []byte { return k.priv.PublicKey().Bytes() }

// Open opens a sealed key made for d with this key pair.
func (k *DeliveryKey) Open(d Delivery, sealed []byte) ([]byte, error) {
	info, err := d.info()
	if err != nil {
		return nil, err
	}
	value, err := hpke.Open(k.priv, deliveryKDF(), deliveryAEAD(), info, sealed)
	if err != nil {
		return nil, errors.New("managed settings: the delivered key does not open for this request")
	}
	return value, nil
}

// SealDelivery seals value, an organization's key, to the client's public
// key for d. A public key that is not one of DeliverySuite's is refused
// before anything is sealed.
func SealDelivery(publicKey []byte, d Delivery, value []byte) ([]byte, error) {
	info, err := d.info()
	if err != nil {
		return nil, err
	}
	if len(value) == 0 || len(value) > MaxDeliveredKey {
		return nil, fmt.Errorf("managed settings: a delivered key is 1 to %d bytes", MaxDeliveredKey)
	}
	pk, err := deliveryKEM().NewPublicKey(publicKey)
	if err != nil {
		return nil, errors.New("managed settings: the delivery's public key is not a " + DeliverySuite + " key")
	}
	return hpke.Seal(pk, deliveryKDF(), deliveryAEAD(), info, value)
}
