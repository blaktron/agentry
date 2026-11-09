// Package keyhandover is the statement a registry's outgoing release-signing
// key makes about its successor when the registry rotates to a new key on
// purpose: "the key that signs for this registry from now on is this one".
//
// A client that pinned an earlier key on first use cannot tell a planned
// rotation from a takeover by looking at the new key set: both look like a
// key it has never seen. A handover signed by a key it already trusts can
// tell them apart. Following a chain of handovers, each verified with the key
// before it, lets the client trust the newest key without the person
// re-pinning, while a key that appears with no handover from a pinned key
// (a compromise, or a rotation forced past a lost key) is still never
// trusted on the registry's word alone.
//
// A handover is a DSSE envelope of its own payload type, so a handover never
// verifies as an attestation or a managed settings document, and neither of
// those verifies as a handover.
package keyhandover

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blaktron/agentry/pkg/attest"
)

// PayloadType is the DSSE payload type of a handover.
const PayloadType = "application/vnd.agentry.signing-key-handover+json"

// Schema names the format of a handover's payload.
const Schema = "signing-key-handover/1"

// Algorithm is the only key algorithm a handover names: the registry signs
// with ECDSA P-256 over SHA-256.
const Algorithm = "ecdsa-p256-sha256"

// Key is a signing key as a handover names it.
type Key struct {
	KeyID        string `json:"keyId"`
	Algorithm    string `json:"algorithm"`
	PublicKeyPEM string `json:"publicKeyPem"`
}

// Handover is what the outgoing key signs.
type Handover struct {
	Schema string `json:"schema"`
	// Registry is the base URL of the registry whose signing key changes.
	Registry string `json:"registry"`
	// From is the outgoing key's id: the key that signs this statement.
	From string `json:"from"`
	// To is the incoming key, whole, so a client can adopt it from the
	// statement alone.
	To Key `json:"to"`
	// At is when the outgoing key signed it.
	At time.Time `json:"at"`
}

// Envelope is a signed handover as the registry serves it.
type Envelope = attest.DSSEEnvelope

// Chain is the document a registry serves beside its key set: every
// handover it has made, oldest first.
type Chain struct {
	Registry  string     `json:"registry"`
	Handovers []Envelope `json:"handovers"`
}

// KeyID is the id a registry derives from a public key: the first 16
// characters of the unpadded base64url SHA-256 of its DER encoding.
func KeyID(publicKeyPEM string) (string, error) {
	pub, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return "", err
	}
	return attest.KeyIDFor(pub), nil
}

func parsePublicKey(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("key handover: not a PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("key handover: parse public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key handover: not an ECDSA public key")
	}
	return ec, nil
}

// Validate checks that a handover is complete and that its incoming key's
// id is the id of the key it carries, so a statement cannot name one key
// and hand over another.
func (h Handover) Validate() error {
	switch {
	case h.Schema != Schema:
		return fmt.Errorf("key handover: schema %q, want %q", h.Schema, Schema)
	case strings.TrimSpace(h.Registry) == "":
		return errors.New("key handover: no registry")
	case h.From == "":
		return errors.New("key handover: no outgoing key")
	case h.To.KeyID == "":
		return errors.New("key handover: no incoming key")
	case h.To.KeyID == h.From:
		return errors.New("key handover: a key cannot hand over to itself")
	case h.To.Algorithm != Algorithm:
		return fmt.Errorf("key handover: algorithm %q, want %q", h.To.Algorithm, Algorithm)
	case h.At.IsZero():
		return errors.New("key handover: no time")
	}
	id, err := KeyID(h.To.PublicKeyPEM)
	if err != nil {
		return err
	}
	if id != h.To.KeyID {
		return fmt.Errorf("key handover: the incoming key's id is %s, but the statement names %s", id, h.To.KeyID)
	}
	return nil
}

// Seal encodes a valid handover as the payload the outgoing key signs.
func Seal(h Handover) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(h)
}

// Wrap puts a payload and the outgoing key's signature into an envelope.
func Wrap(payload []byte, sig attest.DSSESignature) Envelope {
	return Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []attest.DSSESignature{sig},
	}
}

// Open verifies an envelope with the outgoing key, which the caller already
// trusts, and decodes the handover. It refuses another payload type, a
// field the format does not have, a statement whose outgoing key is not the
// key that verified it, and an incoming key whose id does not match. It
// does not check the registry: Follow does.
func Open(env Envelope, fromPublicKeyPEM string) (Handover, error) {
	fromID, err := KeyID(fromPublicKeyPEM)
	if err != nil {
		return Handover{}, err
	}
	payload, err := attest.VerifyPayload(env, fromPublicKeyPEM, PayloadType)
	if err != nil {
		return Handover{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var h Handover
	if err := dec.Decode(&h); err != nil {
		return Handover{}, fmt.Errorf("key handover: decode: %w", err)
	}
	if dec.More() {
		return Handover{}, errors.New("key handover: trailing data after the statement")
	}
	if err := h.Validate(); err != nil {
		return Handover{}, err
	}
	if h.From != fromID {
		return Handover{}, fmt.Errorf("key handover: signed by %s but names %s as the outgoing key", fromID, h.From)
	}
	return h, nil
}

// Follow walks a registry's chain from the keys a client already trusts and
// returns the handovers it can verify, in the order it adopted them: each
// one opened with a key that was trusted before it, for the registry the
// client names. A handover from a key the client never trusted is passed
// over (it proves nothing to this client), and so is one for another
// registry. A key the walk already trusts is never handed over again, so a
// chain that loops back ends.
//
// registry is compared after normalize, which the caller supplies so the
// package carries no rule of its own for spelling a registry's address.
func Follow(registry string, trusted []Key, chain Chain, normalize func(string) string) ([]Handover, error) {
	if normalize == nil {
		normalize = func(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }
	}
	want := normalize(registry)
	if c := normalize(chain.Registry); c != "" && c != want {
		return nil, fmt.Errorf("key handover: the chain is %s's, not %s's", chain.Registry, registry)
	}
	known := map[string]string{}
	for _, k := range trusted {
		if k.KeyID != "" && k.PublicKeyPEM != "" {
			known[k.KeyID] = k.PublicKeyPEM
		}
	}
	var adopted []Handover
	used := make([]bool, len(chain.Handovers))
	for progress := true; progress; {
		progress = false
		for i, env := range chain.Handovers {
			if used[i] {
				continue
			}
			for _, pemText := range known {
				h, err := Open(env, pemText)
				if err != nil {
					continue
				}
				used[i] = true
				if normalize(h.Registry) != want {
					break
				}
				if _, have := known[h.To.KeyID]; have {
					break
				}
				known[h.To.KeyID] = h.To.PublicKeyPEM
				adopted = append(adopted, h)
				progress = true
				break
			}
		}
	}
	return adopted, nil
}
