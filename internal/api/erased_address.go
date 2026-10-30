package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// erasedAddressPurpose names the key ErasedAddressKey is made under.
const erasedAddressPurpose = "erased address v1"

// normalizeAddress is one mailbox's address in one form: lowercase,
// trimmed, without a +tag in its local part, and for Gmail (gmail.com or
// googlemail.com, which deliver to the same mailboxes) without the local
// part's dots, which Gmail ignores, on the domain gmail.com. Other
// providers' dots are kept: they may name different mailboxes.
func normalizeAddress(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return email
	}
	local, domain := email[:at], email[at+1:]
	if plus := strings.IndexByte(local, '+'); plus > 0 {
		local = local[:plus]
	}
	if domain == "googlemail.com" {
		domain = "gmail.com"
	}
	if domain == "gmail.com" {
		local = strings.ReplaceAll(local, ".", "")
	}
	return local + "@" + domain
}

// ErasedAddressKey is an address's key for an extension that remembers
// erased accounts (pkg/extension.RemembersErasedAddresses): the
// normalized address under a key derived from the server's sealing key
// for this purpose alone, hex. Every form of one mailbox has the same key,
// and the key cannot be turned back into the address without the sealing
// key. It is not the tombstone's hash, which is of the address as stored.
func (s *Server) ErasedAddressKey(email string) string {
	mac, err := s.sealer.MAC(erasedAddressPurpose, []byte(normalizeAddress(email)))
	if err != nil {
		// HKDF-SHA256 for a 32-byte key does not fail.
		panic("api: erased address key: " + err.Error())
	}
	return hex.EncodeToString(mac)
}

// ErasedAddressRememberer keeps what an extension must remember about an
// erased account's address, by its key, inside the erasure's transaction.
// An error rolls the erasure back.
type ErasedAddressRememberer func(ctx context.Context, tx ErasureTx, userID uuid.UUID, addressKey string) error

type namedRememberer struct {
	name     string
	remember ErasedAddressRememberer
}

// AddErasedAddressRememberer registers an extension's rememberer
// (pkg/extension.RemembersErasedAddresses), called in registration order
// inside the transaction of every account erasure, before the erasers.
// A name registered twice panics.
func (s *Server) AddErasedAddressRememberer(name string, fn ErasedAddressRememberer) {
	for _, r := range s.addressRememberers {
		if r.name == name {
			panic("api: erased address rememberer registered twice: " + name)
		}
	}
	s.addressRememberers = append(s.addressRememberers, namedRememberer{name: name, remember: fn})
}

// rememberErasedAddress hands every registered rememberer the erased
// account's address key in tx.
func (s *Server) rememberErasedAddress(ctx context.Context, tx pgx.Tx, userID uuid.UUID, email string) error {
	if len(s.addressRememberers) == 0 {
		return nil
	}
	key := s.ErasedAddressKey(email)
	for _, r := range s.addressRememberers {
		if err := r.remember(ctx, erasureTx{tx}, userID, key); err != nil {
			return fmt.Errorf("extension %s: remember an erased address: %w", r.name, err)
		}
	}
	return nil
}
