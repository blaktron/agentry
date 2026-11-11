package managedsettings

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
)

// SchemaMembers names the document's shape when it is bound to the
// accounts it is for. A registry that signs several documents for one
// organization at one version (one for each combination of teams with
// settings) binds each to its members, so a member who holds another
// member's document cannot put it in place of their own: the client
// refuses a bound document that does not name its account. A document
// that every member of the organization receives alike keeps Schema.
const SchemaMembers = "managed-settings/2"

// Members binds a document to the accounts it is for. It lists a digest
// of each account's id under a salt drawn for the document, so the
// document names its members to a client that knows its own account and
// to no one else.
type Members struct {
	// Salt is 16 random bytes, base64 (standard, padded).
	Salt string `json:"salt"`
	// Digests are memberDigest of each account's id, lowercase hex,
	// sorted, without repeats.
	Digests []string `json:"digests"`
}

// saltSize is a salt's length in bytes; digestSize a digest's.
const (
	saltSize   = 16
	digestSize = 16
)

// maxMembers bounds the accounts one document is bound to.
const maxMembers = 100_000

// memberDigest is the digest of account under salt: the first 16 bytes of
// SHA-256 over a fixed label, the salt and the account's id, so a digest
// means nothing outside this document and its use.
func memberDigest(salt []byte, account string) string {
	h := sha256.New()
	h.Write([]byte("agentry managed-settings member\x00"))
	h.Write(salt)
	h.Write([]byte(account))
	return hex.EncodeToString(h.Sum(nil)[:digestSize])
}

// BindMembers binds a document to accounts (their ids, as the registry
// names them) under a new random salt.
func BindMembers(accounts []string) (*Members, error) {
	if len(accounts) == 0 {
		return nil, errors.New("managed settings: a bound document needs at least one member")
	}
	if len(accounts) > maxMembers {
		return nil, fmt.Errorf("managed settings: %d members, at most %d", len(accounts), maxMembers)
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("managed settings: draw a salt: %w", err)
	}
	m := &Members{Salt: base64.StdEncoding.EncodeToString(salt)}
	for _, a := range accounts {
		if a == "" {
			return nil, errors.New("managed settings: an empty account id")
		}
		m.Digests = append(m.Digests, memberDigest(salt, a))
	}
	slices.Sort(m.Digests)
	m.Digests = slices.Compact(m.Digests)
	return m, nil
}

// Includes reports whether account is one of the members.
func (m Members) Includes(account string) bool {
	salt, err := base64.StdEncoding.DecodeString(m.Salt)
	if err != nil || len(salt) != saltSize || account == "" {
		return false
	}
	_, found := slices.BinarySearch(m.Digests, memberDigest(salt, account))
	return found
}

// validate checks the shape a registry signs: a salt of the right length
// and sorted, distinct digests of the right length.
func (m Members) validate() error {
	salt, err := base64.StdEncoding.DecodeString(m.Salt)
	if err != nil || len(salt) != saltSize {
		return errors.New("managed settings: members: the salt is not 16 bytes of base64")
	}
	switch {
	case len(m.Digests) == 0:
		return errors.New("managed settings: members: no digests")
	case len(m.Digests) > maxMembers:
		return fmt.Errorf("managed settings: members: %d digests, at most %d", len(m.Digests), maxMembers)
	}
	for i, d := range m.Digests {
		if b, err := hex.DecodeString(d); err != nil || len(b) != digestSize || hex.EncodeToString(b) != d {
			return fmt.Errorf("managed settings: members: digest %d is not %d bytes of lowercase hex", i, digestSize)
		}
		if i > 0 && m.Digests[i-1] >= d {
			return errors.New("managed settings: members: the digests are not sorted and distinct")
		}
	}
	return nil
}

// ErrNotForAccount is a bound document that does not name the account a
// client is signed in as.
var ErrNotForAccount = errors.New("this document was signed for other members of the organization, not for the signed-in account")

// For checks that the document applies to account (the signed-in
// account's id): a document every member receives alike applies to any,
// and a bound one only to the accounts it names. A client calls it after
// Open, with the account it signed in as, before it applies or keeps the
// document.
func (d Document) For(account string) error {
	if d.Members == nil {
		return nil
	}
	if !d.Members.Includes(account) {
		return ErrNotForAccount
	}
	return nil
}
