package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

// Token kinds and their prefixes. PATs use `agy_` (D-22) — registered with
// secret scanners (S2 ships a matching rule). Sessions and verification
// tokens get distinct prefixes so leaked strings identify themselves.
const (
	PATPrefix     = "agy_"
	SessionPrefix = "agys_"
	// InvitePrefix marks an organization invitation token (agentry#361).
	// It is a credential like the others: shown once, stored as its hash.
	InvitePrefix       = "agyi_"
	VerificationPrefix = "agyv_"

	// PATDisplayPrefixLen is how many characters of a PAT are stored and
	// shown for identification (§4.2 pats.token_prefix).
	PATDisplayPrefixLen = 12
)

// base32 lowercase without padding: URL-safe, case-stable, 52 chars for 32B.
var tokenEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewToken mints a token: prefix + base32(32 random bytes).
func NewToken(prefix string) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("auth: token entropy: %w", err)
	}
	return prefix + strings.ToLower(tokenEnc.EncodeToString(raw[:])), nil
}

// HashToken returns the sha256 of the full token string — the only form
// stored at rest (D-22).
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// DisplayPrefix returns the identifying prefix of a PAT for UI/lookup.
func DisplayPrefix(token string) string {
	if len(token) < PATDisplayPrefixLen {
		return token
	}
	return token[:PATDisplayPrefixLen]
}

// IsPAT reports whether a presented credential is a PAT by prefix.
func IsPAT(token string) bool { return strings.HasPrefix(token, PATPrefix) }
