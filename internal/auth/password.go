// Package auth implements authentication and authorization primitives:
// argon2id password hashing, PAT/session token handling, TOTP 2FA, PAT
// scopes, and the single authorization chokepoint.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters per OWASP/RFC 9106 second recommendation
// (m=64MiB, t=3, p=4); encoded in the hash so they can evolve.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns a PHC-formatted argon2id hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// decoyHash is a real argon2id hash of a secret nobody knows, made once,
// for the comparison a login pays when it has no password to check. Made
// on first use rather than at init: the hash costs 64 MiB and ~100 ms,
// which every process importing this package would otherwise pay.
var decoyHash = sync.OnceValue(func() string {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("auth: decoy secret: " + err.Error())
	}
	h, err := HashPassword(base64.RawStdEncoding.EncodeToString(secret))
	if err != nil {
		panic("auth: decoy hash: " + err.Error())
	}
	return h
})

// SpendPasswordCheck runs the argon2id comparison against a decoy, so a
// login that found no account, an inactive one, or one without a password
// takes as long to refuse as a wrong password does; otherwise the time a
// refusal takes says which of those it was.
func SpendPasswordCheck(password string) {
	_ = VerifyPassword(password, decoyHash())
}

// VerifyPassword checks password against a PHC argon2id hash in constant
// time. Unknown formats verify as false, never as an error the caller might
// mistake for "try another way".
func VerifyPassword(password, phc string) bool {
	parts := strings.Split(phc, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
