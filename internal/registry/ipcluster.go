package registry

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// IPClusterHash is the value agent_versions.submitter_ip_hash carries
// (agentry#27, §8.3 S8 "IP cluster"). It is HMAC-SHA256 over the address
// with a key derived from the deployment secret and the calendar month, so
// the same address hashes alike within a month — which is the window the
// ClawHavoc pattern (1,184 skills from 12 accounts in days) needs — and
// differently across months and deployments. The address itself is never
// stored, and a leaked hash set cannot be reversed without the secret.
// The "YYYY-MM:" prefix makes the rotation visible and keeps comparisons
// within one key.
func IPClusterHash(secret []byte, ip string, now time.Time) string {
	if ip == "" || len(secret) == 0 {
		return ""
	}
	month := now.UTC().Format("2006-01")
	km := hmac.New(sha256.New, secret)
	km.Write([]byte("agentry-ip-cluster:" + month))
	monthKey := km.Sum(nil)
	h := hmac.New(sha256.New, monthKey)
	h.Write([]byte(ip))
	return month + ":" + hex.EncodeToString(h.Sum(nil))[:32]
}

// SetIPClusterSecret installs the deployment secret the hash derives from.
// Empty disables the signal (no hash is recorded).
func (s *Service) SetIPClusterSecret(secret []byte) { s.ipClusterSecret = secret }
