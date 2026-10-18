package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/pkg/handle"
)

// pathHandles and firstPartyHandles are the handle package's reserved
// names (pkg/handle): the root paths nobody may take, and the product's own
// names only platform staff may give an organization.
var (
	pathHandles       = handleSet(handle.PathNames())
	firstPartyHandles = handleSet(handle.FirstPartyNames())
)

func handleSet(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// firstPartyOrg reports whether an organization handle is one of the
// product's own: the platform-internal security_reviewer role exists only
// there; everywhere else
// the admins hold its powers.
func firstPartyOrg(h string) bool { return firstPartyHandles[h] }

// handleReserved reports whether no sign-up may take h: a root path or a
// first-party name. Sign-up has no staff.
func handleReserved(h string) bool { return orgHandleReserved(h, false) }

// orgHandleReserved reports whether the caller may not create an org named
// h: a root path is refused for everyone, a first-party name for everyone
// but platform staff.
func orgHandleReserved(h string, staff bool) bool {
	if pathHandles[h] {
		return true
	}
	return firstPartyHandles[h] && !staff
}

// unreservedHandle returns h, or h with a numeric suffix when h is
// reserved — for handles derived from an email or an IdP claim rather
// than chosen (a first sign-in through an IdP), where refusing is not an
// option.
func unreservedHandle(h string) string {
	if !handleReserved(h) {
		return h
	}
	if len(h) > 36 {
		h = h[:36]
	}
	return h + "-1"
}

var reHandleChars = regexp.MustCompile(`[^a-z0-9-]+`)

// allocateHandle derives a unique, grammar-valid handle for a JIT user
// from handleSeed. When the seed's handle is taken, the first fallback is
// the same name with a suffix derived from the subject — deterministic, so
// the same person signing up again lands on the same name, and still
// recognisably the one they chose — and only after that a random suffix.
// The derived suffix is keyed, so a public handle cannot be
// used to confirm a guess at the subject (for a provisioned member, the
// address).
func (s *Server) allocateHandle(ctx context.Context, username, email, subject string) (string, error) {
	base := sanitizeHandle(handleSeed(username, email, subject))
	if base == "" {
		base = "sso-user"
	}
	for i := 0; i < 6; i++ {
		cand := base
		switch {
		case i == 1:
			cand = truncateHandle(base, 30) + "-" + s.handleSuffix(subject)
		case i > 1:
			suffix, _ := auth.NewToken("")
			cand = truncateHandle(base, 30) + "-" + strings.ToLower(suffix)[:6]
		}
		if _, err := s.q().GetHandle(ctx, cand); errors.Is(err, pgx.ErrNoRows) {
			return cand, nil
		}
	}
	return "", errors.New("could not allocate a unique handle")
}

// handleSuffix is six hex characters of a keyed hash of the subject: the
// deterministic fallback suffix of allocateHandle.
func (s *Server) handleSuffix(subject string) string {
	key := []byte(s.cfg.Auth.SealingKey)
	if len(key) == 0 {
		key = []byte("agentry-dev-handle-suffix-key")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("handle-suffix:" + subject))
	return hex.EncodeToString(mac.Sum(nil))[:6]
}

// handleSeed picks what a JIT handle is derived from: the username the IdP
// asserts (OIDC preferred_username, a directory's userName) when it yields a valid
// handle, else the email's local part, else the subject. A username shaped
// like an address (Microsoft's UPN, a userName that is the email)
// contributes its local part, as the email would. The username was the
// person's choice at sign-up; the email's local part was never meant as a
// name.
func handleSeed(username, email, subject string) string {
	username = strings.TrimSpace(username)
	if strings.Contains(username, "@") {
		username = emailLocalPart(username)
	}
	if sanitizeHandle(username) != "" {
		return username
	}
	if seed := emailLocalPart(email); seed != "" {
		return seed
	}
	return subject
}

// handleRequestedDetail is what an audit event and the user.registered
// event record when the handle a JIT sign-up got is not the username the
// IdP asserted (taken, reserved, or outside the grammar), so the difference
// is on the record rather than silent. Nil when they agree or
// no username was asserted.
func handleRequestedDetail(username, handle string) map[string]any {
	username = strings.TrimSpace(username)
	if username == "" || strings.EqualFold(username, handle) {
		return nil
	}
	return map[string]any{"handleRequested": username}
}

func sanitizeHandle(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = reHandleChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	s = truncateHandle(s, 39)
	if len(s) < 1 {
		return ""
	}
	return unreservedHandle(s) // root paths are not handles
}

func truncateHandle(s string, n int) string {
	if len(s) > n {
		return strings.Trim(s[:n], "-")
	}
	return s
}

func emailLocalPart(email string) string {
	if i := strings.Index(email, "@"); i >= 0 {
		return email[:i]
	}
	return ""
}
