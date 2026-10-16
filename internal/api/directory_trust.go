package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth/social"
	"github.com/blaktron/agentry/internal/httpmux"
)

// The directory's trust check.
//
// A deployment that signs in through the directory leaves it to decide
// whether to show the code page. A policy on its MFA stage reads
// the remembered-browser cookie (set by the registry on the callback, scoped to
// the directory's flow executor) and asks here whether that cookie is a live
// record of the user signing in. Only an explicit trusted:true skips the code:
// the policy treats every other answer, and no answer, as "ask", which is what
// makes a 503 below the fail-closed direction.
//
// The route is a root mount outside /api/ and is not in the OpenAPI surface.
// Its caller is infrastructure holding a shared secret, not a principal, and
// no edge shipped with the registry routes /internal/ to the registry. It answers with
// bare status codes rather than problem+json: its only reader is a policy
// that acts on trusted:true and treats everything else as "ask".
//
// The directory calls it directly on the private network, so a request that
// carries a proxy's forwarding header came through an edge or an ingress and
// is answered 404, the right secret or not. That covers a chart whose ingress
// routes the whole host to the api; a directory reached through a proxy of
// its own is refused, and asks for the code.

// directoryTrustBodyLimit bounds the request: a token and a subject are well
// under a kilobyte.
const directoryTrustBodyLimit = 4 << 10

func (s *Server) mountDirectoryTrust(mux httpmux.Mux) {
	MountFunc(mux, "POST /internal/directory/trusted-device", s.directoryTrustCheck)
	MountFunc(mux, "POST /internal/directory/email-verification", s.directoryEmailVerification)
}

type directoryTrustRequest struct {
	// Token is the cookie's value, as the directory received it.
	Token string `json:"token"`
	// Sub is the directory's subject for the user signing in: the same value
	// its ID tokens carry as `sub`, which the registry holds as the identity
	// "authentik:<sub>".
	Sub string `json:"sub"`
}

func (s *Server) allowDirectoryCheck(w http.ResponseWriter, r *http.Request) bool {
	secret := s.cfg.Auth.IdPTrustCheckToken
	if secret == "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
		// The directory path is off, or the request came through a proxy:
		// either way the route answers as though it did not exist.
		http.NotFound(w, r)
		return false
	}
	given, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(given), []byte(secret)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) directoryTrustCheck(w http.ResponseWriter, r *http.Request) {
	if !s.allowDirectoryCheck(w, r) {
		return
	}
	var req directoryTrustRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, directoryTrustBodyLimit)).Decode(&req); err != nil ||
		req.Token == "" || req.Sub == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.st == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	trusted, err := s.directoryTrusts(r.Context(), r, req)
	if err != nil {
		s.log.WarnContext(r.Context(), "directory trust check: the store could not answer, so the directory asks for the code", "err", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"trusted": trusted})
}

// directoryTrusts answers the check. Every "not this user's live record" is
// false with no error, and only a store that could not answer is an error.
// The identity the directory's subject is linked to names the account; the
// rest is useTrustedDevice, the same use an extension's directory makes.
func (s *Server) directoryTrusts(ctx context.Context, r *http.Request, req directoryTrustRequest) (bool, error) {
	q := s.q()
	ident, err := q.GetSocialIdentity(ctx, social.ProviderAuthentik+":"+req.Sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// The use is recorded before the answer is given: a skip nobody could
	// audit is not granted.
	return s.useTrustedDevice(ctx, r, ident.UserID, req.Token, map[string]any{"via": "directory"})
}
