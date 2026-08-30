package api

// GET /ruleset-releases/latest/bundle (§11 `agentry validate --rules-update`).
//
// The CLI ships an embedded S3/S4 rule bundle so offline validation matches
// what the server runs (D-12). Rules move faster than CLI releases, so the
// CLI needs a way to pick up a newer bundle without waiting for a new binary.
// This endpoint is that way: it serves THIS deployment's bundle — the exact
// bytes its own pipeline scans with — as a tar, with the bundle's semver and
// content digest in headers.
//
// "Latest" therefore means "the newest bundle this registry can actually
// produce bytes for", which is the one it is running. A registry cannot serve
// a bundle it does not have, and a ruleset_releases row is a record of a
// bundle's identity, not a copy of it.
//
// Trust: the digest is the pin. A client recomputes it over what it received
// and refuses a mismatch. There is no signature over a bundle yet — see
// DEVIATIONS DEV-024, which records that deferral rather than inventing a
// scheme the server cannot honour.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/scan/ruleset"
)

// GetLatestRulesetBundle implements GET /ruleset-releases/latest/bundle.
func (s *Server) GetLatestRulesetBundle(w http.ResponseWriter, r *http.Request) {
	bundle, err := ruleset.Load()
	if err != nil {
		s.log.Error("ruleset load", "err", err)
		problemInternal(w, r)
		return
	}
	semver, digest := bundle.Version(), normalizeDigest(bundle.Digest())

	// Cross-check against the release row registered at boot. If the row for
	// this semver records a DIFFERENT digest, the deployment's identity is
	// contested: something registered "ruleset 1.2.0" as other bytes than the
	// ones in this binary. Serving either answer would make the digest pin a
	// lie, so serve neither.
	if s.st != nil {
		row, rerr := s.q().GetRulesetReleaseBySemver(r.Context(), semver)
		switch {
		case rerr == nil:
			if normalizeDigest(row.BundleDigest) != digest {
				s.log.Error("ruleset digest mismatch", "semver", semver,
					"embedded", digest, "recorded", row.BundleDigest)
				problemInternal(w, r)
				return
			}
		case errors.Is(rerr, pgx.ErrNoRows):
			// Not registered (dev instance, or boot registration skipped).
			// The bundle's own digest is still a sound pin over these bytes.
		default:
			s.log.Error("ruleset release lookup", "err", rerr)
			problemInternal(w, r)
			return
		}
	}

	data, err := bundle.Tar()
	if err != nil {
		s.log.Error("ruleset tar", "err", err)
		problemInternal(w, r)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "application/x-tar")
	h.Set("X-Agentry-Bundle-Semver", semver)
	h.Set("X-Agentry-Bundle-Digest", digest)
	h.Set("ETag", `"`+digest+`"`)
	// Briefly cacheable: a bundle changes only on deploy, and a client that
	// re-checks every few minutes is not the load problem here.
	h.Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		if _, werr := w.Write(data); werr != nil {
			s.log.Warn("ruleset bundle write", "err", werr)
		}
	}
}

// normalizeDigest renders a bundle digest in the documented "sha256:<hex>"
// form. pkg/rules computes bare hex and the ruleset_releases rows carry
// whatever was registered, so both sides are normalized before comparison —
// a digest that differs only by its prefix is the same digest.
func normalizeDigest(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return ""
	}
	return "sha256:" + strings.TrimPrefix(d, "sha256:")
}
