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
// Trust: the digest is the pin, and — when this deployment signs releases —
// GET /ruleset-releases/latest/attestation is a DSSE envelope over that
// digest, signed with the same key, so a client can verify the bundle by
// signature and not only by a digest the same server advertised (agentry#25;
// DEV-024 recorded the earlier deferral).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/attest"
	"github.com/blaktron/agentry/pkg/ruleset"
)

// GetLatestRulesetBundle implements GET /ruleset-releases/latest/bundle.
func (s *Server) GetLatestRulesetBundle(w http.ResponseWriter, r *http.Request) {
	bundle, err := ruleset.Load()
	if err != nil {
		s.log.ErrorContext(r.Context(), "ruleset load", "err", err)
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
				s.log.ErrorContext(r.Context(), "ruleset digest mismatch", "semver", semver,
					"embedded", digest, "recorded", row.BundleDigest)
				problemInternal(w, r)
				return
			}
		case errors.Is(rerr, pgx.ErrNoRows):
			// Not registered (dev instance, or boot registration skipped).
			// The bundle's own digest is still a sound pin over these bytes.
		default:
			s.log.ErrorContext(r.Context(), "ruleset release lookup", "err", rerr)
			problemInternal(w, r)
			return
		}
	}

	data, err := bundle.Tar()
	if err != nil {
		s.log.ErrorContext(r.Context(), "ruleset tar", "err", err)
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
			s.log.WarnContext(r.Context(), "ruleset bundle write", "err", werr)
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

// storeRulesetAttestation signs the statement over the embedded bundle's
// digest and stores it (agentry#479). The process that holds the key does
// this once at start; the api role, which holds no key, serves the stored
// envelope. A row already there for this digest and key is kept.
func storeRulesetAttestation(ctx context.Context, st *store.Store, signer scan.Signer, baseURL string) error {
	bundle, err := ruleset.Load()
	if err != nil {
		return fmt.Errorf("ruleset attestation: load the bundle: %w", err)
	}
	digest := normalizeDigest(bundle.Digest())
	env, err := signer.Sign(attest.BuildRulesetStatement(baseURL, bundle.Version(), digest))
	if err != nil {
		return fmt.Errorf("ruleset attestation: sign: %w", err)
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("ruleset attestation: encode: %w", err)
	}
	if err := st.Queries().InsertRulesetAttestation(ctx, storegen.InsertRulesetAttestationParams{
		BundleDigest: digest, KeyID: signer.KeyID(), DsseEnvelope: body,
	}); err != nil {
		return fmt.Errorf("ruleset attestation: store: %w", err)
	}
	return nil
}

// GetLatestRulesetAttestation implements GET /ruleset-releases/latest/attestation.
// It serves the envelope the key holder stored for this binary's bundle,
// signed by the active key (agentry#479), so the api role answers without
// the private key. 404 when no key holder has started with this bundle.
func (s *Server) GetLatestRulesetAttestation(w http.ResponseWriter, r *http.Request) {
	bundle, err := ruleset.Load()
	if err != nil {
		s.log.ErrorContext(r.Context(), "ruleset load", "err", err)
		problemInternal(w, r)
		return
	}
	digest := normalizeDigest(bundle.Digest())
	if s.st == nil {
		problemNotFound(w, r)
		return
	}
	row, err := s.q().GetRulesetAttestation(r.Context(), digest)
	if errors.Is(err, pgx.ErrNoRows) {
		// No key holder has started with this bundle yet.
		problemNotFound(w, r)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "ruleset attestation read", "err", err)
		problemInternal(w, r)
		return
	}
	body := row.DsseEnvelope
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Agentry-Bundle-Semver", bundle.Version())
	h.Set("X-Agentry-Bundle-Digest", digest)
	h.Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
