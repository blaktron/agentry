package api

// POST /platform/ruleset-releases (§9.2 platform, §8.3): register the
// versioned scanner bundle a deployment is running so scan_runs can point at
// it. Platform staff only — a ruleset release is the provenance of every
// verdict the pipeline reaches.

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/internal/scan/ruleset"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

var reSemver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?$`)

// CreateRulesetRelease implements POST /platform/ruleset-releases.
func (s *Server) CreateRulesetRelease(w http.ResponseWriter, r *http.Request) {
	if !s.requireDB(w, r) {
		return
	}
	if !s.requireStaff(w, r) {
		return
	}
	ik, handled := s.beginIdempotent(w, r, "POST /platform/ruleset-releases")
	if handled {
		return
	}
	defer ik.abandon(r)

	var req CreateRulesetReleaseJSONRequestBody
	if err := readJSONOptional(r, &req); err != nil {
		problemBadRequest(w, r, "invalid JSON body: "+err.Error())
		return
	}

	semver, digest, notes := "", "", ""
	if req.Semver != nil {
		semver = strings.TrimSpace(*req.Semver)
	}
	if req.BundleDigest != nil {
		digest = strings.TrimSpace(*req.BundleDigest)
	}
	if req.Notes != nil {
		notes = strings.TrimSpace(*req.Notes)
	}

	// No body (or a partial one) registers the server's OWN embedded bundle.
	// That is the common case: an operator confirming which rules this
	// deployment is actually running, which is exactly the fact the release
	// row is supposed to pin down.
	if semver == "" || digest == "" {
		bundle, err := ruleset.Load()
		if err != nil {
			s.log.Error("ruleset load", "err", err)
			problemInternal(w, r)
			return
		}
		if semver == "" {
			semver = bundle.Version()
		}
		if digest == "" {
			digest = bundle.Digest()
		}
		if notes == "" {
			notes = bundle.Notes()
		}
	}
	if !reSemver.MatchString(semver) {
		problemValidation(w, r, "semver must be MAJOR.MINOR.PATCH",
			FieldError{Field: "semver", Message: "expected a semantic version"})
		return
	}
	if digest == "" {
		problemValidation(w, r, "bundleDigest is required",
			FieldError{Field: "bundleDigest", Message: "expected sha256:<hex>"})
		return
	}

	// Re-registering a semver is a no-op that returns the existing row: the
	// digest for a given ruleset version is immutable by definition, so the
	// only sane answer to a repeat is the row already on file.
	if existing, err := s.q().GetRulesetReleaseBySemver(r.Context(), semver); err == nil {
		out := rulesetReleaseToAPI(existing)
		ik.complete(r, http.StatusOK, out)
		writeJSON(w, http.StatusOK, out)
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.log.Error("ruleset lookup", "err", err)
		problemInternal(w, r)
		return
	}

	id := newUUID()
	var created storegen.RulesetRelease
	var inserted bool
	var notesPtr *string
	if notes != "" {
		notesPtr = &notes
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		row, err := q.CreateRulesetRelease(r.Context(), storegen.CreateRulesetReleaseParams{
			ID: id, Semver: semver, BundleDigest: digest, Notes: notesPtr,
		})
		if err != nil {
			return err
		}
		created = storegen.RulesetRelease{
			ID: row.ID, Semver: row.Semver, BundleDigest: row.BundleDigest,
			Notes: row.Notes, PublishedAt: row.PublishedAt,
		}
		inserted = row.Inserted
		e := auditEvent(r, audit.ActionRulesetRelease)
		e.TargetKind, e.TargetID = "ruleset_release", row.ID
		e.Detail = map[string]any{"semver": semver, "bundleDigest": digest}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		if isUniqueViolation(err) {
			problemConflict(w, r, "this ruleset semver is already registered")
			return
		}
		s.log.Error("create ruleset release", "err", err)
		problemInternal(w, r)
		return
	}
	// A genuinely new semver is the §8.7 trigger for re-checking the published
	// catalogue — same rule as boot-time registration in New().
	if inserted {
		scan.EnqueueRescanSweepOnNewRuleset(r.Context(), s.jobs, s.log, scan.RulesetRegistration{
			ID: created.ID, Semver: created.Semver, New: true,
		})
	}
	out := rulesetReleaseToAPI(created)
	ik.complete(r, http.StatusCreated, out)
	writeJSON(w, http.StatusCreated, out)
}

func rulesetReleaseToAPI(row storegen.RulesetRelease) RulesetRelease {
	out := RulesetRelease{
		Id: row.ID, Semver: row.Semver, BundleDigest: row.BundleDigest,
		PublishedAt: row.PublishedAt,
	}
	out.Notes = row.Notes
	return out
}
