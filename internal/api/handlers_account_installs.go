package api

// Account installs: a
// signed-in person's record, on the registry, of a QuickAgent release they
// accepted for their account — the version, the declared capabilities they
// consented to, and the unsigned or unscanned consents the release needed.
// An acceptance, not a laying-down: nothing is written on any machine, the
// desktop's and the CLI's installed.yaml is a different, per-machine record
// never synced with this one, and no download counter moves — a star is
// public approval, an install a private acceptance of a contract.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/manifest"
)

// The acceptances a release can need, as the consent problem names them.
const (
	consentCapabilities = "capabilities"
	consentUnsigned     = "unsigned"
	consentUnscanned    = "unscanned"
)

// installTarget is what the caller may record: the QuickAgent, resolved
// for read, and the caller — or the problem written and false. The
// QuickAgent comes first, before the self-scoped authorization: a caller
// who cannot read it, anonymous or a stranger, gets the missing name's 404
// before any 401 that would say the name exists; a
// public name keeps the conventional 401 for an anonymous write.
func (s *Server) installTarget(w http.ResponseWriter, r *http.Request, ns, name string) (registry.Agent, *auth.Principal, bool) {
	if !s.requireDB(w, r) {
		return registry.Agent{}, nil, false
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return registry.Agent{}, nil, false
	}
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return registry.Agent{}, nil, false
	}
	return a, principalFrom(r.Context()), true
}

// PutAccountInstall implements PUT /user/installs/{ns}/{name}: record a
// published release the caller can read as installed to the account, or
// move an existing record to it. Refused with install-consent-required
// when the request lacks an acceptance the release needs: the declared
// capabilities on a first install and on an update that widened them
// against the accepted snapshot (the rule the CLI's and the desktop's
// updates apply); unsigned whenever the release carries no attestation;
// unscanned whenever it was admitted without a scan.
func (s *Server) PutAccountInstall(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	a, p, ok := s.installTarget(w, r, ns, name)
	if !ok {
		return
	}
	var req AccountInstallRequest
	if !readJSON(w, r, &req) {
		return
	}
	version := strings.TrimSpace(req.Version)
	if version == "" {
		problemValidation(w, r, "Name the published version to record, exactly.", FieldError{Field: "version", Message: "required"})
		return
	}
	ctx := r.Context()
	q := s.q()
	if a.QuarantineState == "blocked" {
		writeProblem(w, r, http.StatusGone, "blocked", "Blocked QuickAgent",
			"Trust & safety has blocked this QuickAgent; nothing of it can be installed.")
		return
	}
	v, err := q.GetVersion(ctx, storegen.GetVersionParams{AgentID: a.ID, Version: version})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemNotFound(w, r)
			return
		}
		s.log.ErrorContext(ctx, "account install: version", "agent", a.ID, "version", version, "err", err)
		problemInternal(w, r)
		return
	}
	if registry.Status(v.Status) != registry.StatusPublished {
		writeProblemWith(w, r, http.StatusConflict, "version-not-published", "Not a published release",
			"Only a published release can be installed to the account; this version is "+v.Status+".",
			map[string]any{"status": v.Status})
		return
	}

	// What this release needs, against what the caller already accepted.
	var declared manifest.Capabilities
	if len(v.Capabilities) > 0 {
		if err := json.Unmarshal(v.Capabilities, &declared); err != nil {
			s.log.ErrorContext(ctx, "account install: declared capabilities", "version", v.ID, "err", err)
			problemInternal(w, r)
			return
		}
	}
	signed, err := s.versionSigned(ctx, v.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "account install: attestation", "version", v.ID, "err", err)
		problemInternal(w, r)
		return
	}
	unscanned := v.ScanStatus == registry.ScanStatusSkipped
	needsCapabilities := true
	var widened []string
	existing, err := q.GetAccountInstall(ctx, storegen.GetAccountInstallParams{UserID: p.UserID, AgentID: a.ID})
	switch {
	case err == nil:
		var accepted manifest.Capabilities
		if len(existing.Capabilities) > 0 {
			if err := json.Unmarshal(existing.Capabilities, &accepted); err != nil {
				s.log.ErrorContext(ctx, "account install: accepted snapshot", "user", p.UserID, "agent", a.ID, "err", err)
				problemInternal(w, r)
				return
			}
		}
		diff := manifest.DiffCapabilities(accepted, declared)
		needsCapabilities = diff.HasWidened()
		widened = diff.Widened
	case errors.Is(err, pgx.ErrNoRows):
		// A first install: the contract is accepted whole.
	default:
		s.log.ErrorContext(ctx, "account install: record", "user", p.UserID, "agent", a.ID, "err", err)
		problemInternal(w, r)
		return
	}
	var missing []string
	if needsCapabilities && (req.AcceptCapabilities == nil || !*req.AcceptCapabilities) {
		missing = append(missing, consentCapabilities)
	}
	if !signed && (req.AcceptUnsigned == nil || !*req.AcceptUnsigned) {
		missing = append(missing, consentUnsigned)
	}
	if unscanned && (req.AcceptUnscanned == nil || !*req.AcceptUnscanned) {
		missing = append(missing, consentUnscanned)
	}
	if len(missing) > 0 {
		problemInstallConsentRequired(w, r, missing, widened)
		return
	}

	// Recorded: the consents kept are the ones the release needed, so the
	// record never says a signed release was accepted as unsigned.
	var row storegen.AccountInstall
	err = s.st.WithTx(ctx, func(tq *storegen.Queries) error {
		var err error
		row, err = tq.UpsertAccountInstall(ctx, storegen.UpsertAccountInstallParams{
			UserID: p.UserID, AgentID: a.ID, VersionID: v.ID,
			RefNamespace: a.Namespace, RefName: a.Name, Capabilities: v.Capabilities,
			AcceptedUnsigned: !signed, AcceptedUnscanned: unscanned,
		})
		if err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionAgentInstall)
		e.TargetKind, e.TargetID = "agent", a.ID
		e.Detail = map[string]any{"version": v.Version}
		return s.auditW.Write(ctx, tq, e)
	})
	if err != nil {
		s.log.ErrorContext(ctx, "account install: write", "user", p.UserID, "agent", a.ID, "err", err)
		problemInternal(w, r)
		return
	}
	out, err := s.composeAccountInstall(ctx, p, row, a.Namespace, a.Name)
	if err != nil {
		s.log.ErrorContext(ctx, "account install: compose", "user", p.UserID, "agent", a.ID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// DeleteAccountInstall implements DELETE /user/installs/{ns}/{name}:
// idempotent, like a star's removal, and audited as agent.uninstall only
// when a record went. The row is the caller's own, so no QuickAgent is
// resolved for read and the answer is 204 whether the name resolves, is
// readable, or neither — nothing about a QuickAgent is learned here, and
// a record whose QuickAgent the caller can no longer read (the bare ref
// on the list) is removable by that ref. The name is tried as a
// QuickAgent first, so a record on the QuickAgent that lives at the name
// today goes before one stored under it by a QuickAgent that has moved.
func (s *Server) DeleteAccountInstall(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	ctx := r.Context()
	p := principalFrom(ctx)
	var byAgent *uuid.UUID
	if a, err := s.reg.Resolve(ctx, ns, name); err == nil {
		byAgent = &a.ID
	} else if !errors.Is(err, registry.ErrNotFound) {
		s.log.ErrorContext(ctx, "account uninstall: resolve", "user", p.UserID, "ref", ns+"/"+name, "err", err)
		problemInternal(w, r)
		return
	}
	err := s.st.WithTx(ctx, func(tq *storegen.Queries) error {
		var removed []uuid.UUID
		if byAgent != nil {
			n, err := tq.DeleteAccountInstall(ctx, storegen.DeleteAccountInstallParams{UserID: p.UserID, AgentID: *byAgent})
			if err != nil {
				return err
			}
			if n > 0 {
				removed = append(removed, *byAgent)
			}
		}
		if len(removed) == 0 {
			ids, err := tq.DeleteAccountInstallByRef(ctx, storegen.DeleteAccountInstallByRefParams{UserID: p.UserID, RefNamespace: ns, RefName: name})
			if err != nil {
				return err
			}
			removed = ids
		}
		for _, id := range removed {
			e := auditEvent(r, audit.ActionAgentUninstall)
			e.TargetKind, e.TargetID = "agent", id
			if err := s.auditW.Write(ctx, tq, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.ErrorContext(ctx, "account uninstall", "user", p.UserID, "ref", ns+"/"+name, "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListAccountInstalls implements GET /user/installs: the caller's records
// composed for a list, newest change first.
func (s *Server) ListAccountInstalls(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	ctx := r.Context()
	p := principalFrom(ctx)
	rows, err := s.q().ListAccountInstalls(ctx, p.UserID)
	if err != nil {
		s.log.ErrorContext(ctx, "account installs: list", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	out := make([]AccountInstall, 0, len(rows))
	for _, row := range rows {
		item, err := s.composeAccountInstall(ctx, p, row.AccountInstall, row.Namespace, row.Name)
		if err != nil {
			s.log.ErrorContext(ctx, "account installs: compose", "user", p.UserID, "agent", row.AccountInstall.AgentID, "err", err)
			problemInternal(w, r)
			return
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

// composeAccountInstall builds one list row for a record whose QuickAgent
// lives at ns/name today. Whether the caller can read it is decided by
// agentForAction with the read action — the one path every agent route
// takes — so a record for a QuickAgent made private to them, or one whose
// organization is suspended, is the bare ref with readable: false and
// nothing else, and that ref is the one stored when they installed it,
// never where the QuickAgent has gone since: the list tells a former
// reader nothing they did not already know. A blocked QuickAgent stays
// readable and says so in quarantineState.
func (s *Server) composeAccountInstall(ctx context.Context, p *auth.Principal, row storegen.AccountInstall, ns, name string) (AccountInstall, error) {
	out := AccountInstall{Ref: row.RefNamespace + "/" + row.RefName}
	a, _, err := s.agentForAction(ctx, p, ns, name, auth.ActAgentRead)
	if err != nil {
		var gate *registry.OrgGateError
		if errors.Is(err, registry.ErrNotFound) || errors.As(err, &gate) {
			return out, nil
		}
		return out, err
	}
	q := s.q()
	v, err := q.GetVersionByID(ctx, row.VersionID)
	if err != nil {
		return out, err
	}
	out.Ref = a.Namespace + "/" + a.Name
	out.Readable = true
	out.InstalledVersion = &v.Version
	// The snapshot is served as the version's own block is (versionToAPI):
	// one that will not parse is left out of the row rather than failing
	// the list. A PUT, which must diff it, fails closed instead.
	if len(row.Capabilities) > 0 {
		var caps map[string]interface{}
		if err := json.Unmarshal(row.Capabilities, &caps); err == nil {
			out.Capabilities = &caps
		}
	}
	unsigned, unscanned := row.AcceptedUnsigned, row.AcceptedUnscanned
	out.AcceptedUnsigned, out.AcceptedUnscanned = &unsigned, &unscanned
	installedAt, updatedAt := row.CreatedAt, row.UpdatedAt
	out.InstalledAt, out.UpdatedAt = &installedAt, &updatedAt
	state := AccountInstallQuarantineState(a.QuarantineState)
	out.QuarantineState = &state
	if a.LatestPublishedVersionID != nil {
		latest, err := q.GetVersionByID(ctx, *a.LatestPublishedVersionID)
		if err != nil {
			return out, err
		}
		out.LatestVersion = &latest.Version
	}
	signed, err := s.versionSigned(ctx, v.ID)
	if err != nil {
		return out, err
	}
	out.Signed = &signed
	verdict, counts, err := s.versionVerdict(ctx, v)
	if err != nil {
		return out, err
	}
	out.Verdict, out.FindingCounts = verdict, counts
	return out, nil
}

// versionSigned reports whether an attestation stands behind the version.
func (s *Server) versionSigned(ctx context.Context, versionID uuid.UUID) (bool, error) {
	if _, err := s.q().GetAttestation(ctx, versionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// versionVerdict is the report's verdict for a version, as GET …/report
// gives it: unscanned for a version admitted without a scan, scanned with
// its finding counts when a run stands behind the report, absent while a
// first scan is pending or when the report's run errored. A rescan in
// flight does not blank it: the report's run is the latest finished one
// (reportRun).
func (s *Server) versionVerdict(ctx context.Context, v registry.Version) (*ReportVerdict, *map[string]int, error) {
	if v.ScanStatus == registry.ScanStatusSkipped {
		unscanned := Unscanned
		return &unscanned, nil, nil
	}
	run, _, err := reportRun(ctx, s.q(), v.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if !scanRunStandsBehindReport(run.Status) {
		return nil, nil, nil
	}
	rows, err := s.q().CountFindingsBySeverity(ctx, run.ID)
	if err != nil {
		return nil, nil, err
	}
	counts := make(map[string]int, len(rows))
	for _, row := range rows {
		counts[row.Severity] = int(row.Count)
	}
	scanned := Scanned
	return &scanned, &counts, nil
}

// problemInstallConsentRequired refuses an account install that lacks an
// acceptance the release needs, naming the missing ones in `missing` so a
// client can ask for exactly those, and in `widened` what an update
// widened.
func problemInstallConsentRequired(w http.ResponseWriter, r *http.Request, missing, widened []string) {
	var what []string
	for _, m := range missing {
		switch m {
		case consentCapabilities:
			if len(widened) > 0 {
				what = append(what, "its widened capabilities ("+strings.Join(widened, "; ")+")")
			} else {
				what = append(what, "its declared capabilities")
			}
		case consentUnsigned:
			what = append(what, "that it carries no attestation")
		case consentUnscanned:
			what = append(what, "that it was admitted without a scan")
		}
	}
	ext := map[string]any{"missing": missing}
	if len(widened) > 0 {
		ext["widened"] = widened
	}
	writeProblemWith(w, r, http.StatusConflict, "install-consent-required", "Consent required",
		"This release needs your acceptance of "+strings.Join(what, ", and ")+". Send the acceptance and retry.", ext)
}
