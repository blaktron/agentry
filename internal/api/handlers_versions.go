package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Upload limits for cli-upload archives (§19: 10 MB post-filter; accept a
// little padding for the container itself). maxUploadBytes caps the whole
// request body; multipartMemoryBytes is only how much of it net/http may hold
// in memory before spooling.
const (
	maxUploadBytes       = 12 << 20
	multipartMemoryBytes = 1 << 20
)

func versionToAPI(v registry.Version) AgentVersion {
	out := AgentVersion{
		Id:        v.ID,
		Version:   v.Version,
		Status:    VersionStatus(v.Status),
		Channel:   AgentVersionChannel(v.Channel),
		Source:    AgentVersionSource(v.Source),
		CreatedAt: v.CreatedAt,
	}
	if v.StatusReason != nil {
		out.StatusReason = v.StatusReason
	}
	// Which manifest schema the snapshot follows (DEV-088): clients read a
	// v1 snapshot through the kind mapping and a v2 one by its modes.
	var snap struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if json.Unmarshal(v.Manifest, &snap) == nil {
		switch strings.SplitN(snap.SchemaVersion, ".", 2)[0] {
		case "1":
			major := N1
			out.ManifestSchemaVersion = &major
		case "2":
			major := N2
			out.ManifestSchemaVersion = &major
		}
	}
	if v.CommitSha != "" {
		out.CommitSha = &v.CommitSha
	}
	if v.ArchiveDigest != nil {
		out.ArchiveDigest = v.ArchiveDigest
	}
	if v.ArchiveSize != nil {
		out.ArchiveSize = v.ArchiveSize
	}
	if v.PublishedAt != nil {
		out.PublishedAt = v.PublishedAt
	}
	if v.YankedAt != nil {
		out.YankedAt = v.YankedAt
	}
	if v.YankReason != nil {
		out.YankReason = v.YankReason
	}
	if len(v.Capabilities) > 0 {
		var caps map[string]interface{}
		if err := json.Unmarshal(v.Capabilities, &caps); err == nil {
			out.Capabilities = &caps
		}
	}
	return out
}

// writeSubmitError maps registry submission errors onto problems.
func (s *Server) writeSubmitError(w http.ResponseWriter, r *http.Request, err error) {
	var vErr *registry.ErrValidation
	var refused *registry.ErrAdmissionRefused
	switch {
	case errors.As(err, &vErr):
		fields := make([]FieldError, 0, len(vErr.Issues))
		for _, iss := range vErr.Issues {
			fields = append(fields, FieldError{Field: "manifest", Message: sentence(iss.Error())})
		}
		problemValidation(w, r, "The registry rejected the submission. Each field error says what to fix.", fields...)
	case errors.Is(err, registry.ErrTwoFactorRequired):
		problemForbidden(w, r, "Enable two-factor authentication before publishing to a public namespace.")
	case errors.Is(err, registry.ErrScanNotScheduled):
		// The version row exists and is in `scanning`; the watchdog will route
		// it to review. Say so rather than implying nothing happened.
		s.log.Error("submit version: scan not scheduled", "err", err)
		writeProblem(w, r, http.StatusServiceUnavailable, "scan-not-scheduled",
			"Scan not started",
			"The registry recorded this version but could not schedule its scan. A watchdog routes it to review.")
	case errors.As(err, &refused):
		problemAdmissionRefused(w, r, refused.Refusal)
	case errors.Is(err, registry.ErrAdmissionUnavailable):
		s.log.Error("submit version: admission unavailable", "err", err)
		writeProblem(w, r, http.StatusServiceUnavailable, "admission-unavailable",
			"Submission not admitted",
			"The registry could not check whether this account may submit. Nothing was recorded; retry shortly.")
	case errors.Is(err, registry.ErrDenied):
		problemValidation(w, r, sentence(err.Error()))
	case errors.Is(err, auth.ErrUnauthorized):
		problemUnauthorized(w, r, "This request carried no valid session or token. Sign in and retry.")
	case errors.Is(err, auth.ErrForbidden):
		problemForbidden(w, r, "This credential does not carry the role or scope this action needs.")
	default:
		s.log.Error("submit version", "err", err)
		problemInternal(w, r)
	}
}

// SubmitVersion implements POST /agents/{ns}/{name}/versions (§6.5, §7).
func (s *Server) SubmitVersion(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	ik, handled := s.beginIdempotent(w, r, "POST /agents/{ns}/{name}/versions")
	if handled {
		return
	}
	defer ik.abandon(r)
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentPublish)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	if !p.EmailVerified {
		problemForbidden(w, r, "Verify this account's email address before publishing.")
		return
	}
	if a.QuarantineState == "blocked" {
		problemForbidden(w, r, "Trust & safety blocked this BriefAgent, so it cannot publish.")
		return
	}

	ct := r.Header.Get("Content-Type")
	var (
		version registry.Version
		err     error
	)
	switch {
	case strings.HasPrefix(ct, "application/json"):
		var req SubmitVersionJSONRequestBody
		if !readJSON(w, r, &req) {
			return
		}
		if req.Tag == "" {
			problemValidation(w, r, "Name the git tag to submit.")
			return
		}
		version, err = s.reg.SubmitTag(r.Context(), p, a, req.Tag, auditEvent(r, audit.ActionVersionSubmit))

	case strings.HasPrefix(ct, "multipart/form-data"):
		version, err = s.submitUpload(w, r, p, a)
		if version.ID == [16]byte{} && err == nil {
			return // problem already written
		}

	default:
		problemBadRequest(w, r, "Send either application/json {tag} or a multipart/form-data archive upload.")
		return
	}
	if err != nil {
		s.writeSubmitError(w, r, err)
		return
	}
	out := versionToAPI(version)
	ik.complete(r, http.StatusAccepted, out)
	writeJSON(w, http.StatusAccepted, out)
}

// submitUpload handles the cli-upload source: unpack, then hand the
// workspace to the registry which re-validates and re-packs (§6.5).
func (s *Server) submitUpload(w http.ResponseWriter, r *http.Request, p *auth.Principal, a registry.Agent) (registry.Version, error) {
	// Cap the BODY, not just the in-memory part. ParseMultipartForm's argument
	// is only the memory budget: everything past it spools to disk, so an
	// unbounded body let an authenticated client fill the server's temp
	// filesystem before a single byte was validated.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(multipartMemoryBytes); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeProblem(w, r, http.StatusRequestEntityTooLarge, "upload-too-large",
				"Upload too large",
				fmt.Sprintf("Release archives are capped at %d bytes.", maxUploadBytes))
			return registry.Version{}, nil
		}
		problemValidation(w, r, "Could not read the multipart upload: "+err.Error())
		return registry.Version{}, nil
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	file, hdr, err := r.FormFile("archive")
	if err != nil {
		problemValidation(w, r, "Include the archive part in the upload.")
		return registry.Version{}, nil
	}
	defer func() { _ = file.Close() }()

	ws, err := os.MkdirTemp("", "agentry-upload-*")
	if err != nil {
		return registry.Version{}, err
	}
	defer func() { _ = os.RemoveAll(ws) }()

	// One hardened extractor for untrusted archives (§8.2). registry's older
	// unpacker checked traversal and sizes but not file COUNT, not the
	// compression ratio, and did not bound decoder memory — so an upload was
	// unpacked under weaker rules than the scanner would later apply to the
	// very same bytes.
	if err := scan.Extract(file, ws, hdr.Size, scan.DefaultLimits()); err != nil {
		problemValidation(w, r, "The extractor rejected this archive: "+err.Error())
		return registry.Version{}, nil
	}
	// The server rebuilds the archive from this workspace and its own digest
	// is authoritative; a claimed digest that disagrees fails validation
	// inside SubmitVersion (§6.5 — never trust client packing).
	return s.reg.SubmitVersion(r.Context(), p, a, registry.SubmitInput{
		Source:        "cli-upload",
		Workspace:     ws,
		ClaimedDigest: r.FormValue("digest"),
	}, auditEvent(r, audit.ActionVersionSubmit))
}

// ListVersions implements GET /agents/{ns}/{name}/versions.
func (s *Server) ListVersions(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return
	}
	rows, err := s.q().ListVersions(r.Context(), a.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]AgentVersion, 0, len(rows))
	for _, v := range rows {
		out = append(out, versionToAPI(v))
	}
	writeJSON(w, http.StatusOK, out)
}

// versionOrNotFound resolves ns/name/version after agent authz.
func (s *Server) versionOrNotFound(w http.ResponseWriter, r *http.Request, ns, name, version string, act auth.Action) (registry.Agent, registry.Version, bool) {
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, act)
	if !ok {
		return registry.Agent{}, registry.Version{}, false
	}
	v, err := s.q().GetVersion(r.Context(), storegen.GetVersionParams{AgentID: a.ID, Version: version})
	if err != nil {
		problemNotFound(w, r)
		return registry.Agent{}, registry.Version{}, false
	}
	return a, v, true
}

// GetVersionInfo implements GET .../versions/{version}.
func (s *Server) GetVersionInfo(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	_, v, ok := s.versionOrNotFound(w, r, ns, name, version, auth.ActAgentRead)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, versionToAPI(v))
}

// GetVersionManifest implements GET .../versions/{version}/manifest.
func (s *Server) GetVersionManifest(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	_, v, ok := s.versionOrNotFound(w, r, ns, name, version, auth.ActAgentRead)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(v.Manifest)
}

// YankVersion implements POST .../versions/{version}/yank (§5.5).
func (s *Server) YankVersion(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	a, v, ok := s.versionOrNotFound(w, r, ns, name, version, auth.ActAgentPublish)
	if !ok {
		return
	}
	var req YankVersionJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > 500 {
		problemValidation(w, r, "The yank reason must be 1-500 characters.")
		return
	}
	e := auditEvent(r, audit.ActionVersionYank)
	if a.NamespaceKind == "org" {
		e.OrgID = a.NamespaceID
	}
	if err := s.reg.Transition(r.Context(), v.ID, registry.StatusYanked, reason, e); err != nil {
		if errors.Is(err, registry.ErrBadTransition) {
			problemConflict(w, r, "Only a published or quarantined version can be yanked.")
			return
		}
		s.log.Error("yank", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DownloadVersion implements GET .../versions/{version}/download (§9.4).
// Self-host streams the archive directly; SaaS will 302 to the CDN (M7).
func (s *Server) DownloadVersion(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	a, v, ok := s.versionOrNotFound(w, r, ns, name, version, auth.ActAgentRead)
	if !ok {
		return
	}
	// Agent-level block short-circuits every version (§7 blocked: downloads
	// return 410). Blocking walks the versions too; this catches the case
	// where a scan finishes and publishes a version after the block landed.
	if a.QuarantineState == "blocked" {
		writeProblem(w, r, http.StatusGone, "blocked", "Blocked BriefAgent",
			"Trust & safety blocked this BriefAgent. Downloads stay refused until platform staff reinstate it.")
		return
	}
	switch registry.Status(v.Status) {
	case registry.StatusPublished:
	case registry.StatusYanked:
		w.Header().Set("X-Agentry-Yanked", "true")
	case registry.StatusBlocked:
		writeProblem(w, r, http.StatusGone, "blocked", "Blocked version",
			"Trust & safety blocked this version. Downloads stay refused until platform staff reinstate it and a reviewer decides.")
		return
	case registry.StatusQuarantined:
		problemConflict(w, r, "This version is quarantined for review. Downloads resume once a reviewer decides.")
		return
	default:
		problemNotFound(w, r)
		return
	}
	if v.ArchiveKey == nil || v.ArchiveDigest == nil {
		problemInternal(w, r)
		return
	}

	blob, err := s.blobs.Get(r.Context(), *v.ArchiveKey)
	if err != nil {
		s.log.Error("download", "err", err)
		problemInternal(w, r)
		return
	}
	defer func() { _ = blob.Close() }()

	if err := s.q().BumpDownloadStat(r.Context(), storegen.BumpDownloadStatParams{AgentID: a.ID, VersionID: v.ID}); err != nil {
		s.log.Warn("install count", "err", err)
	}

	w.Header().Set("Content-Type", "application/zstd")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s_%s.tar.zst", ns, name, version))
	w.Header().Set("ETag", `"`+*v.ArchiveDigest+`"`)
	if a.Visibility == "public" {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	_, _ = io.Copy(w, blob)
}

// ResolveRef implements GET /resolve (§9.4 step 1).
func (s *Server) ResolveRef(w http.ResponseWriter, r *http.Request, params ResolveRefParams) {
	if !s.requireDB(w, r) {
		return
	}
	ref, err := registry.ParseRef(params.Ref)
	if err != nil {
		problemValidation(w, r, sentence(err.Error()))
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ref.Namespace, ref.Name, auth.ActAgentRead)
	if !ok {
		return
	}
	channel := ref.Channel
	if params.Channel != nil {
		channel = string(*params.Channel)
	}
	res, err := s.reg.ResolveVersion(r.Context(), a, ref.Range, channel)
	if err != nil {
		if errors.Is(err, registry.ErrBlocked) {
			writeProblem(w, r, http.StatusGone, "blocked", "Blocked BriefAgent",
				"Trust & safety blocked this BriefAgent. Downloads stay refused until platform staff reinstate it.")
			return
		}
		if errors.Is(err, registry.ErrNoMatch) {
			problemNotFound(w, r)
			return
		}
		problemValidation(w, r, sentence(err.Error()))
		return
	}
	v := res.Version

	// The install-intent hint keeps CLI stats honest without a download
	// round-trip through the API (§9.4 step 4).
	if r.Header.Get("X-Agentry-Install") == "1" {
		if err := s.q().BumpDownloadStat(r.Context(), storegen.BumpDownloadStatParams{AgentID: a.ID, VersionID: v.ID}); err != nil {
			s.log.Warn("install count", "err", err)
		}
	}

	var manifestDoc map[string]interface{}
	_ = json.Unmarshal(v.Manifest, &manifestDoc)
	digest := ""
	if v.ArchiveDigest != nil {
		digest = *v.ArchiveDigest
	}
	base := strings.TrimSuffix(s.cfg.BaseURL, "/")
	out := ResolveResult{
		Namespace:  ref.Namespace,
		Name:       ref.Name,
		Version:    v.Version,
		Digest:     digest,
		ArchiveUrl: fmt.Sprintf("%s/api/v1/agents/%s/%s/versions/%s/download", base, ref.Namespace, ref.Name, v.Version),
		Manifest:   manifestDoc,
		Yanked:     res.Yanked,
	}
	// §9.4 step 1: point verifiers at the attestation whenever one exists
	// (signing happens exactly once, on publish — §7).
	if _, err := s.q().GetAttestation(r.Context(), v.ID); err == nil {
		u := fmt.Sprintf("%s/api/v1/agents/%s/%s/versions/%s/attestation", base, ref.Namespace, ref.Name, v.Version)
		out.AttestationUrl = &u
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.log.Warn("resolve: attestation lookup", "err", err)
	}
	writeJSON(w, http.StatusOK, out)
}
