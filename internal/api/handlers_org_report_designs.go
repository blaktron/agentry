package api

// An organization's house designs: report designs the organization keeps,
// written by its admins and read by its active members, who pick one for a
// run by the organization's handle and the design's name. Membership is
// checked at every call: the chokepoint reads the roles this request
// resolved, active memberships only, so a member who is removed is refused
// the next read, and a caller who is not an active member is answered 404,
// as for another organization's shared knowledge. A design's validation and
// its images are pkg/reportdesign's, as a person's own design's are
// (handlers_user_report_designs.go); what differs is the owner, the name
// rule and that there is no default.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/reportdesign"
)

// ErrOrgReportDesignNameHeld is a create or a replace whose name another of
// the organization's designs holds.
var ErrOrgReportDesignNameHeld = errors.New("report designs: the organization has a design of that name")

// orgReportDesignBody is a house design on the wire: as a person's, with
// the organization in place of the default.
type orgReportDesignBody struct {
	ID             uuid.UUID       `json:"id"`
	Org            string          `json:"org"`
	HasLogo        bool            `json:"hasLogo"`
	HasCoverImage  bool            `json:"hasCoverImage"`
	HasCustomCover bool            `json:"hasCustomCover"`
	CreatedAt      time.Time       `json:"createdAt"`
	UpdatedAt      time.Time       `json:"updatedAt"`
	Design         json.RawMessage `json:"design"`
}

type orgReportDesignSummary struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	BasedOn        string    `json:"basedOn"`
	Version        int       `json:"version"`
	HasLogo        bool      `json:"hasLogo"`
	HasCoverImage  bool      `json:"hasCoverImage"`
	HasCustomCover bool      `json:"hasCustomCover"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type orgReportDesignList struct {
	Org     string                   `json:"org"`
	Designs []orgReportDesignSummary `json:"designs"`
}

// orgReportDesigns resolves {org} for a house-design route and authorizes
// act there: a caller who is signed in but not an active member of the
// organization is 404 before the chokepoint, so the routes say nothing of
// what an organization keeps to anyone outside it.
func (s *Server) orgReportDesigns(w http.ResponseWriter, r *http.Request, org string, act auth.Action) (storegen.GetOrgByHandleRow, bool) {
	if !s.requireDB(w, r) {
		return storegen.GetOrgByHandleRow{}, false
	}
	row, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return row, false
	}
	if p := principalFrom(r.Context()); !p.Anonymous && p.Role(row.ID) == auth.RoleNone {
		problemNotFound(w, r)
		return row, false
	}
	if !s.authorize(w, r, act, row.ID) {
		return row, false
	}
	return row, true
}

// designHead is what a document says of itself, for a list and an audit
// detail: read from the JSON, so a stored document that no longer parses
// is still named.
type designHead struct {
	Name    string `json:"name"`
	BasedOn string `json:"basedOn"`
	Version int    `json:"version"`
}

func headOf(document []byte) designHead {
	var h designHead
	_ = json.Unmarshal(document, &h)
	return h
}

// orgReportDesignAudit records act on one of the organization's designs in
// the organization's audit log, in the transaction of the change it
// records. The detail names the design and, for an image, which one.
func (s *Server) orgReportDesignAudit(ctx context.Context, r *http.Request, q *storegen.Queries, orgID uuid.UUID, act audit.Action, row storegen.OrgReportDesign, image string) error {
	e := auditEvent(r, act)
	e.OrgID = orgID
	e.TargetKind, e.TargetID = "report_design", row.ID
	e.Detail = map[string]any{"name": headOf(row.Document).Name}
	if image != "" {
		e.Detail["image"] = image
	}
	return s.auditW.Write(ctx, q, e)
}

// ListOrgReportDesigns implements GET /orgs/{org}/report-designs.
func (s *Server) ListOrgReportDesigns(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	row, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsRead)
	if !ok {
		return
	}
	rows, err := s.q().ListOrgReportDesigns(r.Context(), row.ID)
	if err != nil {
		s.log.ErrorContext(r.Context(), "report designs: list", "org", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	out := orgReportDesignList{Org: org, Designs: make([]orgReportDesignSummary, 0, len(rows))}
	for _, d := range rows {
		head := headOf(d.Document)
		out.Designs = append(out.Designs, orgReportDesignSummary{
			ID: d.ID, Name: head.Name, BasedOn: head.BasedOn, Version: head.Version,
			HasLogo: d.HasLogo, HasCoverImage: d.HasCoverImage, HasCustomCover: d.HasCustomCover,
			CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateOrgReportDesign implements POST /orgs/{org}/report-designs.
func (s *Server) CreateOrgReportDesign(w http.ResponseWriter, r *http.Request, org OrgHandle, params CreateOrgReportDesignParams) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsWrite)
	if !ok {
		return
	}
	withAssets, ok := includeAssets(w, r, params.Include)
	if !ok {
		return
	}
	var req struct {
		Design json.RawMessage `json:"design"`
	}
	if !readJSONUpTo(w, r, &req, int64(reportdesign.MaxDocumentWithAssets)+reportDesignRequestSlack) {
		return
	}
	d, ok := s.readDesign(w, r, req.Design)
	if !ok {
		return
	}
	assets, err := assetsOf(d)
	if err != nil {
		problemDesign(w, r, err)
		return
	}
	var row storegen.OrgReportDesign
	err = s.st.WithPgxTx(r.Context(), func(tx pgx.Tx, tq *storegen.Queries) error {
		// One create at a time per organization, so the bound holds under
		// two at once.
		if err := tq.LockOrg(r.Context(), orgRow.ID); err != nil {
			return err
		}
		n, err := tq.CountOrgReportDesigns(r.Context(), orgRow.ID)
		if err != nil {
			return err
		}
		if n >= reportdesign.MaxLibrary {
			return ErrReportDesignsFull
		}
		row, err = tq.CreateOrgReportDesign(r.Context(), storegen.CreateOrgReportDesignParams{
			OrgID: orgRow.ID, Document: d.WithoutAssets().Canonical(),
			Logo: assets.logo, CoverImage: assets.coverImage, CoverImageFormat: assets.coverImageFormat, CustomCover: assets.customCover,
		})
		if isUniqueViolation(err) {
			return ErrOrgReportDesignNameHeld
		}
		if err != nil {
			return err
		}
		return s.orgReportDesignAudit(r.Context(), r, tq, orgRow.ID, audit.ActionOrgReportDesignCreate, row, "")
	})
	if s.orgReportDesignProblem(w, r, err, orgRow.ID, "create") {
		return
	}
	s.answerOrgReportDesign(w, r, http.StatusCreated, org, row, withAssets)
}

// orgReportDesignProblem answers a write's refusal and reports whether it
// did: the bound and the name rule as 409, no row as 404, the rest as 500.
func (s *Server) orgReportDesignProblem(w http.ResponseWriter, r *http.Request, err error, orgID uuid.UUID, what string) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrReportDesignsFull):
		problemConflict(w, r, "The organization's library holds ten designs. Remove one to add another.")
	case errors.Is(err, ErrOrgReportDesignNameHeld):
		problemConflict(w, r, "The organization has a design of that name. A run names a house design, so each name is one design's.")
	case errors.Is(err, pgx.ErrNoRows):
		problemNotFound(w, r)
	default:
		s.log.ErrorContext(r.Context(), "report designs: "+what, "org", orgID, "err", err)
		problemInternal(w, r)
	}
	return true
}

// GetOrgReportDesign implements GET /orgs/{org}/report-designs/{designId}.
func (s *Server) GetOrgReportDesign(w http.ResponseWriter, r *http.Request, org OrgHandle, designId ReportDesignId, params GetOrgReportDesignParams) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsRead)
	if !ok {
		return
	}
	withAssets, ok := includeAssets(w, r, params.Include)
	if !ok {
		return
	}
	row, err := s.q().GetOrgReportDesign(r.Context(), storegen.GetOrgReportDesignParams{OrgID: orgRow.ID, ID: designId})
	if s.orgReportDesignProblem(w, r, err, orgRow.ID, "read") {
		return
	}
	s.answerOrgReportDesign(w, r, http.StatusOK, org, row, withAssets)
}

// UpdateOrgReportDesign implements PUT /orgs/{org}/report-designs/{designId}.
func (s *Server) UpdateOrgReportDesign(w http.ResponseWriter, r *http.Request, org OrgHandle, designId ReportDesignId, params UpdateOrgReportDesignParams) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsWrite)
	if !ok {
		return
	}
	withAssets, ok := includeAssets(w, r, params.Include)
	if !ok {
		return
	}
	var req struct {
		Design json.RawMessage `json:"design"`
	}
	if !readJSONUpTo(w, r, &req, int64(reportdesign.MaxDocumentWithAssets)+reportDesignRequestSlack) {
		return
	}
	d, ok := s.readDesign(w, r, req.Design)
	if !ok {
		return
	}
	assets, err := assetsOf(d)
	if err != nil {
		problemDesign(w, r, err)
		return
	}
	var row storegen.OrgReportDesign
	err = s.st.WithPgxTx(r.Context(), func(tx pgx.Tx, tq *storegen.Queries) error {
		var err error
		row, err = tq.UpdateOrgReportDesignDocument(r.Context(), storegen.UpdateOrgReportDesignDocumentParams{
			OrgID: orgRow.ID, ID: designId, Document: d.WithoutAssets().Canonical(),
		})
		if isUniqueViolation(err) {
			return ErrOrgReportDesignNameHeld
		}
		if err != nil {
			return err
		}
		if assets.logo != nil {
			if row, err = tq.SetOrgReportDesignLogo(r.Context(), storegen.SetOrgReportDesignLogoParams{OrgID: orgRow.ID, ID: designId, Logo: assets.logo}); err != nil {
				return err
			}
		}
		if assets.coverImage != nil {
			if row, err = tq.SetOrgReportDesignCoverImage(r.Context(), storegen.SetOrgReportDesignCoverImageParams{
				OrgID: orgRow.ID, ID: designId, CoverImage: assets.coverImage, CoverImageFormat: assets.coverImageFormat,
			}); err != nil {
				return err
			}
		}
		if assets.customCover != nil {
			if row, err = tq.SetOrgReportDesignCustomCover(r.Context(), storegen.SetOrgReportDesignCustomCoverParams{OrgID: orgRow.ID, ID: designId, CustomCover: assets.customCover}); err != nil {
				return err
			}
		}
		return s.orgReportDesignAudit(r.Context(), r, tq, orgRow.ID, audit.ActionOrgReportDesignUpdate, row, "")
	})
	if s.orgReportDesignProblem(w, r, err, orgRow.ID, "update") {
		return
	}
	s.answerOrgReportDesign(w, r, http.StatusOK, org, row, withAssets)
}

// DeleteOrgReportDesign implements DELETE /orgs/{org}/report-designs/{designId}.
func (s *Server) DeleteOrgReportDesign(w http.ResponseWriter, r *http.Request, org OrgHandle, designId ReportDesignId) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsWrite)
	if !ok {
		return
	}
	err := s.st.WithPgxTx(r.Context(), func(tx pgx.Tx, tq *storegen.Queries) error {
		row, err := tq.GetOrgReportDesign(r.Context(), storegen.GetOrgReportDesignParams{OrgID: orgRow.ID, ID: designId})
		if err != nil {
			return err
		}
		if _, err := tq.DeleteOrgReportDesign(r.Context(), storegen.DeleteOrgReportDesignParams{OrgID: orgRow.ID, ID: designId}); err != nil {
			return err
		}
		return s.orgReportDesignAudit(r.Context(), r, tq, orgRow.ID, audit.ActionOrgReportDesignDelete, row, "")
	})
	if s.orgReportDesignProblem(w, r, err, orgRow.ID, "delete") {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// changeOrgReportDesignImage applies one image change to one of the
// organization's designs and records it, in one transaction; what is the
// image for the audit detail and the log.
func (s *Server) changeOrgReportDesignImage(w http.ResponseWriter, r *http.Request, org OrgHandle, orgID uuid.UUID, what string,
	change func(ctx context.Context, tq *storegen.Queries) (storegen.OrgReportDesign, error)) {
	var row storegen.OrgReportDesign
	err := s.st.WithPgxTx(r.Context(), func(tx pgx.Tx, tq *storegen.Queries) error {
		var err error
		if row, err = change(r.Context(), tq); err != nil {
			return err
		}
		return s.orgReportDesignAudit(r.Context(), r, tq, orgID, audit.ActionOrgReportDesignUpdate, row, what)
	})
	if s.orgReportDesignProblem(w, r, err, orgID, what) {
		return
	}
	s.answerOrgReportDesign(w, r, http.StatusOK, org, row, true)
}

// PutOrgReportDesignLogo implements PUT /orgs/{org}/report-designs/{designId}/logo,
// as a person's own logo route reads and keeps the image.
func (s *Server) PutOrgReportDesignLogo(w http.ResponseWriter, r *http.Request, org OrgHandle, designId ReportDesignId) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsWrite)
	if !ok {
		return
	}
	upload, ok := s.readImageUpload(w, r, reportdesign.MaxLogoUploadBytes, "A logo is at most 512 KB.")
	if !ok {
		return
	}
	logo, err := reportdesign.NormalizeLogo(upload)
	if err != nil {
		s.refuseImage(w, r, err, "logo")
		return
	}
	png, err := logo.Decode()
	if err != nil {
		s.log.ErrorContext(r.Context(), "report logo: encode", "err", err)
		problemInternal(w, r)
		return
	}
	s.changeOrgReportDesignImage(w, r, org, orgRow.ID, "logo", func(ctx context.Context, tq *storegen.Queries) (storegen.OrgReportDesign, error) {
		return tq.SetOrgReportDesignLogo(ctx, storegen.SetOrgReportDesignLogoParams{OrgID: orgRow.ID, ID: designId, Logo: png})
	})
}

// DeleteOrgReportDesignLogo implements DELETE /orgs/{org}/report-designs/{designId}/logo.
func (s *Server) DeleteOrgReportDesignLogo(w http.ResponseWriter, r *http.Request, org OrgHandle, designId ReportDesignId) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsWrite)
	if !ok {
		return
	}
	s.changeOrgReportDesignImage(w, r, org, orgRow.ID, "logo", func(ctx context.Context, tq *storegen.Queries) (storegen.OrgReportDesign, error) {
		return tq.ClearOrgReportDesignLogo(ctx, storegen.ClearOrgReportDesignLogoParams{OrgID: orgRow.ID, ID: designId})
	})
}

// PutOrgReportDesignCoverImage implements PUT
// /orgs/{org}/report-designs/{designId}/cover-image.
func (s *Server) PutOrgReportDesignCoverImage(w http.ResponseWriter, r *http.Request, org OrgHandle, designId ReportDesignId) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsWrite)
	if !ok {
		return
	}
	upload, ok := s.readImageUpload(w, r, reportdesign.MaxCoverImageUploadBytes, "A cover image is at most 2 MB.")
	if !ok {
		return
	}
	img, err := reportdesign.NormalizeCoverImage(upload)
	if err != nil {
		s.refuseImage(w, r, err, "cover image")
		return
	}
	data, format, err := img.Decode()
	if err != nil {
		s.log.ErrorContext(r.Context(), "report cover image: encode", "err", err)
		problemInternal(w, r)
		return
	}
	s.changeOrgReportDesignImage(w, r, org, orgRow.ID, "cover image", func(ctx context.Context, tq *storegen.Queries) (storegen.OrgReportDesign, error) {
		return tq.SetOrgReportDesignCoverImage(ctx, storegen.SetOrgReportDesignCoverImageParams{
			OrgID: orgRow.ID, ID: designId, CoverImage: data, CoverImageFormat: &format,
		})
	})
}

// DeleteOrgReportDesignCoverImage implements DELETE
// /orgs/{org}/report-designs/{designId}/cover-image.
func (s *Server) DeleteOrgReportDesignCoverImage(w http.ResponseWriter, r *http.Request, org OrgHandle, designId ReportDesignId) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsWrite)
	if !ok {
		return
	}
	s.changeOrgReportDesignImage(w, r, org, orgRow.ID, "cover image", func(ctx context.Context, tq *storegen.Queries) (storegen.OrgReportDesign, error) {
		return tq.ClearOrgReportDesignCoverImage(ctx, storegen.ClearOrgReportDesignCoverImageParams{OrgID: orgRow.ID, ID: designId})
	})
}

// PutOrgReportDesignCustomCover implements PUT
// /orgs/{org}/report-designs/{designId}/custom-cover.
func (s *Server) PutOrgReportDesignCustomCover(w http.ResponseWriter, r *http.Request, org OrgHandle, designId ReportDesignId) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsWrite)
	if !ok {
		return
	}
	var cc reportdesign.CustomCover
	if !readJSONUpTo(w, r, &cc, int64(reportdesign.MaxDocumentWithAssets)) {
		return
	}
	if err := cc.Validate(); err != nil {
		s.refuseCustomCover(w, r, err)
		return
	}
	stored, err := normalizedCustomCover(cc)
	if err != nil {
		s.refuseCustomCover(w, r, err)
		return
	}
	s.changeOrgReportDesignImage(w, r, org, orgRow.ID, "custom cover", func(ctx context.Context, tq *storegen.Queries) (storegen.OrgReportDesign, error) {
		return tq.SetOrgReportDesignCustomCover(ctx, storegen.SetOrgReportDesignCustomCoverParams{OrgID: orgRow.ID, ID: designId, CustomCover: stored})
	})
}

// DeleteOrgReportDesignCustomCover implements DELETE
// /orgs/{org}/report-designs/{designId}/custom-cover.
func (s *Server) DeleteOrgReportDesignCustomCover(w http.ResponseWriter, r *http.Request, org OrgHandle, designId ReportDesignId) {
	orgRow, ok := s.orgReportDesigns(w, r, org, auth.ActOrgReportDesignsWrite)
	if !ok {
		return
	}
	s.changeOrgReportDesignImage(w, r, org, orgRow.ID, "custom cover", func(ctx context.Context, tq *storegen.Queries) (storegen.OrgReportDesign, error) {
		return tq.ClearOrgReportDesignCustomCover(ctx, storegen.ClearOrgReportDesignCustomCoverParams{OrgID: orgRow.ID, ID: designId})
	})
}

// answerOrgReportDesign answers a house design as the API's record, with
// its images when asked.
func (s *Server) answerOrgReportDesign(w http.ResponseWriter, r *http.Request, status int, org string, row storegen.OrgReportDesign, withAssets bool) {
	rec, err := s.reportDesignOf(r.Context(), orgDesignRow(row))
	if err != nil {
		s.log.ErrorContext(r.Context(), "report designs: read", "org", row.OrgID, "design", row.ID, "err", err)
		problemInternal(w, r)
		return
	}
	d := rec.Design
	if !withAssets {
		d = d.WithoutAssets()
	}
	writeJSON(w, status, orgReportDesignBody{
		ID: row.ID, Org: org,
		HasLogo: row.Logo != nil, HasCoverImage: row.CoverImage != nil, HasCustomCover: row.CustomCover != nil,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		Design: d.Canonical(),
	})
}

// ReportDesignForMember is one of an organization's house designs, by the
// organization's handle and the design's name, with its images, as a
// member's run reads it: nil when the organization is not one a run can
// read (unknown, or erased), when the person is not an active member of
// it, or when it has no design of that name. Membership is read here, at
// the call, so a former member's run is refused the design whatever it
// was handed earlier. It is the read behind the extension seam.
func (s *Server) ReportDesignForMember(ctx context.Context, user uuid.UUID, org, name string) (*ReportDesignEntry, error) {
	orgRow, err := s.q().GetOrgByHandle(ctx, org)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if orgRow.State != registry.OrgStateActive && orgRow.State != registry.OrgStateDecommissioning {
		return nil, nil
	}
	m, err := s.q().GetMembership(ctx, storegen.GetMembershipParams{OrgID: orgRow.ID, UserID: user})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if m.State != registry.StateActive {
		return nil, nil
	}
	row, err := s.q().GetOrgReportDesignByName(ctx, storegen.GetOrgReportDesignByNameParams{OrgID: orgRow.ID, Name: name})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rec, err := s.reportDesignRecord(ctx, orgDesignRow(row))
	if err != nil || rec == nil {
		return rec, err
	}
	rec.Org = org
	return rec, nil
}
