package api

import (
	"net/http"
	"strings"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
	"github.com/PLACEHOLDER_ORG/agentry/internal/webhook"
)

const webhookSecretPrefix = "whsec_"

func webhookToAPI(row storegen.WebhookEndpoint) WebhookEndpoint {
	return WebhookEndpoint{
		Id: row.ID, Url: row.Url, Events: row.Events, Active: row.Active, CreatedAt: row.CreatedAt,
	}
}

// validateWebhookInput checks the URL is https and every event is known (§9.3).
func validateWebhookInput(url string, events []string) *FieldError {
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return &FieldError{Field: "url", Message: "must be an https:// URL (§9.3)"}
	}
	if len(events) == 0 {
		return &FieldError{Field: "events", Message: "at least one event required"}
	}
	for _, e := range events {
		if !webhook.ValidEvent(e) {
			return &FieldError{Field: "events", Message: "unknown event " + e}
		}
	}
	return nil
}

// ListWebhooks implements GET /orgs/{org}/webhooks (admin+, §9.3).
func (s *Server) ListWebhooks(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	rows, err := s.q().ListWebhookEndpoints(r.Context(), orgRow.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]WebhookEndpoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, webhookToAPI(row))
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateWebhook implements POST /orgs/{org}/webhooks (admin+, §9.3).
func (s *Server) CreateWebhook(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	var req WebhookInput
	if !readJSON(w, r, &req) {
		return
	}
	if fe := validateWebhookInput(req.Url, req.Events); fe != nil {
		problemValidation(w, r, "webhook rejected", *fe)
		return
	}
	secret, err := auth.NewToken(webhookSecretPrefix)
	if err != nil {
		problemInternal(w, r)
		return
	}
	sealed, err := s.sealer.Seal([]byte(secret))
	if err != nil {
		problemInternal(w, r)
		return
	}
	id := newUUID()
	var created storegen.WebhookEndpoint
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		row, err := q.CreateWebhookEndpoint(r.Context(), storegen.CreateWebhookEndpointParams{
			ID: id, OrgID: orgRow.ID, Url: req.Url, SecretEnc: sealed, Events: req.Events, Active: true,
		})
		if err != nil {
			return err
		}
		created = row
		e := auditEvent(r, audit.ActionWebhookCreate)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "webhook", id
		e.Detail = map[string]any{"url": req.Url, "events": req.Events}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("create webhook", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, WebhookEndpointCreated{
		Id: created.ID, Url: created.Url, Events: created.Events,
		Active: created.Active, CreatedAt: created.CreatedAt, Secret: secret,
	})
}

// GetWebhook implements GET /orgs/{org}/webhooks/{id} (admin+, §9.3).
func (s *Server) GetWebhook(w http.ResponseWriter, r *http.Request, org OrgHandle, id WebhookID) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	row, err := s.q().GetWebhookEndpoint(r.Context(), storegen.GetWebhookEndpointParams{ID: id, OrgID: orgRow.ID})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, webhookToAPI(row))
}

// UpdateWebhook implements PATCH /orgs/{org}/webhooks/{id} (admin+, §9.3).
func (s *Server) UpdateWebhook(w http.ResponseWriter, r *http.Request, org OrgHandle, id WebhookID) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	existing, err := s.q().GetWebhookEndpoint(r.Context(), storegen.GetWebhookEndpointParams{ID: id, OrgID: orgRow.ID})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	var req UpdateWebhookJSONBody
	if !readJSON(w, r, &req) {
		return
	}
	url := existing.Url
	if req.Url != nil {
		url = *req.Url
	}
	events := existing.Events
	if req.Events != nil {
		events = *req.Events
	}
	active := existing.Active
	if req.Active != nil {
		active = *req.Active
	}
	if fe := validateWebhookInput(url, events); fe != nil {
		problemValidation(w, r, "webhook rejected", *fe)
		return
	}
	var updated storegen.WebhookEndpoint
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		row, err := q.UpdateWebhookEndpoint(r.Context(), storegen.UpdateWebhookEndpointParams{
			ID: id, OrgID: orgRow.ID, Url: url, Events: events, Active: active,
		})
		if err != nil {
			return err
		}
		updated = row
		e := auditEvent(r, audit.ActionWebhookUpdate)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "webhook", id
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, webhookToAPI(updated))
}

// DeleteWebhook implements DELETE /orgs/{org}/webhooks/{id} (admin+, §9.3).
func (s *Server) DeleteWebhook(w http.ResponseWriter, r *http.Request, org OrgHandle, id WebhookID) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	var n int64
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		rows, err := q.DeleteWebhookEndpoint(r.Context(), storegen.DeleteWebhookEndpointParams{ID: id, OrgID: orgRow.ID})
		if err != nil {
			return err
		}
		n = rows
		if n == 0 {
			return nil
		}
		e := auditEvent(r, audit.ActionWebhookDelete)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "webhook", id
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		problemInternal(w, r)
		return
	}
	if n == 0 {
		problemNotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListWebhookDeliveries implements GET /orgs/{org}/webhooks/{id}/deliveries.
func (s *Server) ListWebhookDeliveries(w http.ResponseWriter, r *http.Request, org OrgHandle, id WebhookID) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgUpdate, orgRow.ID) {
		return
	}
	if _, err := s.q().GetWebhookEndpoint(r.Context(), storegen.GetWebhookEndpointParams{ID: id, OrgID: orgRow.ID}); err != nil {
		problemNotFound(w, r)
		return
	}
	rows, err := s.q().ListWebhookDeliveries(r.Context(), storegen.ListWebhookDeliveriesParams{EndpointID: id, Limit: 50})
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]WebhookDelivery, 0, len(rows))
	for _, d := range rows {
		wd := WebhookDelivery{Id: d.ID, EventType: d.EventType, Attempt: int(d.Attempt), CreatedAt: d.CreatedAt}
		if d.StatusCode != nil {
			sc := int(*d.StatusCode)
			wd.StatusCode = &sc
		}
		if d.Error != nil {
			wd.Error = d.Error
		}
		if d.DeliveredAt != nil {
			wd.DeliveredAt = d.DeliveredAt
		}
		out = append(out, wd)
	}
	writeJSON(w, http.StatusOK, out)
}
