package api

import (
	"fmt"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/webhook"
)

const webhookSecretPrefix = "whsec_"

const (
	// The endpoint cap comes from the entitlements resolver.
	deliveryDefaultLimit = 50
	deliveryMaxLimit     = 100
)

func webhookToAPI(row storegen.WebhookEndpoint) WebhookEndpoint {
	return WebhookEndpoint{
		Id: row.ID, Url: row.Url, Events: row.Events, Active: row.Active, CreatedAt: row.CreatedAt,
	}
}

// validateWebhookInput checks the URL is a deliverable https address and
// every event is known.
func validateWebhookInput(url string, events []string) *FieldError {
	if fe := validateWebhookURL(url); fe != nil {
		return fe
	}
	if len(events) == 0 {
		return &FieldError{Field: "events", Message: "Must list at least one event."}
	}
	for _, e := range events {
		if !webhook.ValidEvent(e) {
			return &FieldError{Field: "events", Message: "Lists an unknown event: " + e + "."}
		}
	}
	return nil
}

// validateWebhookURL refuses an address the delivery client could not send
// to: not https, not parsable, with no host, or with a port outside 1-65535.
// No message repeats the address, since its path, query and user information
// routinely carry the endpoint's secret.
func validateWebhookURL(raw string) *FieldError {
	if !strings.HasPrefix(strings.ToLower(raw), "https://") {
		return &FieldError{Field: "url", Message: "Must be an https:// URL."}
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		return &FieldError{Field: "url", Message: "Is not a valid URL. Check the host and the port."}
	}
	if u.Hostname() == "" {
		return &FieldError{Field: "url", Message: "Must name a host after https://."}
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return &FieldError{Field: "url", Message: "Must have a port from 1 to 65535."}
		}
	}
	return nil
}

// ListWebhooks implements GET /orgs/{org}/webhooks (admin+).
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

// CreateWebhook implements POST /orgs/{org}/webhooks (admin+).
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
	ik, handled := s.beginIdempotent(w, r, "POST /orgs/{org}/webhooks")
	if handled {
		return
	}
	defer ik.abandon(r)
	var req WebhookInput
	if !readJSON(w, r, &req) {
		return
	}
	if fe := validateWebhookInput(req.Url, req.Events); fe != nil {
		problemValidation(w, r, "The registry rejected the webhook endpoint. Each field error says what to fix.", *fe)
		return
	}
	// Endpoint cap. Checked before minting a secret so a refused request
	// never leaves a usable key in memory or the log.
	lim, err := s.entitlements().Limits(r.Context(), entitlements.ForOrg(orgRow.ID))
	if err != nil {
		problemInternal(w, r)
		return
	}
	existing, err := s.q().CountWebhookEndpoints(r.Context(), orgRow.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	if existing >= lim.WebhookEndpoints {
		problemConflict(w, r, fmt.Sprintf(
			"This organization already has the maximum of %d webhook endpoints. Delete one before adding another.", lim.WebhookEndpoints))
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
		e.Detail = map[string]any{"host": webhook.EndpointHost(req.Url), "events": req.Events}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "create webhook", "err", err)
		problemInternal(w, r)
		return
	}
	out := WebhookEndpointCreated{
		Id: created.ID, Url: created.Url, Events: created.Events,
		Active: created.Active, CreatedAt: created.CreatedAt, Secret: secret,
	}
	// The signing secret is shown exactly once, including on an
	// idempotent replay, which is the whole point: a client that lost the
	// original response gets that response back rather than a second endpoint.
	ik.complete(r, http.StatusCreated, out)
	writeJSON(w, http.StatusCreated, out)
}

// GetWebhook implements GET /orgs/{org}/webhooks/{id} (admin+).
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

// UpdateWebhook implements PATCH /orgs/{org}/webhooks/{id} (admin+).
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
		problemValidation(w, r, "The registry rejected the change. Each field error says what to fix.", *fe)
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

// DeleteWebhook implements DELETE /orgs/{org}/webhooks/{id} (admin+).
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

// PingWebhook implements POST /orgs/{org}/webhooks/{id}/ping. It
// enqueues a real delivery through the ordinary machinery — same HMAC
// signature, same SSRF guard, same retry ladder — so "does my endpoint work"
// is answered by the code that will actually call it, not by a special path
// that might diverge from it.
func (s *Server) PingWebhook(w http.ResponseWriter, r *http.Request, org OrgHandle, id WebhookID) {
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
	ep, err := s.q().GetWebhookEndpoint(r.Context(), storegen.GetWebhookEndpointParams{ID: id, OrgID: orgRow.ID})
	if err != nil {
		problemNotFound(w, r)
		return
	}
	if s.webhooks == nil {
		problemUnavailable(w, r, "Webhook delivery is not configured on this deployment, so the ping was not sent.")
		return
	}
	ik, handled := s.beginIdempotent(w, r, "POST /orgs/{org}/webhooks/{id}/ping")
	if handled {
		return
	}
	defer ik.abandon(r)

	p := principalFrom(r.Context())
	delivery, err := s.webhooks.EmitToEndpoint(r.Context(), ep.ID, webhook.EventPing, map[string]any{
		"org":         orgRow.Handle,
		"endpointId":  ep.ID.String(),
		"requestedBy": p.Handle,
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "webhook ping", "err", err, "endpoint", ep.ID)
		problemInternal(w, r)
		return
	}
	if err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		e := auditEvent(r, audit.ActionWebhookPing)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "webhook", ep.ID
		e.Detail = map[string]any{"deliveryId": delivery.ID.String()}
		return s.auditW.Write(r.Context(), q, e)
	}); err != nil {
		s.log.ErrorContext(r.Context(), "webhook ping audit", "err", err)
	}
	out := deliveryToAPI(delivery)
	ik.complete(r, http.StatusAccepted, out)
	writeJSON(w, http.StatusAccepted, out)
}

// ListWebhookDeliveries implements GET /orgs/{org}/webhooks/{id}/deliveries.
func (s *Server) ListWebhookDeliveries(w http.ResponseWriter, r *http.Request, org OrgHandle, id WebhookID, params ListWebhookDeliveriesParams) {
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
	limit := clampLimit(params.Limit, deliveryDefaultLimit, deliveryMaxLimit)
	before, beforeID, ok := cursorParams(w, r, params.Cursor)
	if !ok {
		return
	}
	rows, err := s.q().ListWebhookDeliveries(r.Context(), storegen.ListWebhookDeliveriesParams{
		EndpointID: id, Limit: int32(limit), BeforeTime: before, BeforeID: beforeID,
	})
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]WebhookDelivery, 0, len(rows))
	for _, d := range rows {
		out = append(out, deliveryToAPI(d))
	}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		setNextLink(w, r, encodeCursor(last.CreatedAt, last.ID))
	}
	writeJSON(w, http.StatusOK, out)
}

func deliveryToAPI(d storegen.WebhookDelivery) WebhookDelivery {
	wd := WebhookDelivery{Id: d.ID, EventType: d.EventType, Attempt: int(d.Attempt), CreatedAt: d.CreatedAt}
	if d.StatusCode != nil {
		sc := int(*d.StatusCode)
		wd.StatusCode = &sc
	}
	wd.Error = d.Error
	wd.DeliveredAt = d.DeliveredAt
	return wd
}
