package webhook

// Single-endpoint delivery, used by POST /orgs/{org}/webhooks/{id}/ping.
// Emit fans an event out to every subscribed endpoint; a ping is the
// other shape — one endpoint, chosen by the operator, regardless of what that
// endpoint is subscribed to. Everything downstream (envelope, signature,
// SSRF guard, retry ladder) is the same code path as a real event, which is
// what makes the ping a meaningful test.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/queue"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// EventPing is the event type recorded for a test delivery. It is
// deliberately absent from AllEvents: nobody subscribes to a ping, it is sent
// to one endpoint on request.
const EventPing = "ping"

// EmitToEndpoint records and enqueues one delivery to a specific endpoint and
// returns the delivery row.
func (d *Dispatcher) EmitToEndpoint(ctx context.Context, endpointID uuid.UUID, eventType string, data any) (storegen.WebhookDelivery, error) {
	if d.deps.Store == nil || d.deps.Queue == nil {
		return storegen.WebhookDelivery{}, fmt.Errorf("webhook: delivery not configured")
	}
	dataRaw, err := json.Marshal(data)
	if err != nil {
		return storegen.WebhookDelivery{}, fmt.Errorf("webhook: marshal data: %w", err)
	}
	deliveryID, err := uuid.NewV7()
	if err != nil {
		return storegen.WebhookDelivery{}, err
	}
	payload, err := json.Marshal(wirePayload{
		Event: eventType, ID: deliveryID, CreatedAt: d.deps.Now().UTC(), Data: dataRaw,
	})
	if err != nil {
		return storegen.WebhookDelivery{}, fmt.Errorf("webhook: marshal payload: %w", err)
	}
	row, err := d.deps.Store.Queries().CreateWebhookDelivery(ctx, storegen.CreateWebhookDeliveryParams{
		ID: deliveryID, EndpointID: endpointID, EventType: eventType, Payload: payload,
	})
	if err != nil {
		return storegen.WebhookDelivery{}, fmt.Errorf("webhook: record delivery: %w", err)
	}
	if _, err := d.deps.Queue.Enqueue(ctx, JobDeliver, "core",
		deliverArgs{DeliveryID: deliveryID}, queue.WithMaxAttempts(5)); err != nil {
		return row, fmt.Errorf("webhook: enqueue: %w", err)
	}
	return row, nil
}
