package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	"github.com/PLACEHOLDER_ORG/agentry/internal/queue"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// JobDeliver is the queue job kind for one webhook delivery attempt.
const JobDeliver = "webhook.deliver"

// Event types (§9.3). The catalog is closed; endpoints subscribe by name.
const (
	EventAgentCreated       = "agent.created"
	EventVersionSubmitted   = "version.submitted"
	EventVersionPublished   = "version.published"
	EventVersionRejected    = "version.rejected"
	EventVersionNeedsReview = "version.needs_review"
	EventVersionYanked      = "version.yanked"
	EventAgentQuarantined   = "agent.quarantined"
	EventAgentReinstated    = "agent.reinstated"
	EventAdvisoryPublished  = "advisory.published"
	EventScanCompleted      = "scan.completed"
	EventMemberAdded        = "member.added"
	EventMemberRemoved      = "member.removed"
	EventPolicyUpdated      = "policy.updated"
)

// AllEvents lists the subscribable event types (validation, docs).
func AllEvents() []string {
	return []string{
		EventAgentCreated, EventVersionSubmitted, EventVersionPublished,
		EventVersionRejected, EventVersionNeedsReview, EventVersionYanked,
		EventAgentQuarantined, EventAgentReinstated, EventAdvisoryPublished,
		EventScanCompleted, EventMemberAdded, EventMemberRemoved, EventPolicyUpdated,
	}
}

// ValidEvent reports whether e is a known event type.
func ValidEvent(e string) bool {
	for _, v := range AllEvents() {
		if v == e {
			return true
		}
	}
	return false
}

// Deps are the dispatcher's collaborators.
type Deps struct {
	Store  *store.Store
	Sealer *auth.Sealer
	Queue  queue.Client
	Log    *slog.Logger
	// Client is the guarded delivery client; nil defaults to the strict
	// production guard (NewHTTPClient(Guard{}, nil)).
	Client *http.Client
	// Now is the delivery clock; nil defaults to time.Now.
	Now func() time.Time
}

// Dispatcher records and delivers webhook events for an org.
type Dispatcher struct {
	deps Deps
}

// NewDispatcher builds a dispatcher, filling in production defaults.
func NewDispatcher(deps Deps) *Dispatcher {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Client == nil {
		deps.Client = NewHTTPClient(Guard{}, nil)
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &Dispatcher{deps: deps}
}

// wirePayload is the JSON body signed and delivered.
type wirePayload struct {
	Event     string          `json:"event"`
	ID        uuid.UUID       `json:"id"` // delivery UUID, for consumer dedup
	CreatedAt time.Time       `json:"created_at"`
	Data      json.RawMessage `json:"data"`
}

// Emit records a delivery per subscribed active endpoint and enqueues a
// delivery job for each (§9.3). It is best-effort: a webhook failure never
// rolls back the state change that triggered it, so callers log and continue.
func (d *Dispatcher) Emit(ctx context.Context, orgID uuid.UUID, eventType string, data any) error {
	if d.deps.Store == nil || d.deps.Queue == nil {
		return nil // webhooks not wired (e.g. dev without a queue)
	}
	q := d.deps.Store.Queries()
	eps, err := q.ListActiveWebhookEndpointsForEvent(ctx, storegen.ListActiveWebhookEndpointsForEventParams{
		OrgID: orgID, Event: eventType,
	})
	if err != nil {
		return fmt.Errorf("webhook: list endpoints: %w", err)
	}
	dataRaw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("webhook: marshal data: %w", err)
	}
	var firstErr error
	for _, ep := range eps {
		deliveryID, _ := uuid.NewV7()
		payload, err := json.Marshal(wirePayload{
			Event: eventType, ID: deliveryID, CreatedAt: d.deps.Now().UTC(), Data: dataRaw,
		})
		if err != nil {
			firstErr = err
			continue
		}
		if _, err := q.CreateWebhookDelivery(ctx, storegen.CreateWebhookDeliveryParams{
			ID: deliveryID, EndpointID: ep.ID, EventType: eventType, Payload: payload,
		}); err != nil {
			firstErr = err
			continue
		}
		if _, err := d.deps.Queue.Enqueue(ctx, JobDeliver, "core",
			deliverArgs{DeliveryID: deliveryID}, queue.WithMaxAttempts(5)); err != nil {
			d.deps.Log.Error("webhook: enqueue", "err", err, "delivery", deliveryID)
			firstErr = err
		}
	}
	return firstErr
}

type deliverArgs struct {
	DeliveryID uuid.UUID `json:"delivery_id"`
}

// RegisterHandlers wires the delivery handler onto the queue (worker role).
func (d *Dispatcher) RegisterHandlers(q queue.Client) {
	q.Register(JobDeliver, d.deliver)
}

// deliver performs one delivery attempt. Returning an error tells the queue to
// retry with exponential backoff (up to 5 attempts, §9.3). The SSRF guard runs
// inside the HTTP client's dialer, so re-resolution happens on every attempt.
func (d *Dispatcher) deliver(ctx context.Context, job queue.Job) error {
	var args deliverArgs
	if err := json.Unmarshal(job.Args, &args); err != nil {
		return nil // unparseable args: nothing to retry
	}
	q := d.deps.Store.Queries()
	row, err := q.GetWebhookDeliveryWithEndpoint(ctx, args.DeliveryID)
	if err != nil {
		return nil // delivery/endpoint gone: stop
	}
	attempt := int32(job.Attempt)

	record := func(status *int32, errStr string, deliveredAt *time.Time, nextRetry *time.Time) {
		if e := q.RecordWebhookDeliveryResult(ctx, storegen.RecordWebhookDeliveryResultParams{
			ID: args.DeliveryID, Attempt: attempt, StatusCode: status,
			Error: strPtrOrNil(errStr), DeliveredAt: deliveredAt, NextRetryAt: nextRetry,
		}); e != nil {
			d.deps.Log.Error("webhook: record result", "err", e, "delivery", args.DeliveryID)
		}
	}

	// Permanent config problems: record and stop (no retry).
	if !row.EndpointActive {
		record(nil, "endpoint inactive", nil, nil)
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(row.Url), "https://") {
		record(nil, "non-https url blocked (T-08)", nil, nil)
		return nil
	}
	secret, err := d.deps.Sealer.Open(row.SecretEnc)
	if err != nil {
		record(nil, "secret unseal failed", nil, nil)
		return nil
	}

	now := d.deps.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, row.Url, bytes.NewReader(row.Payload))
	if err != nil {
		record(nil, err.Error(), nil, d.backoff(now, job.Attempt))
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "agentry-webhooks/1")
	req.Header.Set(SignatureHeader, Sign(secret, row.Payload, now))
	req.Header.Set("X-Agentry-Event", row.EventType)
	req.Header.Set("X-Agentry-Delivery", args.DeliveryID.String())

	resp, err := d.deps.Client.Do(req)
	if err != nil {
		// Transport error incl. the SSRF guard blocking the address (T-08).
		record(nil, err.Error(), nil, d.backoff(now, job.Attempt))
		return fmt.Errorf("webhook: deliver %s: %w", args.DeliveryID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	code := int32(resp.StatusCode)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		record(&code, "", &now, nil)
		return nil
	}
	// Non-2xx (incl. a 3xx we refuse to follow, T-08): retry.
	record(&code, fmt.Sprintf("non-2xx status %d", resp.StatusCode), nil, d.backoff(now, job.Attempt))
	return fmt.Errorf("webhook: deliver %s: status %d", args.DeliveryID, resp.StatusCode)
}

// backoff mirrors the queue's 2^attempt seconds schedule for the display-only
// next_retry_at column (the queue owns the authoritative retry clock).
func (d *Dispatcher) backoff(now time.Time, attempt int) *time.Time {
	t := now.Add(time.Duration(1<<uint(attempt)) * time.Second)
	return &t
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
