package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/ratelimit"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
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
	// EventAgentDependencyAlert: a published version declares an MCP server
	// version with a newly known high/critical vulnerability (agentry#177).
	EventAgentDependencyAlert = "agent.dependency_alert"
	EventScanCompleted        = "scan.completed"
	EventMemberAdded          = "member.added"
	EventMemberRemoved        = "member.removed"
	EventPolicyUpdated        = "policy.updated"
)

// AllEvents lists the subscribable event types (validation, docs).
func AllEvents() []string {
	return []string{
		EventAgentCreated, EventVersionSubmitted, EventVersionPublished,
		EventVersionRejected, EventVersionNeedsReview, EventVersionYanked,
		EventAgentQuarantined, EventAgentReinstated, EventAdvisoryPublished, EventAgentDependencyAlert,
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
	// DeliveriesPerSecond is the §19 per-org delivery rate (default 5).
	DeliveriesPerSecond float64
}

// deliveryRateBurst is the token-bucket depth for the per-org delivery rate.
//
// Set to one second's worth: §19 says "5 deliveries/s per org", and a deeper
// bucket would let an org that has been quiet dump a burst on an endpoint that
// is at best surprised by it. Deferred deliveries are not dropped — they go
// back on the queue — so smoothing costs latency, not events.
const deliveryRateBurst = 1

// Dispatcher records and delivers webhook events for an org.
type Dispatcher struct {
	deps Deps
	// rate enforces the §19 per-org delivery rate. Per-process, so an
	// N-replica worker fleet allows roughly N× the rate — acceptable for a
	// politeness limit, and the D-06 note applies (Redis on multi-node SaaS).
	rate *ratelimit.Buckets
	// mx counts §16.2 delivery outcomes; nil is a working no-op.
	mx *metrics.Metrics
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
	if deps.DeliveriesPerSecond <= 0 {
		deps.DeliveriesPerSecond = 5 // §19
	}
	return &Dispatcher{deps: deps, rate: ratelimit.New(ratelimit.DefaultIdleTTL)}
}

// SetMetrics wires the §16.2 instrument set.
func (d *Dispatcher) SetMetrics(m *metrics.Metrics) { d.mx = m }

// Close releases the rate-limiter's collector goroutine.
func (d *Dispatcher) Close() error {
	if d == nil {
		return nil
	}
	return d.rate.Close()
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

	// One line per attempt, named for the log contract (docs/logging.md).
	delivered := func(outcome string, extra ...any) {
		attrs := append([]any{logevent.WebhookDelivered.Attr(), "outcome", outcome,
			"org", row.OrgID, "delivery", args.DeliveryID, "attempt", attempt}, extra...)
		d.deps.Log.InfoContext(ctx, "webhook: delivery finished", attrs...)
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

	// §19: 5 deliveries/s per org. Checked AFTER the permanent-failure branches
	// above — spending a token on a delivery we are about to drop for a bad
	// URL would let one misconfigured endpoint eat the org's whole budget.
	//
	// Over budget, the delivery is deferred by returning an error: the queue
	// re-runs it on its 2^attempt backoff. That does consume one of the five
	// attempts §9.3 allows, so the retry budget is shared between throttling
	// and real failures; at 5/s against a 5-attempt budget an org would have
	// to be sustaining a large burst for that to exhaust anything.
	if res := d.rate.Allow("webhook", row.OrgID.String(),
		ratelimit.PerSecond(d.deps.DeliveriesPerSecond), deliveryRateBurst); !res.OK {
		d.mx.RecordWebhookDelivery(ctx, "throttled")
		d.deps.Log.Debug("webhook: org delivery rate exceeded; deferring",
			"org", row.OrgID, "delivery", args.DeliveryID, "retry_in", res.Reset)
		return fmt.Errorf("webhook: org %s over the delivery rate; retrying", row.OrgID)
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
		d.mx.RecordWebhookDelivery(ctx, "error")
		var blocked *ErrBlockedAddress
		if errors.As(err, &blocked) {
			// Named for the log contract: a refused target is a signal the
			// security dashboard watches, not a transport hiccup.
			d.deps.Log.WarnContext(ctx, "webhook: target refused by the private-range guard", logevent.SSRFRefused.Attr(),
				"org", row.OrgID, "delivery", args.DeliveryID, "endpoint", row.EndpointID, "host", blocked.Host)
		}
		delivered("error", "err", err)
		record(nil, err.Error(), nil, d.backoff(now, job.Attempt))
		return fmt.Errorf("webhook: deliver %s: %w", args.DeliveryID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	code := int32(resp.StatusCode)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		d.mx.RecordWebhookDelivery(ctx, "ok")
		delivered("ok", "status", code)
		record(&code, "", &now, nil)
		return nil
	}
	d.mx.RecordWebhookDelivery(ctx, "error")
	delivered("error", "status", code)
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
