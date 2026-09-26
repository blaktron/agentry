// Package metrics is the §16.2 telemetry seam: one instrument set, two ways
// out of the process.
//
//   - OTLP/HTTP export (opt-in, AGENTRY_OTEL_ENDPOINT). On SaaS this points at
//     the ADOT sidecar, which writes the metrics to CloudWatch as EMF under the
//     `Agentry` namespace — which is where the §16.3 alarms read them.
//   - A Prometheus exposition endpoint at /metrics, always on (D-25: a
//     self-hosted operator gets the same numbers without running a collector).
//
// Instrument names are the CloudWatch metric names the terraform dashboards
// and alarms in deploy/terraform/modules/observability reference, verbatim —
// QueueAgeSeconds, ScanStageErrors, ScanStageRuns and the rest. They are
// deliberately NOT renamed to OTel dotted convention on the way out: an alarm
// that reads a metric nobody emits is worse than an unidiomatic name, and the
// same names appear in the Prometheus output so the two views agree.
//
// A nil *Metrics is usable: every method is a no-op. Call sites therefore never
// need a nil check, and code paths that run without telemetry (tests, `agentry
// validate`) stay unchanged.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// scopeName identifies this instrumentation scope in OTLP output.
const scopeName = "github.com/blaktron/agentry/internal/metrics"

// secondsBuckets are the explicit histogram boundaries for every *Seconds
// instrument. The SDK default boundaries top out at 10,000 and are shaped for
// milliseconds; against seconds they put every real latency in the first
// bucket and make the §16.1 p95 SLOs (git clone first byte < 2 s, API p99 <
// 300 ms) unreadable. These span 5 ms to 10 min, which covers an API read and
// a slow scan stage in one scale.
var secondsBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600,
}

// Config selects the exporters.
type Config struct {
	// OTLPEndpoint is the collector base URL (AGENTRY_OTEL_ENDPOINT), e.g.
	// http://localhost:4318. Empty disables OTLP export entirely — no
	// background exporter, no connection attempts.
	OTLPEndpoint string
	// ServiceName and ServiceVersion label the resource.
	ServiceName    string
	ServiceVersion string
	// Role is the agentryd role (api|git|worker|all); it becomes a resource
	// attribute so per-service dashboards can split by it.
	Role string
	// Env is dev|staging|prod.
	Env string
	// ExportInterval is how often the OTLP reader flushes. Zero uses 30s,
	// which matches the ADOT collector's batch timeout.
	ExportInterval time.Duration
}

// Metrics owns the meter provider and the instrument set.
type Metrics struct {
	provider *sdkmetric.MeterProvider
	// scrape is the always-present reader the /metrics handler collects from.
	scrape *sdkmetric.ManualReader

	httpRequests metric.Int64Counter
	httpDuration metric.Float64Histogram

	queueDepth metric.Int64Gauge
	queueAge   metric.Float64Gauge
	queueJobs  metric.Int64Counter

	scanStageRuns     metric.Int64Counter
	scanStageErrors   metric.Int64Counter
	scanStageHits     metric.Int64Counter
	scanStageDuration metric.Float64Histogram

	publishSubmitted metric.Int64Counter
	publishVerdicts  map[string]metric.Int64Counter
	judgeTokens      metric.Int64Counter
	modelInputCalls  metric.Int64Counter
	modelInputTokens metric.Int64Counter

	gitOps            metric.Int64Counter
	gitOpDuration     metric.Float64Histogram
	gitOpConcurrency  metric.Int64Gauge
	gitCloneFirstByte metric.Float64Histogram

	webhookDeliveries metric.Int64Counter

	// failOpen counts the deliberate fail-open paths (agentry#33): places
	// that log and continue so a broken control never becomes an outage.
	// "We did not check" has to be visible on a dashboard, not only in a
	// log line.
	failOpen metric.Int64Counter
	// mcpSweeps / mcpAlerts: the daily MCP server vulnerability sweep and
	// the dependency alerts it opens (agentry#177).
	mcpSweeps metric.Int64Counter
	mcpAlerts metric.Int64Counter
}

// New builds the meter provider and instruments. It returns an error only for
// a malformed OTLP endpoint; every other failure mode degrades to the
// scrape-only reader rather than refusing to start, because losing telemetry
// must never take the registry down with it.
func New(ctx context.Context, cfg Config) (*Metrics, error) {
	scrape := sdkmetric.NewManualReader()
	opts := []sdkmetric.Option{
		sdkmetric.WithReader(scrape),
		sdkmetric.WithResource(resourceFor(cfg)),
		// One view, matched by suffix: every *Seconds histogram gets the
		// seconds-scaled buckets above.
		sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{
				Name: "*Seconds",
				Kind: sdkmetric.InstrumentKindHistogram,
			},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: secondsBuckets,
				},
			},
		)),
	}

	if cfg.OTLPEndpoint != "" {
		exp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(cfg.OTLPEndpoint))
		if err != nil {
			return nil, fmt.Errorf("metrics: otlp exporter: %w", err)
		}
		interval := cfg.ExportInterval
		if interval <= 0 {
			interval = 30 * time.Second
		}
		opts = append(opts, sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(interval)),
		))
	}

	mp := sdkmetric.NewMeterProvider(opts...)
	m := &Metrics{provider: mp, scrape: scrape}
	if err := m.instrument(mp.Meter(scopeName)); err != nil {
		return nil, err
	}
	return m, nil
}

func resourceFor(cfg Config) *resource.Resource {
	name := cfg.ServiceName
	if name == "" {
		name = "agentryd"
	}
	attrs := []attribute.KeyValue{attribute.String("service.name", name)}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, attribute.String("service.version", cfg.ServiceVersion))
	}
	if cfg.Role != "" {
		attrs = append(attrs, attribute.String("agentry.role", cfg.Role))
	}
	if cfg.Env != "" {
		attrs = append(attrs, attribute.String("deployment.environment", cfg.Env))
	}
	// Schemaless on purpose: these four attributes are stable and the semconv
	// module would be a dependency bought for four string constants.
	return resource.NewSchemaless(attrs...)
}

// instrument creates every instrument up front so a typo surfaces at startup
// rather than on the first request that would have recorded it.
func (m *Metrics) instrument(meter metric.Meter) error {
	var errs []error
	i64c := func(name, desc string) metric.Int64Counter {
		c, err := meter.Int64Counter(name, metric.WithDescription(desc))
		errs = append(errs, err)
		return c
	}
	f64h := func(name, desc string) metric.Float64Histogram {
		h, err := meter.Float64Histogram(name, metric.WithDescription(desc), metric.WithUnit("s"))
		errs = append(errs, err)
		return h
	}
	i64g := func(name, desc string) metric.Int64Gauge {
		g, err := meter.Int64Gauge(name, metric.WithDescription(desc))
		errs = append(errs, err)
		return g
	}
	f64g := func(name, desc, unit string) metric.Float64Gauge {
		g, err := meter.Float64Gauge(name, metric.WithDescription(desc), metric.WithUnit(unit))
		errs = append(errs, err)
		return g
	}

	// RED per endpoint (§16.2).
	m.httpRequests = i64c("HttpRequests", "HTTP requests by route class, method and status class.")
	m.httpDuration = f64h("HttpRequestDurationSeconds", "HTTP request duration by route class.")

	// Queue depth/age per River queue (§16.2) — QueueAgeSeconds carries the
	// §16.3 page alarm.
	m.queueDepth = i64g("QueueDepth", "Jobs waiting in a queue.")
	m.queueAge = f64g("QueueAgeSeconds", "Age of the oldest waiting job in a queue.", "s")
	m.queueJobs = i64c("QueueJobs", "Queue job outcomes by queue, kind and outcome.")

	// Scan pipeline. ScanStageRuns/ScanStageErrors are the numerator and
	// denominator of the §16.3 scan-error-rate page alarm.
	m.scanStageRuns = i64c("ScanStageRuns", "Scan stage executions.")
	m.scanStageErrors = i64c("ScanStageErrors", "Scan stage executions that failed.")
	m.failOpen = i64c("FailOpenEvents", "Deliberate fail-open events by path (audit_stream_drop, osv_not_checked, osv_error, history_not_scanned, directory_erasure).")
	m.scanStageHits = i64c("ScanStageHits", "Findings produced by a scan stage.")
	m.mcpSweeps = i64c("McpSweepRuns", "Daily MCP server vulnerability sweeps, by outcome (ok, error).")
	m.mcpAlerts = i64c("McpDependencyAlertsOpened", "Dependency alerts opened on published versions by the MCP sweep.")
	m.scanStageDuration = f64h("ScanStageDurationSeconds", "Scan stage duration.")

	// Publish funnel (§16.2 pipeline dashboard).
	m.publishSubmitted = i64c("PublishSubmitted", "Versions submitted for scanning.")
	m.publishVerdicts = map[string]metric.Int64Counter{
		VerdictClean:   i64c("PublishVerdictClean", "Versions whose pipeline verdict was clean."),
		VerdictReview:  i64c("PublishVerdictReview", "Versions whose pipeline verdict was needs_review."),
		VerdictBlocked: i64c("PublishVerdictBlocked", "Versions whose pipeline verdict was blocked."),
	}
	m.judgeTokens = i64c("JudgeTokens", "S5 judge token use as the provider reported it, by kind (prompt|completion).")
	// The model-input routes (agentry#608): calls by op and verdict, and
	// the judge's input tokens they spent. Counts, never a price (DEV-150).
	m.modelInputCalls = i64c("ModelInputCalls", "Model-input route calls by op (scan|search) and verdict (pass|withheld|not_scanned).")
	m.modelInputTokens = i64c("ModelInputJudgeTokens", "Judge input tokens the model-input routes spent, by op (scan|search).")

	// git (§16.2 git dashboard; first-byte carries the §16.1 p95 < 2s SLO).
	m.gitOps = i64c("GitOps", "git smart-HTTP operations by op and outcome.")
	m.gitOpDuration = f64h("GitOpDurationSeconds", "git smart-HTTP operation duration.")
	m.gitOpConcurrency = i64g("GitOpConcurrency", "git operations currently in flight.")
	m.gitCloneFirstByte = f64h("GitCloneFirstByteSeconds", "Time to first response byte for a git clone/fetch.")

	m.webhookDeliveries = i64c("WebhookDeliveries", "Webhook delivery attempts by outcome.")

	return errors.Join(errs...)
}

// Verdict values recorded by RecordVerdict. They match the version status
// vocabulary the pipeline already uses.
const (
	VerdictClean   = "clean"
	VerdictReview  = "needs_review"
	VerdictBlocked = "blocked"
)

// Shutdown flushes and stops the exporters. Safe on a nil receiver.
func (m *Metrics) Shutdown(ctx context.Context) error {
	if m == nil || m.provider == nil {
		return nil
	}
	return m.provider.Shutdown(ctx)
}

// --- recording API --------------------------------------------------------
//
// Every method tolerates a nil receiver so call sites stay free of guards.

// RecordHTTP records one served request. route is a low-cardinality route
// class (the matched pattern), never the raw path: a per-path metric would let
// any caller mint unbounded time series by varying a path segment.
func (m *Metrics) RecordHTTP(ctx context.Context, route, method string, status int, d time.Duration) {
	if m == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("route", route),
		attribute.String("method", method),
		attribute.String("status_class", statusClass(status)),
	)
	m.httpRequests.Add(ctx, 1, attrs)
	m.httpDuration.Record(ctx, d.Seconds(), metric.WithAttributes(
		attribute.String("route", route),
		attribute.String("method", method),
	))
}

// statusClass buckets a status code as 2xx/3xx/4xx/5xx. The exact code would
// multiply series for no operational gain: the alarms care about the class.
func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

// RecordQueueStats publishes the depth and oldest-job age of one queue.
func (m *Metrics) RecordQueueStats(ctx context.Context, queue string, depth int64, oldest time.Duration) {
	if m == nil {
		return
	}
	attrs := metric.WithAttributes(attribute.String("queue", queue))
	m.queueDepth.Record(ctx, depth, attrs)
	m.queueAge.Record(ctx, oldest.Seconds(), attrs)
}

// RecordQueueJob records one job's terminal outcome ("ok" | "error").
func (m *Metrics) RecordQueueJob(ctx context.Context, queue, kind, outcome string, d time.Duration) {
	if m == nil {
		return
	}
	m.queueJobs.Add(ctx, 1, metric.WithAttributes(
		attribute.String("queue", queue),
		attribute.String("kind", kind),
		attribute.String("outcome", outcome),
	))
	_ = d
}

// RecordScanStage records one stage execution: always a run, plus an error
// when it failed and the number of findings it produced.
func (m *Metrics) RecordScanStage(ctx context.Context, stage string, d time.Duration, findings int, err error) {
	if m == nil {
		return
	}
	attrs := metric.WithAttributes(attribute.String("stage", stage))
	m.scanStageRuns.Add(ctx, 1, attrs)
	m.scanStageDuration.Record(ctx, d.Seconds(), attrs)
	if err != nil {
		m.scanStageErrors.Add(ctx, 1, attrs)
	}
	if findings > 0 {
		m.scanStageHits.Add(ctx, int64(findings), attrs)
	}
}

// FailOpen paths, the attribute values RecordFailOpen accepts. Each is a
// place the code chooses to continue rather than stop when a control is
// unavailable (DEV-020, DEV-026.3), so its count is the honest measure of
// how often that control did not run.
const (
	FailOpenAuditStreamDrop = "audit_stream_drop"
	FailOpenOSVNotChecked   = "osv_not_checked"
	FailOpenOSVError        = "osv_error"
	// FailOpenHistoryNotScanned counts git-tag publishes whose history S2
	// could not (fully) scan for secrets (agentry#54).
	FailOpenHistoryNotScanned = "history_not_scanned"
	// FailOpenDirectoryErasure counts account erasures whose directory
	// half did not happen: the retries ran out, or the retry could not be
	// queued (agentry#499). The registry's erasure stands; the sign-in
	// account is left for the operator to delete.
	FailOpenDirectoryErasure = "directory_erasure"
)

// RecordMCPSweep counts one sweep run and the alerts it opened.
func (m *Metrics) RecordMCPSweep(ctx context.Context, opened int, err error) {
	if m == nil {
		return
	}
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	if m.mcpSweeps != nil {
		m.mcpSweeps.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	}
	if m.mcpAlerts != nil && opened > 0 {
		m.mcpAlerts.Add(ctx, int64(opened))
	}
}

// RecordFailOpen counts one fail-open event on the named path.
func (m *Metrics) RecordFailOpen(ctx context.Context, path string) {
	if m == nil {
		return
	}
	m.failOpen.Add(ctx, 1, metric.WithAttributes(attribute.String("path", path)))
}

// RecordPublishSubmitted counts a version entering the pipeline.
func (m *Metrics) RecordPublishSubmitted(ctx context.Context) {
	if m == nil {
		return
	}
	m.publishSubmitted.Add(ctx, 1)
}

// RecordVerdict counts one pipeline verdict. An unrecognized verdict is
// dropped rather than silently folded into another bucket.
func (m *Metrics) RecordVerdict(ctx context.Context, verdict string) {
	if m == nil {
		return
	}
	if c, ok := m.publishVerdicts[verdict]; ok {
		c.Add(ctx, 1)
	}
}

// RecordJudgeTokens counts one adjudication's token use by kind. It
// replaces the judge-cost counter that nothing ever fed: the price per
// token is the operator's to apply to these counts (plan subscription-tiers
// §10), and a count is what every provider actually reports.
func (m *Metrics) RecordJudgeTokens(ctx context.Context, prompt, completion int) {
	if m == nil {
		return
	}
	m.judgeTokens.Add(ctx, int64(prompt), metric.WithAttributes(attribute.String("kind", "prompt")))
	m.judgeTokens.Add(ctx, int64(completion), metric.WithAttributes(attribute.String("kind", "completion")))
}

// RecordModelInput counts one model-input call by op and verdict, and the
// judge input tokens it spent.
func (m *Metrics) RecordModelInput(ctx context.Context, op, verdict string, inputTokens int) {
	if m == nil {
		return
	}
	m.modelInputCalls.Add(ctx, 1, metric.WithAttributes(attribute.String("op", op), attribute.String("verdict", verdict)))
	m.modelInputTokens.Add(ctx, int64(inputTokens), metric.WithAttributes(attribute.String("op", op)))
}

// RecordGitOp records a completed git smart-HTTP operation.
func (m *Metrics) RecordGitOp(ctx context.Context, op, outcome string, d time.Duration) {
	if m == nil {
		return
	}
	m.gitOps.Add(ctx, 1, metric.WithAttributes(
		attribute.String("op", op),
		attribute.String("outcome", outcome),
	))
	m.gitOpDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("op", op)))
}

// RecordGitConcurrency publishes the in-flight count for a git op class.
func (m *Metrics) RecordGitConcurrency(ctx context.Context, op string, inflight int64) {
	if m == nil {
		return
	}
	m.gitOpConcurrency.Record(ctx, inflight, metric.WithAttributes(attribute.String("op", op)))
}

// RecordGitCloneFirstByte records time-to-first-byte for a clone/fetch — the
// §16.1 "p95 < 2 s first-byte" SLI.
func (m *Metrics) RecordGitCloneFirstByte(ctx context.Context, d time.Duration) {
	if m == nil {
		return
	}
	m.gitCloneFirstByte.Record(ctx, d.Seconds())
}

// RecordWebhookDelivery counts one delivery attempt ("ok" | "error" |
// "throttled").
func (m *Metrics) RecordWebhookDelivery(ctx context.Context, outcome string) {
	if m == nil {
		return
	}
	m.webhookDeliveries.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}

// Meter exposes the provider's meter for callers that need an instrument this
// package does not wrap. Returns a no-op meter on a nil receiver.
func (m *Metrics) Meter() metric.Meter {
	if m == nil || m.provider == nil {
		return noop.NewMeterProvider().Meter(scopeName)
	}
	return m.provider.Meter(scopeName)
}

// Handler serves the Prometheus exposition of the current instrument values.
// It is mounted OUTSIDE /api/v1 and unauthenticated (see docs/ops/
// deployment.md): bind agentryd to a private interface, or keep /metrics off
// the public listener at the proxy, if the numbers are sensitive.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil || m.scrape == nil {
			w.Header().Set("Content-Type", promContentType)
			w.WriteHeader(http.StatusOK)
			return
		}
		body, err := m.Gather(r.Context())
		if err != nil {
			http.Error(w, "metrics collection failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", promContentType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	})
}
