package metrics

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestMetrics(t *testing.T) *Metrics {
	t.Helper()
	m, err := New(t.Context(), Config{ServiceName: "agentryd", Role: "all", Env: "dev"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return m
}

func gather(t *testing.T, m *Metrics) string {
	t.Helper()
	b, err := m.Gather(t.Context())
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	return string(b)
}

// The §16.3 alarms and §16.2 dashboards address these metrics by name. If a
// rename ever lands, this test is the thing that should fail — not a silent
// alarm in production that never fires again.
func TestInstrumentNamesMatchTerraform(t *testing.T) {
	m := newTestMetrics(t)
	ctx := t.Context()

	m.RecordHTTP(ctx, "/agents/{ns}/{name}", "GET", 200, 12*time.Millisecond)
	m.RecordQueueStats(ctx, "core", 3, 42*time.Second)
	m.RecordQueueJob(ctx, "core", "webhook.deliver", "ok", time.Second)
	m.RecordScanStage(ctx, "S2", 250*time.Millisecond, 2, nil)
	// A stage that failed, so ScanStageErrors has a data point: an instrument
	// with no observations is absent from the exposition entirely.
	m.RecordScanStage(ctx, "S6", 250*time.Millisecond, 0, context.DeadlineExceeded)
	m.RecordPublishSubmitted(ctx)
	m.RecordVerdict(ctx, VerdictClean)
	m.RecordVerdict(ctx, VerdictReview)
	m.RecordVerdict(ctx, VerdictBlocked)
	m.RecordJudgeCost(ctx, 1.5)
	m.RecordGitOp(ctx, "upload-pack", "ok", time.Second)
	m.RecordGitConcurrency(ctx, "upload-pack", 2)
	m.RecordGitCloneFirstByte(ctx, 300*time.Millisecond)
	m.RecordWebhookDelivery(ctx, "ok")

	out := gather(t, m)
	// Exactly the names referenced by deploy/terraform/modules/observability.
	for _, name := range []string{
		"QueueDepth", "QueueAgeSeconds",
		"ScanStageErrors", "ScanStageRuns", "ScanStageDurationSeconds", "ScanStageHits",
		"GitCloneFirstByteSeconds", "GitOpConcurrency",
		"PublishSubmitted", "PublishVerdictClean", "PublishVerdictReview", "PublishVerdictBlocked",
		"JudgeCostCents",
		"HttpRequests", "HttpRequestDurationSeconds", "WebhookDeliveries",
	} {
		if !strings.Contains(out, "\n"+name) && !strings.HasPrefix(out, name) {
			t.Errorf("exposition is missing metric %q", name)
		}
	}
}

func TestScanStageErrorsOnlyCountsFailures(t *testing.T) {
	m := newTestMetrics(t)
	ctx := t.Context()

	m.RecordScanStage(ctx, "S2", time.Millisecond, 0, nil)
	m.RecordScanStage(ctx, "S2", time.Millisecond, 0, nil)
	m.RecordScanStage(ctx, "S2", time.Millisecond, 0, context.DeadlineExceeded)

	out := gather(t, m)
	// The scan-error-rate page alarm divides ScanStageErrors by ScanStageRuns,
	// so a failed stage must be counted in BOTH.
	if got := sampleValue(t, out, "ScanStageRuns", `stage="S2"`); got != "3" {
		t.Errorf("ScanStageRuns = %q, want 3", got)
	}
	if got := sampleValue(t, out, "ScanStageErrors", `stage="S2"`); got != "1" {
		t.Errorf("ScanStageErrors = %q, want 1", got)
	}
}

func TestHTTPStatusIsBucketedByClass(t *testing.T) {
	m := newTestMetrics(t)
	ctx := t.Context()
	m.RecordHTTP(ctx, "/meta", "GET", 503, time.Millisecond)
	m.RecordHTTP(ctx, "/meta", "GET", 500, time.Millisecond)

	out := gather(t, m)
	// Both 500 and 503 collapse into one 5xx series: the raw code would let a
	// caller mint series at will.
	if got := sampleValue(t, out, "HttpRequests", `status_class="5xx"`); got != "2" {
		t.Errorf("HttpRequests{status_class=5xx} = %q, want 2", got)
	}
	if strings.Contains(out, `status_class="503"`) {
		t.Error("exposition leaked a raw status code as a label")
	}
}

func TestHistogramIsCumulativeAndSecondsScaled(t *testing.T) {
	m := newTestMetrics(t)
	ctx := t.Context()
	// 0.3s and 3s: with the SDK's millisecond-shaped defaults both would land
	// in the first bucket and the p95 SLO would be unmeasurable.
	m.RecordGitCloneFirstByte(ctx, 300*time.Millisecond)
	m.RecordGitCloneFirstByte(ctx, 3*time.Second)

	out := gather(t, m)
	if got := sampleValue(t, out, "GitCloneFirstByteSeconds_bucket", `le="0.5"`); got != "1" {
		t.Errorf("bucket le=0.5 = %q, want 1", got)
	}
	if got := sampleValue(t, out, "GitCloneFirstByteSeconds_bucket", `le="5"`); got != "2" {
		t.Errorf("bucket le=5 = %q, want 2 (cumulative)", got)
	}
	if got := sampleValue(t, out, "GitCloneFirstByteSeconds_bucket", `le="+Inf"`); got != "2" {
		t.Errorf("bucket le=+Inf = %q, want 2", got)
	}
	if got := sampleValue(t, out, "GitCloneFirstByteSeconds_count", ""); got != "2" {
		t.Errorf("count = %q, want 2", got)
	}
}

func TestExpositionCarriesTypeHeadersAndResourceLabels(t *testing.T) {
	m := newTestMetrics(t)
	m.RecordQueueStats(t.Context(), "sandbox", 7, time.Minute)
	m.RecordPublishSubmitted(t.Context())

	out := gather(t, m)
	if !strings.Contains(out, "# TYPE QueueDepth gauge") {
		t.Error("QueueDepth is not declared as a gauge")
	}
	if !strings.Contains(out, "# TYPE PublishSubmitted counter") {
		t.Error("PublishSubmitted is not declared as a counter")
	}
	if !strings.Contains(out, `service_name="agentryd"`) {
		t.Error("resource attributes did not become labels")
	}
	if !strings.Contains(out, `queue="sandbox"`) {
		t.Error("per-queue attribute missing")
	}
}

// A nil *Metrics is the "telemetry not wired" case every call site relies on.
func TestNilMetricsIsANoOp(t *testing.T) {
	var m *Metrics
	ctx := t.Context()
	m.RecordHTTP(ctx, "/x", "GET", 200, time.Second)
	m.RecordQueueStats(ctx, "core", 1, time.Second)
	m.RecordQueueJob(ctx, "core", "k", "ok", time.Second)
	m.RecordScanStage(ctx, "S1", time.Second, 1, nil)
	m.RecordPublishSubmitted(ctx)
	m.RecordVerdict(ctx, VerdictClean)
	m.RecordJudgeCost(ctx, 1)
	m.RecordGitOp(ctx, "upload-pack", "ok", time.Second)
	m.RecordGitConcurrency(ctx, "upload-pack", 1)
	m.RecordGitCloneFirstByte(ctx, time.Second)
	m.RecordWebhookDelivery(ctx, "ok")
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if m.Meter() == nil {
		t.Error("nil Metrics returned a nil Meter")
	}

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Errorf("nil-metrics /metrics returned %d, want 200", rec.Code)
	}
}

func TestHandlerServesExposition(t *testing.T) {
	m := newTestMetrics(t)
	m.RecordPublishSubmitted(t.Context())

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != promContentType {
		t.Errorf("Content-Type = %q, want %q", ct, promContentType)
	}
	if !strings.Contains(rec.Body.String(), "PublishSubmitted") {
		t.Error("body did not contain the recorded metric")
	}
}

func TestUnknownVerdictIsDropped(t *testing.T) {
	m := newTestMetrics(t)
	m.RecordVerdict(t.Context(), "yanked")
	out := gather(t, m)
	// Nothing recorded means no series at all — never silently folded into
	// one of the three real verdict counters.
	if strings.Contains(out, "PublishVerdict") {
		t.Errorf("an unknown verdict produced a verdict series:\n%s", out)
	}
}

func TestLabelValuesAreEscaped(t *testing.T) {
	m := newTestMetrics(t)
	m.RecordHTTP(t.Context(), `weird"route`, "GET", 200, time.Millisecond)
	out := gather(t, m)
	if !strings.Contains(out, `route="weird\"route"`) {
		t.Errorf("quote in a label value was not escaped:\n%s", out)
	}
}

// sampleValue finds the first exposition line starting with name whose label
// set contains match, and returns its value.
func sampleValue(t *testing.T, exposition, name, match string) string {
	t.Helper()
	for _, line := range strings.Split(exposition, "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, name) {
			continue
		}
		// Guard against name being a prefix of a longer metric name.
		rest := line[len(name):]
		if rest == "" || (rest[0] != '{' && rest[0] != ' ') {
			continue
		}
		if match != "" && !strings.Contains(line, match) {
			continue
		}
		fields := strings.Fields(line)
		return fields[len(fields)-1]
	}
	t.Errorf("no sample for %s matching %q in:\n%s", name, match, exposition)
	return ""
}
