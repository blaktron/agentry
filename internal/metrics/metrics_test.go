package metrics

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/blaktron/agentry/internal/logevent"
)

// resourceLabels are what every series of newTestMetrics carries.
var resourceLabels = map[string]string{"agentry_role": "all", "deployment_environment": "dev", "service_name": "agentryd"}

// seriesKey renders name and the sorted label set the way the exposition does.
func seriesKey(name string, resource, extra map[string]string) string {
	all := map[string]string{}
	for k, v := range resource {
		all[k] = v
	}
	for k, v := range extra {
		all[k] = v
	}
	var keys []string
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+`="`+all[k]+`"`)
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

// exact returns the value of the one sample whose name and complete label set
// (resource labels included) are exactly these.
func exact(t *testing.T, out, name string, labels map[string]string) string {
	t.Helper()
	key := seriesKey(name, resourceLabels, labels) + " "
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, key) {
			return strings.TrimPrefix(l, key)
		}
	}
	t.Errorf("no sample %s in:\n%s", strings.TrimSuffix(key, " "), out)
	return ""
}

// absent fails when any sample of the metric exists.
func absent(t *testing.T, out, name string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, name+"{") || strings.HasPrefix(l, name+" ") || strings.HasPrefix(l, "# TYPE "+name+" ") {
			t.Errorf("unexpected %s: %s", name, l)
		}
	}
}

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

// The alarms and dashboards address these metrics by name. If a
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
	m.RecordJudgeTokens(ctx, 800, 90)
	m.RecordGitOp(ctx, "upload-pack", "ok", time.Second)
	m.RecordGitConcurrency(ctx, "upload-pack", 2)
	m.RecordGitCloneFirstByte(ctx, 300*time.Millisecond)
	m.RecordWebhookDelivery(ctx, "ok")
	m.RecordFailOpen(ctx, FailOpenOSVNotChecked)
	// The funnel counts one, two and three, so a verdict landing on another
	// verdict's counter shows.
	m.RecordVerdict(ctx, VerdictReview)
	m.RecordVerdict(ctx, VerdictBlocked)
	m.RecordVerdict(ctx, VerdictBlocked)

	out := gather(t, m)
	// Exactly the names the hosted deployment's dashboards and alarms
	// reference.
	for _, name := range []string{
		"QueueDepth", "QueueAgeSeconds",
		"ScanStageErrors", "ScanStageRuns", "ScanStageDurationSeconds", "ScanStageHits",
		"GitCloneFirstByteSeconds", "GitOpConcurrency",
		"PublishSubmitted", "PublishVerdictClean", "PublishVerdictReview", "PublishVerdictBlocked",
		"JudgeTokens",
		"HttpRequests", "HttpRequestDurationSeconds", "WebhookDeliveries",
		"FailOpenEvents",
	} {
		if !strings.Contains(out, "\n"+name) && !strings.HasPrefix(out, name) {
			t.Errorf("exposition is missing metric %q", name)
		}
	}

	// And each metric carries the labels and the value its recording call
	// gave it: the alarms divide, filter and group on exactly these.
	for _, c := range []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{"HttpRequests", map[string]string{"route": "/agents/{ns}/{name}", "method": "GET", "status_class": "2xx"}, "1"},
		{"HttpRequestDurationSeconds_count", map[string]string{"route": "/agents/{ns}/{name}", "method": "GET"}, "1"},
		{"HttpRequestDurationSeconds_sum", map[string]string{"route": "/agents/{ns}/{name}", "method": "GET"}, "0.012"},
		{"QueueDepth", map[string]string{"queue": "core"}, "3"},
		{"QueueAgeSeconds", map[string]string{"queue": "core"}, "42"},
		{"QueueJobs", map[string]string{"queue": "core", "kind": "webhook.deliver", "outcome": "ok"}, "1"},
		{"ScanStageRuns", map[string]string{"stage": "S2"}, "1"},
		{"ScanStageRuns", map[string]string{"stage": "S6"}, "1"},
		{"ScanStageErrors", map[string]string{"stage": "S6"}, "1"},
		{"ScanStageHits", map[string]string{"stage": "S2"}, "2"},
		{"ScanStageDurationSeconds_count", map[string]string{"stage": "S2"}, "1"},
		{"ScanStageDurationSeconds_sum", map[string]string{"stage": "S2"}, "0.25"},
		{"PublishSubmitted", nil, "1"},
		{"PublishVerdictClean", nil, "1"},
		{"PublishVerdictReview", nil, "2"},
		{"PublishVerdictBlocked", nil, "3"},
		{"JudgeTokens", map[string]string{"kind": "prompt"}, "800"},
		{"JudgeTokens", map[string]string{"kind": "completion"}, "90"},
		{"GitOps", map[string]string{"op": "upload-pack", "outcome": "ok"}, "1"},
		{"GitOpDurationSeconds_count", map[string]string{"op": "upload-pack"}, "1"},
		{"GitOpDurationSeconds_sum", map[string]string{"op": "upload-pack"}, "1"},
		{"GitOpConcurrency", map[string]string{"op": "upload-pack"}, "2"},
		{"GitCloneFirstByteSeconds_sum", nil, "0.3"},
		{"GitCloneFirstByteSeconds_count", nil, "1"},
		{"WebhookDeliveries", map[string]string{"outcome": "ok"}, "1"},
		{"FailOpenEvents", map[string]string{"path": "osv_not_checked"}, "1"},
	} {
		if got := exact(t, out, c.name, c.labels); got != c.want {
			t.Errorf("%s%v = %q, want %q", c.name, c.labels, got, c.want)
		}
	}
	// A stage that succeeded has no error series, and one that found nothing
	// has no hits series, so the rates divide by what happened.
	if strings.Contains(out, `ScanStageErrors{`+`agentry_role="all",deployment_environment="dev",service_name="agentryd",stage="S2"}`) ||
		strings.Contains(out, `ScanStageHits{`+`agentry_role="all",deployment_environment="dev",service_name="agentryd",stage="S6"}`) {
		t.Errorf("a clean stage has an error series, or an empty one has hits:\n%s", out)
	}
	t.Run("fail-open paths", failOpenPaths)
}

// failOpenPaths: the fail-open paths are the values the dashboards group by,
// and each one is the name of the event the same fail-open writes to the log.
func failOpenPaths(t *testing.T) {
	m := newTestMetrics(t)
	paths := map[string]logevent.Event{
		FailOpenAuditStreamDrop:   logevent.FailOpenAuditStreamDrop,
		FailOpenOSVNotChecked:     logevent.FailOpenOSVNotChecked,
		FailOpenOSVError:          logevent.FailOpenOSVError,
		FailOpenVersionNotChecked: logevent.FailOpenVersionNotChecked,
		FailOpenHistoryNotScanned: logevent.FailOpenHistoryNotScanned,
		FailOpenDirectoryErasure:  logevent.FailOpenDirectoryErasure,
	}
	literal := map[string]string{
		FailOpenAuditStreamDrop: "audit_stream_drop", FailOpenOSVNotChecked: "osv_not_checked", FailOpenOSVError: "osv_error",
		FailOpenVersionNotChecked: "version_not_checked", FailOpenHistoryNotScanned: "history_not_scanned", FailOpenDirectoryErasure: "directory_erasure",
	}
	for p, ev := range paths {
		if p != literal[p] {
			t.Errorf("path constant %q, want %q", p, literal[p])
		}
		if "failopen."+p != string(ev) {
			t.Errorf("metric path %q and log event %q do not name the same fail-open", p, ev)
		}
		m.RecordFailOpen(t.Context(), p)
		m.RecordFailOpen(t.Context(), p)
	}
	out := gather(t, m)
	for p := range paths {
		if got := exact(t, out, "FailOpenEvents", map[string]string{"path": p}); got != "2" {
			t.Errorf("FailOpenEvents{path=%s} = %q, want 2", p, got)
		}
	}
	if len(paths) != 6 {
		t.Fatalf("%d fail-open paths, the catalogue names six", len(paths))
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

	// Every edge of the classes: the first and last code of each, and codes
	// below 200 and above 599.
	edges := map[int]string{
		100: "1xx", 199: "1xx", 200: "2xx", 299: "2xx", 300: "3xx", 399: "3xx",
		400: "4xx", 499: "4xx", 500: "5xx", 599: "5xx", 600: "5xx",
	}
	m2 := newTestMetrics(t)
	for code := range edges {
		m2.RecordHTTP(ctx, "/edge/"+strconv.Itoa(code), "GET", code, time.Millisecond)
	}
	out2 := gather(t, m2)
	classes := map[string]int{}
	for _, l := range strings.Split(out2, "\n") {
		if strings.HasPrefix(l, "HttpRequests{") {
			classes[regexp.MustCompile(`status_class="([^"]+)"`).FindStringSubmatch(l)[1]]++
		}
	}
	wantClasses := map[string]int{}
	for _, c := range edges {
		wantClasses[c]++
	}
	for c, n := range wantClasses {
		if classes[c] != n {
			t.Errorf("status class %s has %d series, want %d (edges %v)", c, classes[c], n, edges)
		}
	}
	for c := range classes {
		if _, ok := wantClasses[c]; !ok {
			t.Errorf("unexpected status class %q", c)
		}
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
	if got := sampleValue(t, out, "GitCloneFirstByteSeconds_sum", ""); got != "3.3" {
		t.Errorf("sum = %q, want 3.3", got)
	}

	// The boundaries are the seconds-scaled ones the SLOs are read against,
	// in order, with the overflow bucket last.
	var les []string
	counts := map[string]string{}
	re := regexp.MustCompile(`^GitCloneFirstByteSeconds_bucket\{.*le="([^"]+)".*\} (\d+)$`)
	for _, l := range strings.Split(out, "\n") {
		if mm := re.FindStringSubmatch(l); mm != nil {
			les = append(les, mm[1])
			counts[mm[1]] = mm[2]
		}
	}
	wantLes := []string{"0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10", "30", "60", "120", "300", "600", "+Inf"}
	if strings.Join(les, " ") != strings.Join(wantLes, " ") {
		t.Fatalf("bucket boundaries = %v, want %v", les, wantLes)
	}
	for _, le := range wantLes {
		want := "0"
		switch le {
		case "0.5", "1", "2.5":
			want = "1"
		case "5", "10", "30", "60", "120", "300", "600", "+Inf":
			want = "2"
		}
		if counts[le] != want {
			t.Errorf("bucket le=%s = %s, want %s", le, counts[le], want)
		}
	}
	// Every *Seconds histogram gets the same scale, not only this one.
	m.RecordHTTP(ctx, "/x", "GET", 200, 300*time.Millisecond)
	m.RecordScanStage(ctx, "S1", 300*time.Millisecond, 0, nil)
	m.RecordGitOp(ctx, "upload-pack", "ok", 300*time.Millisecond)
	out = gather(t, m)
	for _, name := range []string{"HttpRequestDurationSeconds", "ScanStageDurationSeconds", "GitOpDurationSeconds"} {
		if got := sampleValue(t, out, name+"_bucket", `le="0.5"`); got != "1" {
			t.Errorf("%s le=0.5 = %q, want 1", name, got)
		}
		if got := sampleValue(t, out, name+"_bucket", `le="0.25"`); got != "0" {
			t.Errorf("%s le=0.25 = %q, want 0", name, got)
		}
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
	if !strings.Contains(out, "# HELP PublishSubmitted Versions submitted for scanning.\n# TYPE PublishSubmitted counter\n") {
		t.Errorf("HELP and TYPE lines of PublishSubmitted are not as documented:\n%s", out)
	}
	m.RecordHTTP(t.Context(), "/x", "GET", 200, time.Second)
	m.RecordGitConcurrency(t.Context(), "upload-pack", 1)
	out = gather(t, m)
	for _, c := range [][2]string{
		{"QueueAgeSeconds", "gauge"}, {"GitOpConcurrency", "gauge"}, {"HttpRequests", "counter"}, {"HttpRequestDurationSeconds", "histogram"},
	} {
		if !strings.Contains(out, "# TYPE "+c[0]+" "+c[1]+"\n") {
			t.Errorf("%s is not declared as a %s", c[0], c[1])
		}
	}
	if got := exact(t, out, "QueueDepth", map[string]string{"queue": "sandbox"}); got != "7" {
		t.Errorf("QueueDepth = %q, want 7", got)
	}
	if got := exact(t, out, "QueueAgeSeconds", map[string]string{"queue": "sandbox"}); got != "60" {
		t.Errorf("QueueAgeSeconds = %q, want 60", got)
	}

	// The resource: the configured name, version, role and environment each
	// under its own label; unset ones are not written, and an unset name is
	// the daemon's.
	full, err := New(t.Context(), Config{ServiceName: "gitd", ServiceVersion: "1.2.3", Role: "git", Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = full.Shutdown(context.Background()) })
	full.RecordPublishSubmitted(t.Context())
	want := `PublishSubmitted{agentry_role="git",deployment_environment="prod",service_name="gitd",service_version="1.2.3"} 1`
	if got := gather(t, full); !strings.Contains(got, "\n"+want+"\n") {
		t.Errorf("resource labels: want the line %s in:\n%s", want, got)
	}
	bare, err := New(t.Context(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bare.Shutdown(context.Background()) })
	bare.RecordPublishSubmitted(t.Context())
	if got := gather(t, bare); !strings.Contains(got, "\nPublishSubmitted{service_name=\"agentryd\"} 1\n") {
		t.Errorf("an empty config must label only the default service name:\n%s", got)
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
	m.RecordJudgeTokens(ctx, 1, 1)
	m.RecordGitOp(ctx, "upload-pack", "ok", time.Second)
	m.RecordGitConcurrency(ctx, "upload-pack", 1)
	m.RecordGitCloneFirstByte(ctx, time.Second)
	m.RecordWebhookDelivery(ctx, "ok")
	m.RecordFailOpen(ctx, FailOpenOSVError)
	m.RecordMCPSweep(ctx, 2, errors.New("x"))
	m.RecordModelInput(ctx, "scan", "pass", 10)
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if m.Meter() == nil {
		t.Error("nil Metrics returned a nil Meter")
	}
	if b, err := m.Gather(ctx); b != nil || err != nil {
		t.Errorf("nil Gather = %q, %v", b, err)
	}

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Errorf("nil-metrics /metrics returned %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != promContentType || rec.Body.Len() != 0 {
		t.Errorf("nil-metrics /metrics = %q body %q, want the exposition type and nothing", ct, rec.Body.String())
	}

	// A Metrics that was never built (no provider, no reader) is as inert.
	z := &Metrics{}
	if err := z.Shutdown(ctx); err != nil {
		t.Errorf("zero Metrics Shutdown: %v", err)
	}
	if z.Meter() == nil || z.ExtensionMeter("runs") == nil {
		t.Error("zero Metrics returned a nil meter")
	}
	if b, err := z.Gather(ctx); b != nil || err != nil {
		t.Errorf("zero Gather = %q, %v", b, err)
	}
	zrec := httptest.NewRecorder()
	z.Handler().ServeHTTP(zrec, httptest.NewRequest("GET", "/metrics", nil))
	if zrec.Code != 200 || zrec.Header().Get("Content-Type") != promContentType {
		t.Errorf("zero Metrics /metrics = %d %q", zrec.Code, zrec.Header().Get("Content-Type"))
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
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the Prometheus text format 0.0.4", ct)
	}
	if !strings.Contains(rec.Body.String(), "PublishSubmitted") {
		t.Error("body did not contain the recorded metric")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	// Once the provider is shut down the scrape fails closed: a 500 with the
	// fixed message, not an empty 200 a collector would read as zero.
	down := newTestMetrics(t)
	down.RecordPublishSubmitted(t.Context())
	if err := down.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	drec := httptest.NewRecorder()
	down.Handler().ServeHTTP(drec, httptest.NewRequest("GET", "/metrics", nil))
	if drec.Code != http.StatusInternalServerError || strings.TrimSpace(drec.Body.String()) != "metrics collection failed" {
		t.Errorf("scrape after shutdown = %d %q, want 500 and the fixed message", drec.Code, drec.Body.String())
	}
	if _, err := down.Gather(t.Context()); err == nil {
		t.Error("Gather after shutdown must report the reader error")
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

	// The three real verdicts are the version statuses the pipeline writes,
	// spelled exactly so, each on its own counter.
	for verdict, want := range map[string]string{"clean": "PublishVerdictClean", "needs_review": "PublishVerdictReview", "blocked": "PublishVerdictBlocked"} {
		mv := newTestMetrics(t)
		mv.RecordVerdict(t.Context(), verdict)
		got := gather(t, mv)
		if v := exact(t, got, want, nil); v != "1" {
			t.Errorf("verdict %q: %s = %q, want 1", verdict, want, v)
		}
		if n := strings.Count(got, "# TYPE PublishVerdict"); n != 1 {
			t.Errorf("verdict %q produced %d verdict series", verdict, n)
		}
	}
	if VerdictClean != "clean" || VerdictReview != "needs_review" || VerdictBlocked != "blocked" {
		t.Errorf("verdict vocabulary = %q %q %q", VerdictClean, VerdictReview, VerdictBlocked)
	}
}

func TestLabelValuesAreEscaped(t *testing.T) {
	m := newTestMetrics(t)
	m.RecordHTTP(t.Context(), `weird"route`, "GET", 200, time.Millisecond)
	out := gather(t, m)
	if !strings.Contains(out, `route="weird\"route"`) {
		t.Errorf("quote in a label value was not escaped:\n%s", out)
	}
	m.RecordHTTP(t.Context(), "back\\slash", "GET", 200, time.Millisecond)
	m.RecordHTTP(t.Context(), "new\nline", "GET", 200, time.Millisecond)
	out = gather(t, m)
	if !strings.Contains(out, `route="back\\slash"`) {
		t.Errorf("backslash in a label value was not escaped:\n%s", out)
	}
	if !strings.Contains(out, `route="new\nline"`) || strings.Contains(out, "new\nline") {
		t.Errorf("newline in a label value was not escaped:\n%s", out)
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

// An extension's instrument is scraped beside the core's, with the same
// resource labels.
func TestExtensionInstrumentIsScrapedWithTheResourceLabels(t *testing.T) {
	m := newTestMetrics(t)
	c, err := m.ExtensionMeter("runs").Int64Counter("RunsHostedTokens")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	c.Add(t.Context(), 1200, metric.WithAttributes(attribute.String("kind", "run")))
	out := gather(t, m)
	if !strings.Contains(out, "# TYPE RunsHostedTokens counter") {
		t.Fatalf("the extension's counter is not in the exposition:\n%s", out)
	}
	if got := sampleValue(t, out, "RunsHostedTokens", `kind="run"`); got != "1200" {
		t.Errorf("RunsHostedTokens = %q, want 1200", got)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "RunsHostedTokens{") && !strings.Contains(line, `service_name="agentryd"`) {
			t.Errorf("the extension's series lacks the resource labels: %s", line)
		}
	}

	// Every kind of instrument an extension can create is rendered with the
	// right type and value, under a valid name, with escaped help and labels.
	ctx := t.Context()
	em := m.ExtensionMeter("runs")
	fc, _ := em.Float64Counter("RunsFloat", metric.WithDescription("back\\slash and\nnewline"))
	fc.Add(ctx, 1.5, metric.WithAttributes(attribute.String("k", "v")))
	ud, _ := em.Int64UpDownCounter("RunsLive")
	ud.Add(ctx, 5)
	ud.Add(ctx, -2)
	fud, _ := em.Float64UpDownCounter("RunsFloatLive")
	fud.Add(ctx, 0.25)
	ig, _ := em.Int64Gauge("RunsIntGauge")
	ig.Record(ctx, 9, metric.WithAttributes(attribute.String("k", "v")))
	fg, _ := em.Float64Gauge("RunsFloatGauge")
	fg.Record(ctx, math.Inf(1), metric.WithAttributes(attribute.String("v", "pos")))
	fg.Record(ctx, math.Inf(-1), metric.WithAttributes(attribute.String("v", "neg")))
	fg.Record(ctx, math.NaN(), metric.WithAttributes(attribute.String("v", "nan")))
	fg.Record(ctx, 0.125, metric.WithAttributes(attribute.String("v", "frac")))
	ih, _ := em.Int64Histogram("RunsBytes")
	ih.Record(ctx, 5, metric.WithAttributes(attribute.String("k", "v")))
	ih.Record(ctx, 20000, metric.WithAttributes(attribute.String("k", "v")))
	fh, _ := em.Float64Histogram("RunsLatencySeconds")
	fh.Record(ctx, 1.5, metric.WithAttributes(attribute.String("le", "own")))
	dots, _ := em.Int64Counter("runs.hosted-tokens/total")
	dots.Add(ctx, 4, metric.WithAttributes(attribute.String("a.b:c", "x\\y\"z\nw"), attribute.String("9lives", "1")))
	out = gather(t, m)
	for _, want := range []string{
		"# HELP RunsFloat back\\\\slash and\\nnewline\n# TYPE RunsFloat counter\n",
		"# TYPE RunsLive gauge\n",
		"# TYPE RunsFloatLive gauge\n",
		"# TYPE RunsIntGauge gauge\n",
		"# TYPE RunsFloatGauge gauge\n",
		"# TYPE RunsBytes histogram\n",
		"# TYPE RunsLatencySeconds histogram\n",
		"# TYPE runs_hosted_tokens_total counter\n",
		"\nRunsFloat{" + `agentry_role="all",deployment_environment="dev",k="v",service_name="agentryd"} 1.5` + "\n",
		"\nRunsLive{" + `agentry_role="all",deployment_environment="dev",service_name="agentryd"} 3` + "\n",
		"\nRunsFloatLive{" + `agentry_role="all",deployment_environment="dev",service_name="agentryd"} 0.25` + "\n",
		"\nRunsIntGauge{" + `agentry_role="all",deployment_environment="dev",k="v",service_name="agentryd"} 9` + "\n",
		`service_name="agentryd",v="pos"} +Inf` + "\n",
		`service_name="agentryd",v="neg"} -Inf` + "\n",
		`service_name="agentryd",v="nan"} NaN` + "\n",
		`service_name="agentryd",v="frac"} 0.125` + "\n",
		"\nRunsBytes_count{" + `agentry_role="all",deployment_environment="dev",k="v",service_name="agentryd"} 2` + "\n",
		"\nRunsBytes_sum{" + `agentry_role="all",deployment_environment="dev",k="v",service_name="agentryd"} 20005` + "\n",
		`RunsBytes_bucket{agentry_role="all",deployment_environment="dev",k="v",le="+Inf",service_name="agentryd"} 2` + "\n",
		`RunsBytes_bucket{agentry_role="all",deployment_environment="dev",k="v",le="10000",service_name="agentryd"} 1` + "\n",
		`runs_hosted_tokens_total{_lives="1",a_b_c="x\\y\"z\nw",agentry_role="all",deployment_environment="dev",service_name="agentryd"} 4` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition lacks %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "# HELP RunsLive") {
		t.Error("an instrument with no description got a HELP line")
	}
	// An extension's attribute named le cannot add a second le to a bucket
	// line: the series' own wins and the label appears once.
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "RunsLatencySeconds_bucket{") && (len(regexp.MustCompile(`[{,]le="`).FindAllString(l, -1)) != 1 || !strings.Contains(l, `le="own"`)) {
			t.Errorf("bucket line with a series attribute named le: %s", l)
		}
	}
	// The core's own meter is the core's scope: an instrument created on it
	// is rendered ahead of an extension's of the same name, whatever the
	// extension's name sorts as.
	ext, _ := m.ExtensionMeter("aaa").Int64Counter("CoreExtra")
	ext.Add(ctx, 99)
	own, _ := m.Meter().Int64Counter("CoreExtra")
	own.Add(ctx, 5)
	if got := sampleValue(t, gather(t, m), "CoreExtra", ""); got != "5" {
		t.Errorf("CoreExtra = %q, want the core scope's 5 ahead of an extension's 99", got)
	}
}

// An extension that names an instrument after one of the core's cannot
// change the core's series or break the scrape: the core's is rendered and
// the extension's dropped, whatever order the SDK hands the scopes over.
func TestExtensionCannotShadowACoreName(t *testing.T) {
	m := newTestMetrics(t)
	m.RecordPublishSubmitted(t.Context())
	c, err := m.ExtensionMeter("aaa").Int64Counter("PublishSubmitted")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	c.Add(t.Context(), 99)
	for range 5 {
		out := gather(t, m)
		if n := strings.Count(out, "# TYPE PublishSubmitted "); n != 1 {
			t.Fatalf("PublishSubmitted declared %d times:\n%s", n, out)
		}
		if got := sampleValue(t, out, "PublishSubmitted", ""); got != "1" {
			t.Fatalf("PublishSubmitted = %q, want the core's 1", got)
		}
	}
}

// With an OTLP endpoint, an extension's instrument leaves with the core's.
func TestExtensionInstrumentLeavesThroughOTLP(t *testing.T) {
	bodies := make(chan []byte, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	m, err := New(t.Context(), Config{OTLPEndpoint: srv.URL, ExportInterval: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, err := m.ExtensionMeter("runs").Int64Counter("RunsHostedTokens")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	c.Add(t.Context(), 7)
	// Shutdown flushes the periodic reader once.
	if err := m.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case b := <-bodies:
		if !bytes.Contains(b, []byte("RunsHostedTokens")) || !bytes.Contains(b, []byte(extensionScope("runs"))) {
			t.Fatal("the OTLP export did not carry the extension's instrument under its scope")
		}
		// The scope is the documented one: the core's, then /x/ and the name.
		if !bytes.Contains(b, []byte("github.com/blaktron/agentry/internal/metrics/x/runs")) {
			t.Fatal("the extension's scope is not <core scope>/x/<name>")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was exported")
	}
}

// A nil *Metrics still hands an extension a usable meter.
func TestNilMetricsHandsANoOpExtensionMeter(t *testing.T) {
	var m *Metrics
	mt := m.ExtensionMeter("runs")
	if mt == nil {
		t.Fatal("nil Metrics returned a nil extension meter")
	}
	c, err := mt.Int64Counter("RunsHostedTokens")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	c.Add(t.Context(), 1)
}

// A family is dropped when any of its sample names is taken, so an
// extension's counter named after a core histogram's _count series cannot
// add a second sample of it.
func TestExtensionCannotShadowAHistogramSeries(t *testing.T) {
	m := newTestMetrics(t)
	m.RecordGitCloneFirstByte(t.Context(), time.Second)
	c, err := m.ExtensionMeter("aaa").Int64Counter("GitCloneFirstByteSeconds_count")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	c.Add(t.Context(), 99)
	out := gather(t, m)
	if n := strings.Count(out, "\nGitCloneFirstByteSeconds_count"); n != 1 {
		t.Fatalf("GitCloneFirstByteSeconds_count has %d samples:\n%s", n, out)
	}
	if got := sampleValue(t, out, "GitCloneFirstByteSeconds_count", ""); got != "1" {
		t.Errorf("GitCloneFirstByteSeconds_count = %q, want the core's 1", got)
	}

	// The same for the other two series of a histogram.
	for _, suffix := range []string{"_sum", "_bucket"} {
		sc, err := m.ExtensionMeter("aaa").Int64Counter("GitCloneFirstByteSeconds" + suffix)
		if err != nil {
			t.Fatalf("counter: %v", err)
		}
		sc.Add(t.Context(), 99)
	}
	out = gather(t, m)
	if strings.Contains(out, "# TYPE GitCloneFirstByteSeconds_sum") || strings.Contains(out, "# TYPE GitCloneFirstByteSeconds_bucket") {
		t.Fatalf("an extension declared a histogram series of the core:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "GitCloneFirstByteSeconds_bucket{") && !strings.Contains(l, "le=") {
			t.Errorf("an extension's sample joined the core's buckets: %s", l)
		}
		if strings.HasPrefix(l, "GitCloneFirstByteSeconds_sum{") && strings.HasSuffix(l, " 99") {
			t.Errorf("an extension's sample replaced the core's sum: %s", l)
		}
	}

	// A histogram of an extension reserves its series names too, whichever
	// integer or float kind it is, and extensions are considered in name
	// order: the first one to take a name keeps it.
	h, err := m.ExtensionMeter("aaa").Int64Histogram("Taken")
	if err != nil {
		t.Fatal(err)
	}
	h.Record(t.Context(), 1)
	late, err := m.ExtensionMeter("bbb").Int64Counter("Taken_count")
	if err != nil {
		t.Fatal(err)
	}
	late.Add(t.Context(), 7)
	a, _ := m.ExtensionMeter("aaa").Int64Counter("Clash")
	z, _ := m.ExtensionMeter("zzz").Int64Counter("Clash")
	z.Add(t.Context(), 2)
	a.Add(t.Context(), 1)
	for range 5 {
		out = gather(t, m)
		if n := strings.Count(out, "\nTaken_count{"); n != 1 {
			t.Fatalf("Taken_count has %d samples:\n%s", n, out)
		}
		if got := sampleValue(t, out, "Taken_count", ""); got != "1" {
			t.Fatalf("Taken_count = %q, want the histogram's 1", got)
		}
		if got := sampleValue(t, out, "Clash", ""); got != "1" {
			t.Fatalf("Clash = %q, want the first extension's 1", got)
		}
	}
}

// An extension's attribute named like a resource label cannot relabel the
// process or repeat the label, which would make the scrape invalid.
func TestASeriesAttributeNeverOverridesAResourceLabel(t *testing.T) {
	m := newTestMetrics(t)
	c, err := m.ExtensionMeter("runs").Int64Counter("RunsThings")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	c.Add(t.Context(), 1, metric.WithAttributes(attribute.String("service.name", "other"), attribute.String("kind", "run")))
	out := gather(t, m)
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "RunsThings{") {
			line = l
		}
	}
	if line != `RunsThings{agentry_role="all",deployment_environment="dev",kind="run",service_name="agentryd"} 1` {
		t.Fatalf("the series line is %q", line)
	}
}

// The daily MCP sweep: every run is counted with its outcome, and the alerts
// it opened are counted without a label, and not at all when it opened none.
func TestMCPSweepCountsRunsAndOpenedAlerts(t *testing.T) {
	m := newTestMetrics(t)
	ctx := t.Context()
	m.RecordMCPSweep(ctx, 0, nil)
	out := gather(t, m)
	if got := exact(t, out, "McpSweepRuns", map[string]string{"outcome": "ok"}); got != "1" {
		t.Errorf("McpSweepRuns{ok} = %q, want 1", got)
	}
	absent(t, out, "McpDependencyAlertsOpened")

	m.RecordMCPSweep(ctx, 3, nil)
	m.RecordMCPSweep(ctx, 2, errors.New("registry unreachable"))
	out = gather(t, m)
	if got := exact(t, out, "McpSweepRuns", map[string]string{"outcome": "ok"}); got != "2" {
		t.Errorf("McpSweepRuns{ok} = %q, want 2", got)
	}
	if got := exact(t, out, "McpSweepRuns", map[string]string{"outcome": "error"}); got != "1" {
		t.Errorf("McpSweepRuns{error} = %q, want 1", got)
	}
	if got := exact(t, out, "McpDependencyAlertsOpened", nil); got != "5" {
		t.Errorf("McpDependencyAlertsOpened = %q, want 5", got)
	}
}

// The model-input routes: calls by op and verdict, and the judge's input
// tokens by op, as counts and never a price.
func TestModelInputCountsCallsAndJudgeTokens(t *testing.T) {
	m := newTestMetrics(t)
	ctx := t.Context()
	m.RecordModelInput(ctx, "scan", "pass", 120)
	m.RecordModelInput(ctx, "scan", "withheld", 30)
	m.RecordModelInput(ctx, "scan", "pass", 0)
	m.RecordModelInput(ctx, "search", "not_scanned", 0)
	out := gather(t, m)
	for _, c := range []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{"ModelInputCalls", map[string]string{"op": "scan", "verdict": "pass"}, "2"},
		{"ModelInputCalls", map[string]string{"op": "scan", "verdict": "withheld"}, "1"},
		{"ModelInputCalls", map[string]string{"op": "search", "verdict": "not_scanned"}, "1"},
		{"ModelInputJudgeTokens", map[string]string{"op": "scan"}, "150"},
		{"ModelInputJudgeTokens", map[string]string{"op": "search"}, "0"},
	} {
		if got := exact(t, out, c.name, c.labels); got != c.want {
			t.Errorf("%s%v = %q, want %q", c.name, c.labels, got, c.want)
		}
	}
}
