package metrics

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// promContentType is the Prometheus text exposition format, version 0.0.4.
const promContentType = "text/plain; version=0.0.4; charset=utf-8"

// Gather collects the current values from the manual reader and renders them
// in the Prometheus text exposition format.
//
// The rendering is done here rather than by go.opentelemetry.io/otel/exporters/
// prometheus for two reasons. First, that exporter would pull the whole
// prometheus/client_golang tree in for one HTTP handler. Second — and this is
// the one that matters operationally — it rewrites instrument names on the way
// out (unit suffixes, `_total` on counters), so `QueueAgeSeconds` in a
// CloudWatch alarm and the same series scraped from a self-hosted box would no
// longer share a name. One vocabulary across both backends is worth ~120 lines
// of encoder.
func (m *Metrics) Gather(ctx context.Context) ([]byte, error) {
	if m == nil || m.scrape == nil {
		return nil, nil
	}
	var rm metricdata.ResourceMetrics
	if err := m.scrape.Collect(ctx, &rm); err != nil {
		return nil, err
	}

	// Resource attributes become labels on every series, the way the OTLP
	// resource becomes EMF dimensions on the CloudWatch side.
	base := labelsFromSet(rm.Resource.Set())

	// The core's scope first, then the extensions' by scope name (the SDK
	// hands scopes over in no fixed order). A name already rendered is not
	// rendered again: two TYPE lines for one name would make the whole
	// scrape invalid, and the core's series must not change because an
	// extension chose one of its names (agentry#777).
	scopes := rm.ScopeMetrics
	sort.SliceStable(scopes, func(i, j int) bool {
		a, b := scopes[i].Scope.Name, scopes[j].Scope.Name
		if (a == scopeName) != (b == scopeName) {
			return a == scopeName
		}
		return a < b
	})
	seen := map[string]bool{}
	var buf bytes.Buffer
	for _, sm := range scopes {
		for _, md := range sm.Metrics {
			name := sanitizeName(md.Name)
			if seen[name] {
				continue
			}
			seen[name] = true
			writeMetric(&buf, md, base)
		}
	}
	return buf.Bytes(), nil
}

// label is one rendered name="value" pair, kept apart from its siblings so
// series labels can be merged with the resource labels and sorted as a unit.
type label struct{ name, value string }

func labelsFromSet(set *attribute.Set) []label {
	if set == nil {
		return nil
	}
	out := make([]label, 0, set.Len())
	for _, kv := range set.ToSlice() {
		out = append(out, label{name: sanitizeLabel(string(kv.Key)), value: kv.Value.String()})
	}
	return out
}

func writeMetric(buf *bytes.Buffer, md metricdata.Metrics, base []label) {
	name := sanitizeName(md.Name)
	switch data := md.Data.(type) {
	case metricdata.Sum[int64]:
		writeHeader(buf, name, md.Description, sumType(data.IsMonotonic))
		for _, dp := range data.DataPoints {
			writeSample(buf, name, "", base, labelsFromSet(&dp.Attributes), formatInt(dp.Value))
		}
	case metricdata.Sum[float64]:
		writeHeader(buf, name, md.Description, sumType(data.IsMonotonic))
		for _, dp := range data.DataPoints {
			writeSample(buf, name, "", base, labelsFromSet(&dp.Attributes), formatFloat(dp.Value))
		}
	case metricdata.Gauge[int64]:
		writeHeader(buf, name, md.Description, "gauge")
		for _, dp := range data.DataPoints {
			writeSample(buf, name, "", base, labelsFromSet(&dp.Attributes), formatInt(dp.Value))
		}
	case metricdata.Gauge[float64]:
		writeHeader(buf, name, md.Description, "gauge")
		for _, dp := range data.DataPoints {
			writeSample(buf, name, "", base, labelsFromSet(&dp.Attributes), formatFloat(dp.Value))
		}
	case metricdata.Histogram[int64]:
		writeHeader(buf, name, md.Description, "histogram")
		for _, dp := range data.DataPoints {
			writeHistogram(buf, name, base, labelsFromSet(&dp.Attributes),
				dp.Bounds, dp.BucketCounts, dp.Count, float64(dp.Sum))
		}
	case metricdata.Histogram[float64]:
		writeHeader(buf, name, md.Description, "histogram")
		for _, dp := range data.DataPoints {
			writeHistogram(buf, name, base, labelsFromSet(&dp.Attributes),
				dp.Bounds, dp.BucketCounts, dp.Count, dp.Sum)
		}
	}
	// Aggregations this server never creates (exponential histograms, summaries)
	// fall through unrendered rather than being approximated into something a
	// reader would take at face value.
}

func sumType(monotonic bool) string {
	if monotonic {
		return "counter"
	}
	return "gauge"
}

func writeHeader(buf *bytes.Buffer, name, help, typ string) {
	if help != "" {
		fmt.Fprintf(buf, "# HELP %s %s\n", name, escapeHelp(help))
	}
	fmt.Fprintf(buf, "# TYPE %s %s\n", name, typ)
}

// writeSample renders one series line. suffix is appended to the metric name
// (histograms use _bucket/_sum/_count); extra carries per-sample labels such
// as a bucket's le=.
func writeSample(buf *bytes.Buffer, name, suffix string, base, series []label, value string, extra ...label) {
	buf.WriteString(name)
	buf.WriteString(suffix)
	writeLabels(buf, base, series, extra)
	buf.WriteByte(' ')
	buf.WriteString(value)
	buf.WriteByte('\n')
}

func writeLabels(buf *bytes.Buffer, base, series []label, extra []label) {
	all := make([]label, 0, len(base)+len(series)+len(extra))
	all = append(all, base...)
	all = append(all, series...)
	all = append(all, extra...)
	if len(all) == 0 {
		return
	}
	// Sorted so a scrape of unchanged state renders byte-identically — which
	// is what makes the encoder testable at all.
	sort.SliceStable(all, func(i, j int) bool { return all[i].name < all[j].name })
	buf.WriteByte('{')
	for i, l := range all {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(l.name)
		buf.WriteString(`="`)
		buf.WriteString(escapeLabelValue(l.value))
		buf.WriteByte('"')
	}
	buf.WriteByte('}')
}

func writeHistogram(buf *bytes.Buffer, name string, base, series []label, bounds []float64, counts []uint64, count uint64, sum float64) {
	// Prometheus buckets are cumulative; OTel's are not.
	var cumulative uint64
	for i, bound := range bounds {
		if i < len(counts) {
			cumulative += counts[i]
		}
		writeSample(buf, name, "_bucket", base, series, formatUint(cumulative),
			label{name: "le", value: formatFloat(bound)})
	}
	// The final +Inf bucket must equal the observation count, including the
	// overflow bucket OTel keeps past the last boundary.
	writeSample(buf, name, "_bucket", base, series, formatUint(count),
		label{name: "le", value: "+Inf"})
	writeSample(buf, name, "_sum", base, series, formatFloat(sum))
	writeSample(buf, name, "_count", base, series, formatUint(count))
}

func formatInt(v int64) string   { return strconv.FormatInt(v, 10) }
func formatUint(v uint64) string { return strconv.FormatUint(v, 10) }

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// sanitizeName coerces an instrument name to the Prometheus name grammar
// ([a-zA-Z_:][a-zA-Z0-9_:]*). The names this package uses are already valid;
// this exists so a future instrument with a dot cannot emit a malformed
// exposition that breaks the whole scrape.
func sanitizeName(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == ':':
			b.WriteRune(r)
		case r >= '0' && r <= '9' && i > 0:
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// sanitizeLabel is sanitizeName without ':', which is reserved in label names.
func sanitizeLabel(s string) string {
	return strings.ReplaceAll(sanitizeName(s), ":", "_")
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}
