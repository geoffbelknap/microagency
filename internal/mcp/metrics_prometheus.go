package mcp

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// PrometheusContentType is the exposition-format content type for Prometheus /
// OpenMetrics text (v0.0.4), served at GET /admin/metrics/prometheus.
const PrometheusContentType = "text/plain; version=0.0.4; charset=utf-8"

// Prometheus renders the metrics as Prometheus text-exposition format, so an
// existing Prometheus/OTel scrape pipeline can pull them instead of parsing the
// JSON. TotalRuns and the impact figures are all-time cumulative counters; the
// per-substrate/per-engine breakdown is over the recent window, so those are
// gauges (not monotonic), and labelled honestly.
func (m MetricsSummary) Prometheus() string {
	var b strings.Builder
	scalar := func(name, typ, help string, val float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %s\n", name, help, name, typ, name, promNum(val))
	}
	scalar("microagency_runs_total", "counter", "All-time recorded runs (proxied calls + reductions).", float64(m.TotalRuns))
	scalar("microagency_calls_total", "counter", "All-time calls counted toward impact (excludes operator materialize).", float64(m.Impact.Calls))
	scalar("microagency_parked_total", "counter", "All-time results held off-context as a reference.", float64(m.Impact.Parked))
	scalar("microagency_bytes_kept_out_total", "counter", "All-time bytes kept OUT of the model's context.", float64(m.Impact.BytesKeptOut))
	scalar("microagency_bytes_to_context_total", "counter", "All-time bytes returned INTO the model's context.", float64(m.Impact.BytesToContext))
	scalar("microagency_est_tokens_saved_total", "counter", "All-time estimated tokens saved (bytes_kept_out / 4).", float64(m.Impact.EstTokensSaved))
	scalar("microagency_fields_protected_total", "counter", "All-time sensitive field values redacted or tokenized.", float64(m.Impact.FieldsProtected))
	scalar("microagency_reduction_percent", "gauge", "bytes_kept_out / (bytes_kept_out + bytes_to_context) * 100.", m.Impact.ReductionPercent)

	// Per-substrate breakdown (recent window → gauges).
	subs := sortedKeys(m.BySubstrate)
	family(&b, "microagency_substrate_runs", "gauge", "Reduce runs on a substrate (recent window).", subs, func(k string) float64 {
		return float64(m.BySubstrate[k].Runs)
	}, "substrate")
	family(&b, "microagency_substrate_p50_latency_ms", "gauge", "Median reduce latency by substrate (recent window).", subs, func(k string) float64 {
		return float64(m.BySubstrate[k].P50LatencyMs)
	}, "substrate")
	family(&b, "microagency_substrate_input_bytes", "gauge", "Bytes fetched by substrate (recent window).", subs, func(k string) float64 {
		return float64(m.BySubstrate[k].InputBytesTotal)
	}, "substrate")
	family(&b, "microagency_substrate_output_bytes", "gauge", "Bytes returned by substrate (recent window).", subs, func(k string) float64 {
		return float64(m.BySubstrate[k].OutputBytesTotal)
	}, "substrate")

	// Per-engine breakdown (recent window → gauge).
	engs := make([]string, 0, len(m.ByEngine))
	for k := range m.ByEngine {
		engs = append(engs, k)
	}
	sort.Strings(engs)
	family(&b, "microagency_engine_runs", "gauge", "Reduce runs by wasm engine (recent window).", engs, func(k string) float64 {
		return float64(m.ByEngine[k])
	}, "engine")

	return b.String()
}

// family emits one HELP/TYPE header plus a labelled sample per key.
func family(b *strings.Builder, name, typ, help string, keys []string, val func(string) float64, label string) {
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	for _, k := range keys {
		fmt.Fprintf(b, "%s{%s=\"%s\"} %s\n", name, label, promLabel(k), promNum(val(k)))
	}
}

func sortedKeys(m map[string]*SubstrateStats) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func promNum(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// promLabel escapes a label value per the exposition format (\ " and newline).
func promLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}
