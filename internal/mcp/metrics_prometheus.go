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
	scalar("microagency_runs_total", "counter", "All-time recorded discoveries, proxied calls, and reductions.", float64(m.TotalRuns))
	scalar("microagency_calls_total", "counter", "All-time calls counted toward impact (excludes operator materialize).", float64(m.Impact.Calls))
	scalar("microagency_parked_total", "counter", "All-time results held off-context as a reference.", float64(m.Impact.Parked))
	scalar("microagency_bytes_kept_out_total", "counter", "All-time bytes kept OUT of the model's context.", float64(m.Impact.BytesKeptOut))
	scalar("microagency_bytes_to_context_total", "counter", "All-time bytes returned INTO the model's context.", float64(m.Impact.BytesToContext))
	scalar("microagency_est_tokens_saved_total", "counter", "All-time estimated tokens saved (bytes_kept_out / 4).", float64(m.Impact.EstTokensSaved))
	scalar("microagency_fields_protected_total", "counter", "All-time sensitive field values redacted or tokenized.", float64(m.Impact.FieldsProtected))
	scalar("microagency_reduction_percent", "gauge", "bytes_kept_out / (bytes_kept_out + bytes_to_context) * 100.", m.Impact.ReductionPercent)

	// Exact context-cost counters. These deliberately use no task/user/tool labels:
	// the metric cardinality is fixed regardless of tenant traffic.
	scalar("microagency_context_bytes_total", "counter", "Exact serialized tool-result bytes returned into model context.", float64(m.Context.BytesToContext))
	scalar("microagency_context_est_tokens_total", "counter", "Approximate context tokens (exact serialized bytes / 4; model tokenizer is not observed).", float64(m.Context.EstTokensToContext))
	scalar("microagency_discovery_calls_total", "counter", "Measured find_tools calls.", float64(m.Context.Discovery.Calls))
	scalar("microagency_discovery_query_bytes_total", "counter", "Bytes in find_tools query strings; query contents are not retained.", float64(m.Context.Discovery.QueryBytes))
	scalar("microagency_discovery_context_bytes_total", "counter", "Exact serialized find_tools result bytes returned into context.", float64(m.Context.Discovery.ContextBytes))
	scalar("microagency_discovery_full_schema_entries_total", "counter", "Full schema entries returned by find_tools.", float64(m.Context.Discovery.FullSchemaEntries))
	scalar("microagency_discovery_schema_digest_entries_total", "counter", "Schema-digest entries returned by find_tools.", float64(m.Context.Discovery.SchemaDigestEntries))
	scalar("microagency_discovery_summarized_entries_total", "counter", "Summarized entries returned by find_tools.", float64(m.Context.Discovery.SummarizedEntries))
	scalar("microagency_discovery_omitted_entries_total", "counter", "Entries omitted by find_tools context budgets.", float64(m.Context.Discovery.OmittedEntries))
	scalar("microagency_invocation_calls_total", "counter", "Measured call_tool invocations.", float64(m.Context.Invocation.Calls))
	scalar("microagency_invocation_raw_upstream_bytes_total", "counter", "Raw upstream result bytes processed by call_tool.", float64(m.Context.Invocation.RawUpstreamBytes))
	scalar("microagency_invocation_parked_bytes_total", "counter", "Invocation result bytes parked behind references.", float64(m.Context.Invocation.ParkedBytes))
	scalar("microagency_invocation_minimized_bytes_total", "counter", "Serialized invocation bytes removed by field minimization.", float64(m.Context.Invocation.MinimizedBytes))
	scalar("microagency_invocation_context_bytes_total", "counter", "Exact serialized call_tool result bytes returned into context.", float64(m.Context.Invocation.ContextBytes))
	scalar("microagency_reduce_calls_total", "counter", "Measured reduce executions.", float64(m.Context.Reduction.Calls))
	scalar("microagency_reduce_input_bytes_total", "counter", "Bytes processed off-context by reduce.", float64(m.Context.Reduction.InputBytes))
	scalar("microagency_reduce_raw_output_bytes_total", "counter", "Raw reducer output bytes before result shaping.", float64(m.Context.Reduction.RawOutputBytes))
	scalar("microagency_reduce_parked_bytes_total", "counter", "Reducer output bytes parked behind references.", float64(m.Context.Reduction.ParkedBytes))
	scalar("microagency_reduce_context_bytes_total", "counter", "Exact serialized reduce result bytes returned into context.", float64(m.Context.Reduction.ContextBytes))

	stageLatency := map[string]float64{
		"discovery":  float64(m.Context.Discovery.P50LatencyMs),
		"invocation": float64(m.Context.Invocation.P50LatencyMs),
		"reduction":  float64(m.Context.Reduction.P50LatencyMs),
	}
	family(&b, "microagency_context_stage_p50_latency_ms", "gauge", "Median latency by fixed context stage (recent window).", []string{"discovery", "invocation", "reduction"}, func(k string) float64 {
		return stageLatency[k]
	}, "stage")
	scalar("microagency_correlated_tasks", "gauge", "Tasks represented by bounded opaque task ids in the recent window.", float64(m.Context.Tasks.CorrelatedTasks))
	scalar("microagency_task_calls", "gauge", "Calls associated with correlated tasks in the recent window.", float64(m.Context.Tasks.Calls))
	scalar("microagency_task_schema_escalations", "gauge", "Exact-schema discovery escalations in correlated tasks (recent window).", float64(m.Context.Tasks.SchemaEscalations))
	scalar("microagency_task_separate_invoke_reduce_trips", "gauge", "Separate call_tool then reduce trips in correlated tasks (recent window).", float64(m.Context.Tasks.SeparateInvokeReduceTrips))
	scalar("microagency_task_fused_invoke_reduce_trips", "gauge", "Fused invoke-and-reduce trips in correlated tasks (recent window).", float64(m.Context.Tasks.FusedInvokeReduceTrips))
	scalar("microagency_task_avg_discovery_calls", "gauge", "Average find_tools calls per correlated task (recent window).", m.Context.Tasks.AvgDiscoveryCallsPerTask)
	scalar("microagency_task_avg_schema_escalations", "gauge", "Average exact-schema escalations per correlated task (recent window).", m.Context.Tasks.AvgSchemaEscalationsPerTask)

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
