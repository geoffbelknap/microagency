package mcp

import (
	"sort"
	"strings"
)

// MetricsSummary aggregates run impact — the data behind the three claims:
// routing mix (is the cheap path actually used?), latency by substrate (is wasm
// cheaper than the microVM?), and data minimization (how much fetched data the
// query kept OUT of the model's context).
type MetricsSummary struct {
	TotalRuns   int                        `json:"total_runs"`
	BySubstrate map[string]*SubstrateStats `json:"by_substrate"`
	ByEngine    map[string]int             `json:"by_engine"`
	Impact      Impact                     `json:"impact"`
	Context     ContextCost                `json:"context"`
}

// ContextCost separates the two context costs a gateway can control: discovery
// schemas and tool/reduction responses. Byte counters are exact and all-time;
// p50 latency and correlated-task figures use the bounded recent run window.
// EstTokensToContext is intentionally only bytes/4: tokenization belongs to the
// downstream model and is not observable here.
type ContextCost struct {
	BytesToContext     int64          `json:"bytes_to_context"`
	EstTokensToContext int64          `json:"est_tokens_to_context"`
	Discovery          DiscoveryCost  `json:"discovery"`
	Invocation         InvocationCost `json:"invocation"`
	Reduction          ReductionCost  `json:"reduction"`
	Tasks              TaskCost       `json:"tasks"`
}

type DiscoveryCost struct {
	Calls               int   `json:"calls"`
	QueryBytes          int64 `json:"query_bytes"`
	ContextBytes        int64 `json:"context_bytes"`
	FullSchemaEntries   int64 `json:"full_schema_entries"`
	SchemaDigestEntries int64 `json:"schema_digest_entries"`
	SummarizedEntries   int64 `json:"summarized_entries"`
	OmittedEntries      int64 `json:"omitted_entries"`
	P50LatencyMs        int64 `json:"p50_latency_ms"`
}

type InvocationCost struct {
	Calls            int   `json:"calls"`
	RawUpstreamBytes int64 `json:"raw_upstream_bytes"`
	ParkedBytes      int64 `json:"parked_bytes"`
	MinimizedBytes   int64 `json:"minimized_bytes"`
	ContextBytes     int64 `json:"context_bytes"`
	P50LatencyMs     int64 `json:"p50_latency_ms"`
}

type ReductionCost struct {
	Calls          int   `json:"calls"`
	InputBytes     int64 `json:"input_bytes"`
	RawOutputBytes int64 `json:"raw_output_bytes"`
	ParkedBytes    int64 `json:"parked_bytes"`
	ContextBytes   int64 `json:"context_bytes"`
	P50LatencyMs   int64 `json:"p50_latency_ms"`
}

// TaskCost aggregates only valid, bounded task_id values and never exports the
// ids themselves. That keeps Prometheus cardinality fixed and prevents an opaque
// correlation convenience from becoming a user-identity label.
type TaskCost struct {
	CorrelatedTasks             int     `json:"correlated_tasks"`
	Calls                       int     `json:"calls"`
	DiscoveryCalls              int     `json:"discovery_calls"`
	SchemaEscalations           int     `json:"schema_escalations"`
	Invocations                 int     `json:"invocations"`
	Reductions                  int     `json:"reductions"`
	SeparateInvokeReduceTrips   int     `json:"separate_invoke_reduce_trips"`
	FusedInvokeReduceTrips      int     `json:"fused_invoke_reduce_trips"`
	AvgDiscoveryCallsPerTask    float64 `json:"avg_discovery_calls_per_task"`
	AvgSchemaEscalationsPerTask float64 `json:"avg_schema_escalations_per_task"`
}

// Impact is the efficiency headline: how much data microagency kept OUT of the
// model's context (the token saving) versus what it returned into context. Bytes
// are measured precisely; tokens are a model-agnostic estimate (~bytes/4). This is
// the data that says whether the gateway does anything beyond privacy/security.
//
// Honest scope: this measures what microagency keeps out of context — the precise,
// in-product saving. It does NOT measure the downstream model-turn speedup (smaller
// context → faster inference), which happens in the client and isn't observable
// here. Latency below is microagency's OWN processing time (overhead), not the
// end-to-end turn time.
type Impact struct {
	Calls            int     `json:"calls"`             // recorded runs + proxied calls + reductions
	Parked           int     `json:"parked"`            // results held off-context as a <ref_>
	BytesKeptOut     int64   `json:"bytes_kept_out"`    // total bytes held off-context (never entered context)
	BytesToContext   int64   `json:"bytes_to_context"`  // total bytes returned INTO context (inline results + answers)
	EstTokensSaved   int64   `json:"est_tokens_saved"`  // BytesKeptOut / 4 (rough, model-agnostic)
	ReductionPercent float64 `json:"reduction_percent"` // BytesKeptOut / (BytesKeptOut + BytesToContext)
	// FieldsProtected is the total sensitive field values minimized (redacted or
	// tokenized) across all calls. This is the field-level-minimization impact —
	// separate from park/reduce, which is about bulk context reduction. A run can
	// return data INTO context (no park) yet still protect many fields.
	FieldsProtected int `json:"fields_protected"`
}

// SubstrateStats summarizes the runs that landed on one substrate.
type SubstrateStats struct {
	Runs             int   `json:"runs"`
	P50LatencyMs     int64 `json:"p50_latency_ms"`
	InputBytesTotal  int   `json:"input_bytes_total"`
	OutputBytesTotal int   `json:"output_bytes_total"`
	// MinimizationRatio is input/output bytes across runs that fetched data: how
	// many bytes were fetched per byte returned to the model. Only the wasm path
	// observes input bytes, so it's meaningful there (0 when no input was seen).
	MinimizationRatio float64 `json:"minimization_ratio"`
}

// Metrics aggregates the recorded runs by substrate and engine.
func (s *Server) Metrics() MetricsSummary {
	s.rs.mu.Lock()
	defer s.rs.mu.Unlock()
	m := MetricsSummary{
		// TotalRuns and Impact are ALL-TIME cumulative (they survive the bounded
		// window's eviction), accumulated as runs are recorded and rebuilt from the
		// durable log on restart. The by-substrate/engine/latency breakdown below is
		// over the retained recent window — a bounded scan, and recent latency is the
		// useful signal anyway.
		TotalRuns:   s.rs.total,
		Impact:      s.rs.impact,
		Context:     s.rs.context,
		BySubstrate: map[string]*SubstrateStats{},
		ByEngine:    map[string]int{},
	}
	lat := map[string][]int64{}
	stageLat := map[string][]int64{}
	type taskState struct {
		discovery int
		refs      map[string]bool
	}
	tasks := map[string]*taskState{}
	for _, id := range s.rs.order {
		rec, ok := s.rs.byID[id]
		if !ok {
			continue
		}
		// by_substrate is where reduction ran: standalone reduce or a declarative
		// transform fused into a proxied invocation.
		if sub := rec.Substrate; sub != "" {
			st := m.BySubstrate[sub]
			if st == nil {
				st = &SubstrateStats{}
				m.BySubstrate[sub] = st
			}
			st.Runs++
			inputBytes, outputBytes, latencyMs := rec.InputBytes, rec.OutputBytes, rec.LatencyMs
			if rec.FusedInvocation {
				inputBytes, outputBytes = rec.TransformInputBytes, rec.TransformOutputBytes
				latencyMs = rec.TransformLatencyMs
			}
			st.InputBytesTotal += inputBytes
			st.OutputBytesTotal += outputBytes
			lat[sub] = append(lat[sub], latencyMs)
		}
		if rec.Engine != "" {
			m.ByEngine[rec.Engine]++
		}
		if rec.Kind == "discovery" || rec.Kind == "proxy" || rec.Kind == "reduce" {
			stageLat[rec.Kind] = append(stageLat[rec.Kind], rec.LatencyMs)
		}
		if rec.TaskID == "" {
			continue
		}
		ts := tasks[rec.TaskID]
		if ts == nil {
			ts = &taskState{refs: map[string]bool{}}
			tasks[rec.TaskID] = ts
		}
		m.Context.Tasks.Calls++
		switch rec.Kind {
		case "discovery":
			if rec.ExactSchemaLookup && ts.discovery > 0 {
				m.Context.Tasks.SchemaEscalations++
			}
			ts.discovery++
			m.Context.Tasks.DiscoveryCalls++
		case "proxy":
			m.Context.Tasks.Invocations++
			if rec.FusedInvocation {
				m.Context.Tasks.FusedInvokeReduceTrips++
			}
			if rec.Reffed && rec.Ref != "" {
				ts.refs[rec.Ref] = true
			}
		case "reduce":
			m.Context.Tasks.Reductions++
			for _, source := range splitSources(rec.SourceID) {
				if ts.refs[source] {
					m.Context.Tasks.SeparateInvokeReduceTrips++
					break
				}
			}
		}
	}
	m.Impact.EstTokensSaved = m.Impact.BytesKeptOut / 4
	if total := m.Impact.BytesKeptOut + m.Impact.BytesToContext; total > 0 {
		m.Impact.ReductionPercent = float64(m.Impact.BytesKeptOut) / float64(total) * 100
	}
	for sub, st := range m.BySubstrate {
		st.P50LatencyMs = median(lat[sub])
		if st.InputBytesTotal > 0 && st.OutputBytesTotal > 0 {
			st.MinimizationRatio = float64(st.InputBytesTotal) / float64(st.OutputBytesTotal)
		}
	}
	m.Context.Discovery.P50LatencyMs = median(stageLat["discovery"])
	m.Context.Invocation.P50LatencyMs = median(stageLat["proxy"])
	m.Context.Reduction.P50LatencyMs = median(stageLat["reduce"])
	m.Context.EstTokensToContext = m.Context.BytesToContext / 4
	m.Context.Tasks.CorrelatedTasks = len(tasks)
	if len(tasks) > 0 {
		m.Context.Tasks.AvgDiscoveryCallsPerTask = float64(m.Context.Tasks.DiscoveryCalls) / float64(len(tasks))
		m.Context.Tasks.AvgSchemaEscalationsPerTask = float64(m.Context.Tasks.SchemaEscalations) / float64(len(tasks))
	}
	return m
}

func (s *Server) accumulateContextLocked(rec runRecord) {
	if !rec.ContextMeasured {
		return
	}
	contextBytes := int64(rec.OutputBytes)
	s.rs.context.BytesToContext += contextBytes
	switch rec.Kind {
	case "discovery":
		s.rs.context.Discovery.Calls++
		s.rs.context.Discovery.QueryBytes += int64(rec.InputBytes)
		s.rs.context.Discovery.ContextBytes += contextBytes
		s.rs.context.Discovery.FullSchemaEntries += int64(rec.FullSchemaEntries)
		s.rs.context.Discovery.SchemaDigestEntries += int64(rec.SchemaDigestEntries)
		s.rs.context.Discovery.SummarizedEntries += int64(rec.SummarizedEntries)
		s.rs.context.Discovery.OmittedEntries += int64(rec.OmittedEntries)
	case "proxy":
		s.rs.context.Invocation.Calls++
		s.rs.context.Invocation.RawUpstreamBytes += int64(rec.RawBytes)
		s.rs.context.Invocation.ParkedBytes += int64(rec.ParkedBytes)
		s.rs.context.Invocation.MinimizedBytes += int64(rec.MinimizedBytes)
		s.rs.context.Invocation.ContextBytes += contextBytes
	case "reduce":
		s.rs.context.Reduction.Calls++
		s.rs.context.Reduction.InputBytes += int64(rec.InputBytes)
		s.rs.context.Reduction.RawOutputBytes += int64(rec.RawBytes)
		s.rs.context.Reduction.ParkedBytes += int64(rec.ParkedBytes)
		s.rs.context.Reduction.ContextBytes += contextBytes
	}
}

func splitSources(source string) []string {
	parts := make([]string, 0, 1)
	for _, p := range strings.Split(source, ",") {
		if p = strings.TrimSpace(p); p != "" && p != "inline" {
			parts = append(parts, p)
		}
	}
	return parts
}

func median(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[len(v)/2]
}
