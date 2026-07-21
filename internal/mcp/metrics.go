package mcp

import "sort"

// MetricsSummary aggregates run impact — the data behind the three claims:
// routing mix (is the cheap path actually used?), latency by substrate (is wasm
// cheaper than the microVM?), and data minimization (how much fetched data the
// query kept OUT of the model's context).
type MetricsSummary struct {
	TotalRuns   int                        `json:"total_runs"`
	BySubstrate map[string]*SubstrateStats `json:"by_substrate"`
	ByEngine    map[string]int             `json:"by_engine"`
	Impact      Impact                     `json:"impact"`
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
	s.mu.Lock()
	defer s.mu.Unlock()
	m := MetricsSummary{
		// TotalRuns and Impact are ALL-TIME cumulative (they survive the bounded
		// window's eviction), accumulated as runs are recorded and rebuilt from the
		// durable log on restart. The by-substrate/engine/latency breakdown below is
		// over the retained recent window — a bounded scan, and recent latency is the
		// useful signal anyway.
		TotalRuns:   s.runsTotal,
		Impact:      s.impact,
		BySubstrate: map[string]*SubstrateStats{},
		ByEngine:    map[string]int{},
	}
	lat := map[string][]int64{}
	for _, rec := range s.runs {
		// by_substrate is "where reduce ran" — only reduce runs land on a substrate
		// (wasm/microvm). Proxy calls have none, so they don't belong in this
		// breakdown (otherwise they pile up under a bogus "unknown" substrate).
		if sub := rec.Substrate; sub != "" {
			st := m.BySubstrate[sub]
			if st == nil {
				st = &SubstrateStats{}
				m.BySubstrate[sub] = st
			}
			st.Runs++
			st.InputBytesTotal += rec.InputBytes
			st.OutputBytesTotal += rec.OutputBytes
			lat[sub] = append(lat[sub], rec.LatencyMs)
		}
		if rec.Engine != "" {
			m.ByEngine[rec.Engine]++
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
	return m
}

func median(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[len(v)/2]
}
