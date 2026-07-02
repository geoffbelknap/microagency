package mcp

import "testing"

func TestMetricsImpact(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	// a parked (reffed) result — 1 MiB held off-context
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Reffed: true, Bytes: 1 << 20})
	// an inline result — 500 bytes into context
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", OutputBytes: 500})
	// a materialize — the OPERATOR pulled data out-of-band; must NOT count as context
	s.putRun(s.nextRunID(), runRecord{Kind: "materialize", OutputBytes: 9999})

	imp := s.Metrics().Impact
	if imp.Calls != 2 {
		t.Fatalf("calls = %d, want 2 (materialize excluded)", imp.Calls)
	}
	if imp.Parked != 1 {
		t.Fatalf("parked = %d, want 1", imp.Parked)
	}
	if imp.BytesKeptOut != 1<<20 {
		t.Fatalf("bytes_kept_out = %d, want %d", imp.BytesKeptOut, 1<<20)
	}
	if imp.BytesToContext != 500 {
		t.Fatalf("bytes_to_context = %d, want 500 (materialize must be excluded)", imp.BytesToContext)
	}
	if imp.EstTokensSaved != (1<<20)/4 {
		t.Fatalf("est_tokens_saved = %d", imp.EstTokensSaved)
	}
	if imp.ReductionPercent < 99.9 { // 1MiB kept out vs 500B in → ~99.95%
		t.Fatalf("reduction_percent = %.2f, want ~99.95", imp.ReductionPercent)
	}
}
