package mcp

import "testing"

// The in-memory run window is bounded — RunLog and the metrics breakdown scan only
// the recent window — while TotalRuns and the Impact totals stay ALL-TIME
// cumulative (they must survive eviction, since they're the product's headline
// numbers).
func TestRunWindowBoundedButTotalsCumulative(t *testing.T) {
	s := NewServer(fakeRunner{}, WithMaxRuns(10))
	for i := 0; i < 25; i++ {
		s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "t", Reffed: true, Bytes: 100})
	}

	log := s.RunLog()
	if len(log) != 10 {
		t.Fatalf("run window not bounded: RunLog has %d, want 10", len(log))
	}
	if log[0].RunID != "run_25" {
		t.Fatalf("RunLog should be newest-first: top = %q, want run_25", log[0].RunID)
	}
	// The oldest runs were evicted from the in-memory index.
	if _, ok := s.getRun("run_1"); ok {
		t.Fatal("run_1 should have been evicted from the window")
	}

	m := s.Metrics()
	if m.TotalRuns != 25 {
		t.Fatalf("Metrics.TotalRuns = %d, want 25 (all-time, not the window size)", m.TotalRuns)
	}
	if m.Impact.Calls != 25 || m.Impact.Parked != 25 || m.Impact.BytesKeptOut != 2500 {
		t.Fatalf("cumulative impact wrong after eviction: %+v", m.Impact)
	}
}

// Across a restart the totals are rebuilt from the durable log (complete), while
// the in-memory window stays bounded — replaying a long log doesn't reload it all.
func TestRunWindowCumulativeAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(fakeRunner{}, WithStateDir(dir), WithMaxRuns(10))
	for i := 0; i < 25; i++ {
		s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "t", Reffed: true, Bytes: 100})
	}

	// Restart: a fresh server replays the log. maxRuns is applied before the replay.
	s2 := NewServer(fakeRunner{}, WithStateDir(dir), WithMaxRuns(10))
	if got := len(s2.RunLog()); got != 10 {
		t.Fatalf("replayed window not bounded: %d, want 10", got)
	}
	m := s2.Metrics()
	if m.TotalRuns != 25 {
		t.Fatalf("replayed TotalRuns = %d, want 25 (rebuilt from the durable log)", m.TotalRuns)
	}
	if m.Impact.Calls != 25 || m.Impact.BytesKeptOut != 2500 {
		t.Fatalf("replayed cumulative impact wrong: %+v", m.Impact)
	}
	// New run ids still continue past the whole history (no collision).
	if id := s2.nextRunID(); id != "run_26" {
		t.Fatalf("run-id counter not restored past history: next = %q, want run_26", id)
	}
}
