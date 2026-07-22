package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsPrometheusRendering(t *testing.T) {
	m := MetricsSummary{
		TotalRuns: 5,
		Impact:    Impact{Calls: 5, Parked: 2, BytesKeptOut: 1 << 20, EstTokensSaved: 262144, FieldsProtected: 4, ReductionPercent: 87.5},
		BySubstrate: map[string]*SubstrateStats{
			"wasm": {Runs: 3, P50LatencyMs: 12, InputBytesTotal: 100, OutputBytesTotal: 20},
		},
		ByEngine: map[string]int{"jq": 3},
	}
	out := m.Prometheus()
	for _, want := range []string{
		"# TYPE microagency_runs_total counter",
		"microagency_runs_total 5",
		"microagency_bytes_kept_out_total 1048576",
		"microagency_fields_protected_total 4",
		"# TYPE microagency_reduction_percent gauge",
		"microagency_reduction_percent 87.5",
		`microagency_substrate_runs{substrate="wasm"} 3`,
		`microagency_substrate_p50_latency_ms{substrate="wasm"} 12`,
		`microagency_engine_runs{engine="jq"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Prometheus output missing %q\n---\n%s", want, out)
		}
	}
}

// Empty breakdowns emit no labelled families (no HELP/TYPE with zero samples).
func TestMetricsPrometheusEmptyBreakdown(t *testing.T) {
	out := MetricsSummary{TotalRuns: 0}.Prometheus()
	if strings.Contains(out, "microagency_substrate_runs") || strings.Contains(out, "microagency_engine_runs") {
		t.Fatalf("empty breakdowns should emit no substrate/engine families:\n%s", out)
	}
	if !strings.Contains(out, "microagency_runs_total 0") {
		t.Fatalf("scalar counters should always be present:\n%s", out)
	}
}

// The admin endpoint serves the exposition format behind the operator token.
func TestMetricsPrometheusEndpoint(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	srv := httptest.NewServer(s.AdminHandler("op"))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/metrics/prometheus", nil)
	req.Header.Set("Authorization", "Bearer op")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != PrometheusContentType {
		t.Fatalf("content-type = %q, want %q", ct, PrometheusContentType)
	}
	// Unauthenticated is refused (same gate as the rest of /admin).
	rec := httptest.NewRecorder()
	s.AdminHandler("op").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/metrics/prometheus", nil))
	if rec.Code == http.StatusOK {
		t.Fatal("prometheus endpoint must sit behind the operator token")
	}
}
