package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsoleServesPage(t *testing.T) {
	h := Handler("")

	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	// Assert the console↔API contract (endpoint paths + tab structure), not the
	// page's internal JS identifiers — those are free to change with a redesign.
	for _, want := range []string{"microagency", "/admin/upstreams", "/admin/runs", "/admin/registry", "/admin/registry/import", `data-tab="connections"`, `data-tab="activity"`, `id="tab-connections"`, `id="tab-activity"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("console page missing %q", want)
		}
	}
}

// The console must never carry an embedded fabricated dataset or fall back to
// one when the API is unreachable — a governance console showing invented
// upstreams, runs, or metrics is worse than an empty one. This guards against a
// future design drop reintroducing the demo/mock pathway.
func TestConsoleHasNoFabricatedDataFallback(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler("").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/console", nil))
	body := rec.Body.String()
	for _, forbidden := range []string{"state.demo", "MOCK", "demo data"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("console page contains demo/mock fallback marker %q — it must render real data or an honest error, never fabricated data", forbidden)
		}
	}
}

func TestConsoleNotFoundElsewhere(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/console/nope", nil)
	rec := httptest.NewRecorder()
	Handler("").ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestConsoleInjectsTokenOnLoopbackOnly(t *testing.T) {

	// loopback → the operator token is injected so the console self-authenticates
	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	Handler("op-token-xyz").ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "op-token-xyz") {
		t.Fatal("loopback console did not inject the operator token")
	}

	// off loopback → never injected (would leak the token over the network)
	req2 := httptest.NewRequest(http.MethodGet, "/console", nil)
	req2.RemoteAddr = "203.0.113.7:5555"
	rec2 := httptest.NewRecorder()
	Handler("op-token-xyz").ServeHTTP(rec2, req2)
	if strings.Contains(rec2.Body.String(), "op-token-xyz") {
		t.Fatal("off-loopback console leaked the operator token")
	}
}
