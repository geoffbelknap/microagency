package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsoleServesPage(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	h := s.ConsoleHandler("")

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
	s := newTestServer(t, fakeRunner{})
	rec := httptest.NewRecorder()
	s.ConsoleHandler("").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/console", nil))
	body := rec.Body.String()
	for _, forbidden := range []string{"state.demo", "MOCK", "demo data"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("console page contains demo/mock fallback marker %q — it must render real data or an honest error, never fabricated data", forbidden)
		}
	}
}

func TestConsoleNotFoundElsewhere(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	req := httptest.NewRequest(http.MethodGet, "/console/nope", nil)
	rec := httptest.NewRecorder()
	s.ConsoleHandler("").ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestConsoleInjectsTokenOnLoopbackOnly(t *testing.T) {
	s := newTestServer(t, fakeRunner{})

	// loopback → the operator token is injected so the console self-authenticates
	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	s.ConsoleHandler("op-token-xyz").ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "op-token-xyz") {
		t.Fatal("loopback console did not inject the operator token")
	}

	// off loopback → never injected (would leak the token over the network)
	req2 := httptest.NewRequest(http.MethodGet, "/console", nil)
	req2.RemoteAddr = "203.0.113.7:5555"
	rec2 := httptest.NewRecorder()
	s.ConsoleHandler("op-token-xyz").ServeHTTP(rec2, req2)
	if strings.Contains(rec2.Body.String(), "op-token-xyz") {
		t.Fatal("off-loopback console leaked the operator token")
	}
}

// The console's operator affordances must match the admin API: every action the
// page wires a button to actually exists and works. This drives the exact HTTP
// calls the new buttons issue — enable a discovered upstream, scope it to a user,
// verify the audit chain — against a live handler.
func TestConsoleAffordancesMatchAdminAPI(t *testing.T) {
	// The page carries the affordances.
	s := newTestServer(t, fakeRunner{}, WithStateDir(t.TempDir()), WithUpstreamClient(&http.Client{}))
	page := httptest.NewRecorder()
	s.ConsoleHandler("").ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/console", nil))
	body := page.Body.String()
	// The affordances, asserted by the endpoint each button calls (the stable
	// contract) plus the user-facing label — not the JS handler names.
	for _, want := range []string{"/enable", "/owner", "/admin/audit/verify", "Scope to user", "Verify audit chain"} {
		if !strings.Contains(body, want) {
			t.Fatalf("console page missing affordance %q", want)
		}
	}

	// ...and the endpoints they call behave.
	up := cannedUpstream(t)
	defer up.Close()
	admin := httptest.NewServer(s.AdminHandler("op"))
	defer admin.Close()
	call := func(method, path, payload string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, admin.URL+path, strings.NewReader(payload))
		req.Header.Set("Authorization", "Bearer op")
		if payload != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var sb strings.Builder
		_, _ = io.Copy(&sb, resp.Body)
		return resp.StatusCode, sb.String()
	}

	if code, out := call(http.MethodPost, "/admin/upstreams", `{"name":"docs","url":"`+up.URL+`","discover":true}`); code != http.StatusCreated {
		t.Fatalf("add discovered: %d %s", code, out)
	}
	// enable — the button the discovered state renders.
	if code, out := call(http.MethodPost, "/admin/upstreams/docs/enable", ""); code != http.StatusOK {
		t.Fatalf("enable: %d %s", code, out)
	}
	// owner — the scope-to-user modal's POST.
	if code, out := call(http.MethodPost, "/admin/upstreams/docs/owner", `{"owner":"alice"}`); code != http.StatusOK {
		t.Fatalf("set owner: %d %s", code, out)
	}
	if code, out := call(http.MethodGet, "/admin/upstreams", ""); code != http.StatusOK || !strings.Contains(out, `"owner":"alice"`) || !strings.Contains(out, `"state":"enabled"`) {
		t.Fatalf("list after enable+scope: %d %s", code, out)
	}
	// verify — the audit-chain button's GET (records exist from the actions above
	// only if proxied; guarantee at least an intact/empty answer).
	if code, out := call(http.MethodGet, "/admin/audit/verify", ""); code != http.StatusOK || !strings.Contains(out, `"intact":true`) {
		t.Fatalf("audit verify: %d %s", code, out)
	}
}
