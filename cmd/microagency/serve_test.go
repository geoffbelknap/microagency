package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEffectiveAdminAddr(t *testing.T) {
	cases := []struct {
		name string
		cfg  httpConfig
		want string
	}{
		{"default local", httpConfig{addr: "127.0.0.1:8765"}, ""},
		{"tunnel defaults to loopback admin", httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare"}, defaultAdminAddr},
		{"explicit admin-addr wins", httpConfig{addr: "127.0.0.1:8765", adminAddr: "127.0.0.1:8201"}, "127.0.0.1:8201"},
		{"explicit admin-addr wins over tunnel default", httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare", adminAddr: "127.0.0.1:8201"}, "127.0.0.1:8201"},
		{"explicit shared bind is respected", httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare", adminAddr: "127.0.0.1:8765"}, "127.0.0.1:8765"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveAdminAddr(tc.cfg); got != tc.want {
				t.Fatalf("effectiveAdminAddr(%+v) = %q, want %q", tc.cfg, got, tc.want)
			}
		})
	}
}

// TestTunnelIsolatesOperatorSurface asserts the public-mode invariant: with a
// tunnel configured and no --admin-addr, the tunneled (agent-plane) mux must NOT
// serve the operator surface — /admin/* and /console 404 — while the separate
// loopback admin listener serves both.
func TestTunnelIsolatesOperatorSurface(t *testing.T) {
	srv := buildServer(nil, 512, 2048, false)
	cfg := httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare", token: "agent-tok"}

	mcpMux, adminMux, mode, bearer := buildMuxes(srv, cfg, "op-tok")
	if mode != "bearer" || bearer != "agent-tok" {
		t.Fatalf("mode/bearer = %q/%q, want bearer/agent-tok", mode, bearer)
	}
	if adminMux == mcpMux {
		t.Fatal("tunnel without --admin-addr must put the operator surface on its own mux")
	}

	// The tunnel proxies everything the public mux serves — the operator surface
	// must not be routable there.
	for _, path := range []string{"/console", "/admin/runs", "/admin/upstreams", "/admin/refs/r1"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer op-tok")
		mcpMux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("public mux GET %s = %d, want 404 (operator surface leaked onto the tunneled listener)", path, rec.Code)
		}
	}

	// The agent plane still works on the public mux: /mcp is routed and gated by
	// the bearer (401 without it, not 404).
	rec := httptest.NewRecorder()
	mcpMux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("public mux POST /mcp (no auth) = %d, want 401", rec.Code)
	}

	// The admin mux, served from its own loopback listener, carries the operator
	// surface: console page for a browser, token-gated /admin API.
	admin := httptest.NewServer(adminMux) // binds 127.0.0.1, like the real admin listener
	defer admin.Close()

	resp, err := http.Get(admin.URL + "/console")
	if err != nil {
		t.Fatalf("GET /console on admin listener: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(body) == 0 {
		t.Fatalf("admin listener GET /console = %d (%d bytes), want 200 with the console page", resp.StatusCode, len(body))
	}

	req, _ := http.NewRequest(http.MethodGet, admin.URL+"/admin/runs", nil)
	req.Header.Set("Authorization", "Bearer op-tok")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/runs on admin listener: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin listener GET /admin/runs (operator token) = %d, want 200", resp.StatusCode)
	}
	// And the operator token is still enforced there.
	resp, err = http.Get(admin.URL + "/admin/runs")
	if err != nil {
		t.Fatalf("GET /admin/runs (no token): %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin listener GET /admin/runs (no token) = %d, want 401", resp.StatusCode)
	}
}

// Without a tunnel or --admin-addr everything shares the single loopback
// listener — the local default is unchanged.
func TestOperatorSurfaceSharesListenerByDefault(t *testing.T) {
	srv := buildServer(nil, 512, 2048, false)
	cfg := httpConfig{addr: "127.0.0.1:8765", token: "agent-tok"} // bearer mode: no signer/issuer I/O

	mcpMux, adminMux, _, _ := buildMuxes(srv, cfg, "op-tok")
	if adminMux != mcpMux {
		t.Fatal("without a tunnel or --admin-addr, the operator surface should share the agent listener")
	}
	rec := httptest.NewRecorder()
	mcpMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/console", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("shared mux GET /console = %d, want 200", rec.Code)
	}
}
