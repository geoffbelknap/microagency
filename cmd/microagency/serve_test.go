package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microagency/internal/auth"
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
		{"explicit shared bind is calculated before validation", httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare", adminAddr: "127.0.0.1:8765"}, "127.0.0.1:8765"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveAdminAddr(tc.cfg); got != tc.want {
				t.Fatalf("effectiveAdminAddr(%+v) = %q, want %q", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestTunnelBuiltInOAuthUsesDiscoveredOriginAndKeepsConsentLocal(t *testing.T) {
	srv := buildServer(nil, 512, 2048, false, false, "127.0.0.1:8766")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", tunnel: "cloudflare",
		publicURL: "https://gateway.example", authDir: t.TempDir(),
	}
	mcpMux, adminMux, mode, bearer, err := buildMuxes(srv, cfg, "op-tok")
	if err != nil {
		t.Fatal(err)
	}
	if mode != "oauth-tunnel" || bearer != "" || adminMux == mcpMux {
		t.Fatalf("mode/bearer/split = %q/%q/%v", mode, bearer, adminMux != mcpMux)
	}

	for _, path := range []string{
		"/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-authorization-server",
		"/oauth/register",
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/revoke",
		"/oauth/jwks",
		"/mcp",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "attacker.example"
		req.Header.Set("Forwarded", "proto=http;host=attacker.example")
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", "attacker.example")
		mcpMux.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("public OAuth route %s is missing", path)
		}
		if path == "/.well-known/oauth-authorization-server" {
			var metadata map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata["issuer"] != "https://gateway.example" {
				t.Fatalf("forwarded headers changed issuer: %v", metadata["issuer"])
			}
			for field, want := range map[string]string{
				"authorization_endpoint": "https://gateway.example/oauth/authorize",
				"token_endpoint":         "https://gateway.example/oauth/token",
				"registration_endpoint":  "https://gateway.example/oauth/register",
				"revocation_endpoint":    "https://gateway.example/oauth/revoke",
				"jwks_uri":               "https://gateway.example/oauth/jwks",
			} {
				if metadata[field] != want {
					t.Errorf("AS metadata %s = %v, want %s", field, metadata[field], want)
				}
			}
		}
		if path == "/.well-known/oauth-protected-resource/mcp" {
			var metadata map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata["resource"] != "https://gateway.example/mcp" {
				t.Fatalf("protected resource metadata = %v", metadata["resource"])
			}
		}
	}

	for _, path := range []string{"/admin/runs", "/console", "/oauth/consent"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer op-tok")
		mcpMux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("public mux GET %s = %d, want 404", path, rec.Code)
		}
	}
	consentRec := httptest.NewRecorder()
	consentReq := httptest.NewRequest(http.MethodGet, "/oauth/consent", nil)
	consentReq.RemoteAddr = "127.0.0.1:45231"
	adminMux.ServeHTTP(consentRec, consentReq)
	if consentRec.Code == http.StatusNotFound {
		t.Fatal("operator mux is missing local consent route")
	}

	// A real MCP access token is still useless against the operator mux.
	signer, err := auth.LoadOrCreateSigner(oauthKeyPathFor(cfg.authDir))
	if err != nil {
		t.Fatal(err)
	}
	access, err := signer.Mint("https://gateway.example", "https://gateway.example/mcp", "operator", []string{"mcp"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mcpRec := httptest.NewRecorder()
	mcpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	mcpReq.Header.Set("Authorization", "Bearer "+access)
	mcpMux.ServeHTTP(mcpRec, mcpReq)
	if mcpRec.Code == http.StatusUnauthorized {
		t.Fatal("built-in public OAuth access token did not authenticate /mcp")
	}
	opRec := httptest.NewRecorder()
	opReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	opReq.Header.Set("Authorization", "Bearer op-tok")
	mcpMux.ServeHTTP(opRec, opReq)
	if opRec.Code != http.StatusUnauthorized {
		t.Fatalf("operator token authenticated public /mcp: status=%d", opRec.Code)
	}
	if want := `resource_metadata="https://gateway.example/.well-known/oauth-protected-resource/mcp"`; !strings.Contains(opRec.Header().Get("WWW-Authenticate"), want) {
		t.Fatalf("public 401 metadata hint = %q, want %q", opRec.Header().Get("WWW-Authenticate"), want)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/runs", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	adminMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("MCP access token reached operator API: status=%d", rec.Code)
	}
}

func TestTunnelExternalIssuerRemainsDistinctFromBuiltInOAuth(t *testing.T) {
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": "https://issuer.example/jwks"})
	}))
	defer issuer.Close()
	srv := buildServer(nil, 512, 2048, false, false, "127.0.0.1:8766")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", tunnel: "ngrok", publicURL: "https://gateway.example",
		issuer: issuer.URL, audience: "gateway-audience",
	}
	mcpMux, adminMux, mode, bearer, err := buildMuxes(srv, cfg, "op-tok")
	if err != nil {
		t.Fatal(err)
	}
	if mode != "oauth-external" || bearer != "" || adminMux == mcpMux {
		t.Fatalf("mode/bearer/split = %q/%q/%v", mode, bearer, adminMux != mcpMux)
	}
	metadataRec := httptest.NewRecorder()
	mcpMux.ServeHTTP(metadataRec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
	var metadata struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(metadataRec.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Resource != "https://gateway.example/mcp" || len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != issuer.URL {
		t.Fatalf("external protected resource metadata = %+v", metadata)
	}
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/oauth/register", "/oauth/authorize", "/oauth/token", "/oauth/revoke", "/oauth/jwks"} {
		rec := httptest.NewRecorder()
		mcpMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("external issuer mode mounted built-in route %s: status=%d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	mcpMux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "https://gateway.example/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("external /mcp challenge = %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

// TestTunnelIsolatesOperatorSurface asserts the public-mode invariant: with a
// tunnel configured and no --admin-addr, the tunneled (agent-plane) mux must NOT
// serve the operator surface — /admin/* and /console 404 — while the separate
// loopback admin listener serves both.
func TestTunnelIsolatesOperatorSurface(t *testing.T) {
	srv := buildServer(nil, 512, 2048, false, false, "127.0.0.1:8765")
	cfg := httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare", token: "agent-tok", publicURL: "https://gateway.example"}

	mcpMux, adminMux, mode, bearer, err := buildMuxes(srv, cfg, "op-tok")
	if err != nil {
		t.Fatal(err)
	}
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

// An explicit public bearer remains available for compatibility and is never the
// operator token. The default tunnel mode is built-in OAuth instead.
func TestExplicitTunnelBearerIsDistinctFromOperatorToken(t *testing.T) {
	srv := buildServer(nil, 512, 2048, false, false, "127.0.0.1:8765")
	cfg := httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare", token: "mcp-bearer-tok", publicURL: "https://gateway.example"}

	mcpMux, _, mode, bearer, err := buildMuxes(srv, cfg, "op-tok")
	if err != nil {
		t.Fatal(err)
	}
	if mode != "bearer" {
		t.Fatalf("mode = %q, want bearer", mode)
	}
	if bearer == "op-tok" {
		t.Fatal("the tunnel /mcp bearer must NOT be the operator token")
	}
	if bearer != "mcp-bearer-tok" {
		t.Fatalf("bearer = %q, want the distinct mcp bearer", bearer)
	}

	// The operator token must be rejected at /mcp (planes use different secrets).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer op-tok")
	mcpMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/mcp with the operator token = %d, want 401 (operator token must not reach the agent plane)", rec.Code)
	}

	// The distinct bearer authenticates /mcp (past auth → not 401).
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req2.Header.Set("Authorization", "Bearer mcp-bearer-tok")
	mcpMux.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusUnauthorized {
		t.Fatal("/mcp with the distinct bearer = 401, want authenticated")
	}
}

// Without a tunnel or --admin-addr everything shares the single loopback
// listener — the local default is unchanged.
func TestOperatorSurfaceSharesListenerByDefault(t *testing.T) {
	srv := buildServer(nil, 512, 2048, false, false, "127.0.0.1:8765")
	cfg := httpConfig{addr: "127.0.0.1:8765", token: "agent-tok"} // bearer mode: no signer/issuer I/O

	mcpMux, adminMux, _, _, err := buildMuxes(srv, cfg, "op-tok")
	if err != nil {
		t.Fatal(err)
	}
	if adminMux != mcpMux {
		t.Fatal("without a tunnel or --admin-addr, the operator surface should share the agent listener")
	}
	rec := httptest.NewRecorder()
	mcpMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/console", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("shared mux GET /console = %d, want 200", rec.Code)
	}
}

func TestTunnelConfigurationRequiresSeparateLoopbackListeners(t *testing.T) {
	cases := []httpConfig{
		{addr: "0.0.0.0:8765", tunnel: "cloudflare"},
		{addr: "127.0.0.1:8765", adminAddr: "0.0.0.0:8766", tunnel: "cloudflare"},
		{addr: "127.0.0.1:8765", adminAddr: "127.0.0.1:8765", tunnel: "cloudflare"},
	}
	for _, cfg := range cases {
		if err := validateHTTPConfig(cfg); err == nil {
			t.Fatalf("unsafe tunnel config accepted: %+v", cfg)
		}
	}
	if err := validateHTTPConfig(httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare"}); err != nil {
		t.Fatalf("safe tunnel defaults rejected: %v", err)
	}
}

func TestValidatePublicTunnelURL(t *testing.T) {
	if got, err := validatePublicTunnelURL("https://named.trycloudflare.com/"); err != nil || got != "https://named.trycloudflare.com" {
		t.Fatalf("valid public URL = %q, %v", got, err)
	}
	for _, raw := range []string{
		"http://named.trycloudflare.com",
		"https://user:pass@named.trycloudflare.com",
		"https://named.trycloudflare.com/unexpected",
		"https://named.trycloudflare.com?issuer=evil",
	} {
		if _, err := validatePublicTunnelURL(raw); err == nil {
			t.Fatalf("unsafe public URL accepted: %s", raw)
		}
	}
}

func TestRecordAuthPostureReportsTunnelURLChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-posture.json")
	first := httpConfig{tunnel: "cloudflare", publicURL: "https://first.example"}
	changed, err := recordAuthPostureAt(first, "oauth-tunnel", path)
	if err != nil || changed {
		t.Fatalf("first posture = changed %v, err %v", changed, err)
	}
	second := httpConfig{tunnel: "cloudflare", publicURL: "https://second.example"}
	changed, err = recordAuthPostureAt(second, "oauth-tunnel", path)
	if err != nil || !changed {
		t.Fatalf("changed posture = changed %v, err %v", changed, err)
	}
	posture, err := readAuthPosture(path)
	if err != nil {
		t.Fatal(err)
	}
	if posture.Issuer != second.publicURL || posture.Resource != second.publicURL+"/mcp" || posture.Audience != second.publicURL+"/mcp" {
		t.Fatalf("stored posture = %+v", posture)
	}
}
