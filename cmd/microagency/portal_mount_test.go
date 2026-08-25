package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"microagency/internal/mcp"
	"microagency/internal/portal"
)

func portalStatus(t *testing.T, mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// withBearer asks for a route the way the sign-in page's own fetch does: with a
// token, which is the only way this route answers with the application at all.
func withBearer(t *testing.T, mux *http.ServeMux, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// The portal belongs to the agent plane's listener, beside the /connections API
// it drives. It must never appear on the operator listener, and mounting it must
// not put an operator route on the public one.
func TestPortalIsOnTheAgentPlaneOnly(t *testing.T) {
	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", tunnel: "cloudflare",
		publicURL: "https://gateway.example", authDir: t.TempDir(),
	}
	mcpMux, adminMux, mode, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "oauth-tunnel" || adminMux == mcpMux {
		t.Fatalf("mode = %q, separate operator mux = %v", mode, adminMux != mcpMux)
	}

	// Mounted, and gated: a caller with no credential is sent to the one page
	// that can sign it in, and never receives the application.
	rec := portalStatus(t, mcpMux, portal.Path)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("anonymous %s on the agent plane = %d to %q, want 303 to /",
			portal.Path, rec.Code, rec.Header().Get("Location"))
	}
	// A refused token gets this deployment's own discovery URL, which is how the
	// page that asked learns where to authenticate.
	metadata := "https://gateway.example/.well-known/oauth-protected-resource/mcp"
	refused := withBearer(t, mcpMux, portal.Path, "not-a-real-token")
	if refused.Code != http.StatusUnauthorized {
		t.Fatalf("refused token on %s = %d, want 401", portal.Path, refused.Code)
	}
	if got := refused.Header().Get("WWW-Authenticate"); !strings.Contains(got, metadata) {
		t.Errorf("WWW-Authenticate = %q, want this deployment's metadata URL %q", got, metadata)
	}
	// The sign-in page is handed the same URL, so the flow it runs and the route
	// it unlocks cannot point at two different authorization servers.
	root := portalStatus(t, mcpMux, "/")
	if root.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", root.Code)
	}
	if !strings.Contains(root.Body.String(), metadata) {
		t.Error("sign-in page was not handed this deployment's protected-resource metadata URL")
	}

	if rec := portalStatus(t, adminMux, portal.Path); rec.Code != http.StatusNotFound {
		t.Errorf("%s answered %d on the operator listener; the account surface has no place there", portal.Path, rec.Code)
	}
	if rec := portalStatus(t, mcpMux, "/admin/upstreams"); rec.Code != http.StatusNotFound {
		t.Errorf("/admin is reachable from the agent plane (%d); mounting the portal must not open it", rec.Code)
	}
}

// Without the built-in authorization server there is no registration endpoint
// for a browser to obtain a client from and no consent screen this gateway
// serves, so the portal is not mounted rather than served broken.
func TestPortalNeedsTheBuiltInAuthorizationServer(t *testing.T) {
	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{addr: "127.0.0.1:8765", token: "static-bearer", authDir: t.TempDir()}
	mcpMux, _, mode, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "bearer" {
		t.Fatalf("mode = %q, want bearer", mode)
	}
	if rec := portalStatus(t, mcpMux, portal.Path); rec.Code != http.StatusNotFound {
		t.Fatalf("%s = %d in static bearer mode, want 404", portal.Path, rec.Code)
	}
	if servesPortal(cfg) {
		t.Error("servesPortal disagrees with what buildMuxes mounted")
	}
}

// servesPortal drives the startup banner, so it has to agree with the mount
// condition for every auth mode rather than being maintained separately.
func TestServesPortalMatchesTheMountCondition(t *testing.T) {
	cases := []struct {
		name string
		cfg  httpConfig
		want bool
	}{
		{"built-in local", httpConfig{addr: "127.0.0.1:8765"}, true},
		{"built-in over a tunnel", httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare", publicURL: "https://gateway.example"}, true},
		{"federated sign-in", httpConfig{addr: "127.0.0.1:8765", ssoIssuer: "https://accounts.example"}, true},
		{"external issuer", httpConfig{addr: "127.0.0.1:8765", issuer: "https://issuer.example"}, false},
		{"static bearer", httpConfig{addr: "127.0.0.1:8765", token: "t"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := servesPortal(tc.cfg); got != tc.want {
				t.Fatalf("servesPortal(%+v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}
