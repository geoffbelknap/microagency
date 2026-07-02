package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microagency/internal/auth"
	"microagency/internal/gateway"
	"microagency/internal/secretstore"
)

// TestConsoleOAuthAddUpstream drives the whole console OAuth-add flow: POST the
// upstream (no token) → get an authorize URL → the operator approves at the
// upstream's AS → the redirect hits microagency's /admin/oauth/callback → the
// upstream is registered with a cred-blind token. The "upstream" 401s and points
// at our own AS; the operator's browser is simulated.
func TestConsoleOAuthAddUpstream(t *testing.T) {
	// The upstream's authorization server (a separate AuthServer + PR metadata).
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	asTS := httptest.NewUnstartedServer(nil)
	asURL := "http://" + asTS.Listener.Addr().String()
	asMux := http.NewServeMux()
	auth.NewAuthServer(signer, asURL, "microagency", time.Hour).Register(asMux)
	asMux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadata("microagency", asURL))
	asTS.Config.Handler = asMux
	asTS.Start()
	defer asTS.Close()

	// The upstream MCP: 401 (pointing at its AS) with no bearer; serves once authed.
	upTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+asURL+`/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "tools/list") {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"query","description":"q"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upTS.Close()

	// microagency's admin API, with a plain client so it can reach the loopback mocks.
	dir := t.TempDir()
	tokenStore := secretstore.Open(dir, func(string) string { return "" }, nil) // file store
	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}), WithSecretStore(tokenStore), WithStateDir(dir))
	const opTok = "op"
	admin := httptest.NewServer(srv.AdminHandler(opTok))
	defer admin.Close()

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 1. add the upstream (no token) → authorization_required + authorize_url
	body, _ := json.Marshal(map[string]any{"name": "supa", "url": upTS.URL})
	addReq, _ := http.NewRequest(http.MethodPost, admin.URL+"/admin/upstreams", bytes.NewReader(body))
	addReq.Header.Set("Authorization", "Bearer "+opTok)
	addResp, err := http.DefaultClient.Do(addReq)
	if err != nil {
		t.Fatal(err)
	}
	if addResp.StatusCode != http.StatusAccepted {
		t.Fatalf("add upstream = %d, want 202", addResp.StatusCode)
	}
	var added struct {
		Status       string `json:"status"`
		AuthorizeURL string `json:"authorize_url"`
	}
	json.NewDecoder(addResp.Body).Decode(&added)
	if added.Status != "authorization_required" || added.AuthorizeURL == "" {
		t.Fatalf("unexpected add response: %+v", added)
	}

	// 2. the operator approves at the upstream's AS → 302 back to our callback
	au, _ := url.Parse(added.AuthorizeURL)
	form := au.Query()
	form.Set("approve", "yes")
	approveResp, err := noRedirect.PostForm(au.Scheme+"://"+au.Host+au.Path, form)
	if err != nil {
		t.Fatal(err)
	}
	if approveResp.StatusCode != http.StatusFound {
		t.Fatalf("approve = %d, want 302", approveResp.StatusCode)
	}

	// 3. follow the redirect to microagency's callback → exchange + register
	cb, err := http.Get(approveResp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cb.Body.Close()
	if cb.StatusCode != http.StatusOK {
		t.Fatalf("callback = %d", cb.StatusCode)
	}

	// 4. the upstream is now registered
	listReq, _ := http.NewRequest(http.MethodGet, admin.URL+"/admin/upstreams", nil)
	listReq.Header.Set("Authorization", "Bearer "+opTok)
	listResp, _ := http.DefaultClient.Do(listReq)
	var ups []map[string]any
	json.NewDecoder(listResp.Body).Decode(&ups)
	found := false
	for _, u := range ups {
		if u["name"] == "supa" {
			found = true
		}
	}
	if !found {
		t.Fatalf("upstream not registered after callback: %v", ups)
	}

	// the refresh token was persisted to the store (held there, not memory-only)
	raw, err := tokenStore.Load(context.Background(), tokenKey("supa"))
	if err != nil {
		t.Fatalf("refresh token not persisted: %v", err)
	}
	var rec auth.TokenRecord
	json.Unmarshal(raw, &rec)
	if rec.RefreshToken == "" || rec.TokenEndpoint == "" {
		t.Fatalf("persisted record incomplete: %s", raw)
	}

	// a "restart": a fresh server with the same store + state dir reloads the
	// upstream from its registration + stored refresh token — no re-login.
	srv2 := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}),
		WithSecretStore(secretstore.Open(dir, func(string) string { return "" }, nil)), WithStateDir(dir))
	srv2.ReloadUpstreams(context.Background())
	reloaded := false
	for _, u := range srv2.UpstreamList() {
		if u.Name == "supa" {
			reloaded = true
		}
	}
	if !reloaded {
		t.Fatal("upstream did not reload after restart")
	}
}

// TestConsoleOAuthCallbackRejectsUnknownState: a forged/expired state never
// registers anything.
func TestConsoleOAuthCallbackRejectsUnknownState(t *testing.T) {
	srv := NewServer(fakeRunner{})
	admin := httptest.NewServer(srv.AdminHandler("op"))
	defer admin.Close()
	r, err := http.Get(admin.URL + "/admin/oauth/callback?state=forged&code=x")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if len(srv.UpstreamList()) != 0 {
		t.Fatal("a forged callback registered an upstream")
	}
}

// TestConsoleOAuthAddPassesScope: an operator-supplied scope must reach the
// upstream's authorize URL, so the issued token carries the right privileges
// (empty scope otherwise yields an under-privileged token — the LimaCharlie case).
func TestConsoleOAuthAddPassesScope(t *testing.T) {
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	asTS := httptest.NewUnstartedServer(nil)
	asURL := "http://" + asTS.Listener.Addr().String()
	asMux := http.NewServeMux()
	auth.NewAuthServer(signer, asURL, "microagency", time.Hour).Register(asMux)
	asMux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadata("microagency", asURL))
	asTS.Config.Handler = asMux
	asTS.Start()
	defer asTS.Close()

	upTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+asURL+`/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upTS.Close()

	dir := t.TempDir()
	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}),
		WithSecretStore(secretstore.Open(dir, func(string) string { return "" }, nil)), WithStateDir(dir))
	admin := httptest.NewServer(srv.AdminHandler("op"))
	defer admin.Close()

	body, _ := json.Marshal(map[string]any{"name": "up", "url": upTS.URL, "scope": "limacharlie:read limacharlie:write"})
	req, _ := http.NewRequest(http.MethodPost, admin.URL+"/admin/upstreams", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer op")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var added struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	json.NewDecoder(resp.Body).Decode(&added)
	au, err := url.Parse(added.AuthorizeURL)
	if err != nil {
		t.Fatalf("bad authorize_url: %v", err)
	}
	if got := au.Query().Get("scope"); got != "limacharlie:read limacharlie:write" {
		t.Fatalf("authorize_url scope = %q, want the requested scopes", got)
	}
}

// TestConsoleReauthUpstream: re-auth of an already-registered upstream returns an
// authorize URL carrying the newly-requested scope (change-scope-later path).
func TestConsoleReauthUpstream(t *testing.T) {
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	asTS := httptest.NewUnstartedServer(nil)
	asURL := "http://" + asTS.Listener.Addr().String()
	asMux := http.NewServeMux()
	auth.NewAuthServer(signer, asURL, "microagency", time.Hour).Register(asMux)
	asMux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadata("microagency", asURL))
	asTS.Config.Handler = asMux
	asTS.Start()
	defer asTS.Close()

	// Upstream: public tools/list (no 401), advertises OAuth via well-known — the
	// LimaCharlie shape, reachable without a token so it can be pre-registered.
	upTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"x","authorization_servers":["` + asURL + `"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upTS.Close()

	dir := t.TempDir()
	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}),
		WithSecretStore(secretstore.Open(dir, func(string) string { return "" }, nil)), WithStateDir(dir))
	if err := srv.AddUpstream(context.Background(), &gateway.Upstream{Name: "lc", URL: upTS.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("pre-register: %v", err)
	}
	admin := httptest.NewServer(srv.AdminHandler("op"))
	defer admin.Close()

	body, _ := json.Marshal(map[string]any{"scope": "limacharlie:read"})
	req, _ := http.NewRequest(http.MethodPost, admin.URL+"/admin/upstreams/lc/reauth", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer op")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("reauth = %d, want 202", resp.StatusCode)
	}
	var out struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	au, err := url.Parse(out.AuthorizeURL)
	if err != nil {
		t.Fatalf("bad authorize_url: %v", err)
	}
	if got := au.Query().Get("scope"); got != "limacharlie:read" {
		t.Fatalf("reauth scope = %q, want limacharlie:read", got)
	}
}

// TestAdminOAuthScopesDiscovery: the scopes endpoint probes a URL and returns the
// provider's advertised scopes, so the console can render a checkbox picker.
func TestAdminOAuthScopesDiscovery(t *testing.T) {
	asTS := httptest.NewUnstartedServer(nil)
	asURL := "http://" + asTS.Listener.Addr().String()
	asMux := http.NewServeMux()
	// AS metadata advertising scopes_supported (no full AuthServer needed here).
	asMux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + asURL + `","authorization_endpoint":"` + asURL + `/authorize","token_endpoint":"` + asURL + `/token","scopes_supported":["lc:read","lc:write","lc:admin"]}`))
	})
	asTS.Config.Handler = asMux
	asTS.Start()
	defer asTS.Close()

	// LimaCharlie-shaped upstream: public, advertises OAuth via well-known.
	upTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"x","authorization_servers":["` + asURL + `"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upTS.Close()

	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}))
	admin := httptest.NewServer(srv.AdminHandler("op"))
	defer admin.Close()

	req, _ := http.NewRequest(http.MethodGet, admin.URL+"/admin/oauth-scopes?url="+url.QueryEscape(upTS.URL), nil)
	req.Header.Set("Authorization", "Bearer op")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		OAuth  bool     `json:"oauth"`
		Scopes []string `json:"scopes"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if !out.OAuth {
		t.Fatal("expected oauth=true")
	}
	if strings.Join(out.Scopes, ",") != "lc:read,lc:write,lc:admin" {
		t.Fatalf("scopes = %v, want [lc:read lc:write lc:admin]", out.Scopes)
	}
}
