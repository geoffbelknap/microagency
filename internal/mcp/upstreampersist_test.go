package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"microagency/internal/secretstore"
)

// addUpstream posts to the admin API and returns the decoded JSON response.
func addUpstream(t *testing.T, adminURL, opTok string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, adminURL+"/admin/upstreams", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+opTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// upstreamNames returns the reloaded upstreams of a fresh server sharing dir+store.
func reloadInto(t *testing.T, dir string) *Server {
	t.Helper()
	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}),
		WithSecretStore(secretstore.Open(dir, func(string) string { return "" }, nil)), WithStateDir(dir))
	srv.ReloadUpstreams(context.Background())
	return srv
}

func upstreamState(s *Server, name string) (string, bool) {
	for _, u := range s.UpstreamList() {
		if u.Name == name {
			return u.State, true
		}
	}
	return "", false
}

// A tokenless discovered upstream (public tools/list, like LimaCharlie) must
// persist and reload as discovered — it was memory-only before.
func TestTokenlessDiscoveredUpstreamReloads(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	dir := t.TempDir()
	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}),
		WithSecretStore(secretstore.Open(dir, func(string) string { return "" }, nil)), WithStateDir(dir))
	admin := httptest.NewServer(srv.AdminHandler("op"))
	defer admin.Close()

	if code, out := addUpstream(t, admin.URL, "op", map[string]any{"name": "lc", "url": up.URL, "discover": true}); code != http.StatusCreated || out["state"] != "discovered" {
		t.Fatalf("add discovered: code=%d out=%v", code, out)
	}

	srv2 := reloadInto(t, dir)
	state, ok := upstreamState(srv2, "lc")
	if !ok {
		t.Fatal("tokenless discovered upstream did not reload after restart")
	}
	if state != "discovered" {
		t.Fatalf("reloaded state = %q, want discovered", state)
	}
}

// A static-bearer upstream must persist (token in the secret store, not the
// plaintext registration) and reload with the token restored.
func TestStaticTokenUpstreamReloadsWithToken(t *testing.T) {
	const wantTok = "s3cret-bearer"
	var lastAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(b), "tools/list") {
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"q","description":"q"}]}}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer up.Close()

	dir := t.TempDir()
	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}),
		WithSecretStore(secretstore.Open(dir, func(string) string { return "" }, nil)), WithStateDir(dir))
	admin := httptest.NewServer(srv.AdminHandler("op"))
	defer admin.Close()

	if code, _ := addUpstream(t, admin.URL, "op", map[string]any{"name": "st", "url": up.URL, "token": wantTok}); code != http.StatusCreated {
		t.Fatalf("add static: code=%d", code)
	}
	// The token must NOT be written to the plaintext registration file.
	regBytes, _ := os.ReadFile(srv.registrationsPath())
	if strings.Contains(string(regBytes), wantTok) {
		t.Fatalf("static token leaked into registration file: %s", regBytes)
	}

	lastAuth = ""
	srv2 := reloadInto(t, dir)
	if _, ok := upstreamState(srv2, "st"); !ok {
		t.Fatal("static-token upstream did not reload")
	}
	if lastAuth != "Bearer "+wantTok {
		t.Fatalf("reloaded upstream sent Authorization %q, want bearer %q", lastAuth, wantTok)
	}
}

// Enabling a discovered upstream must flip its persisted discover flag so it
// reloads enabled (invocable), not discovered.
func TestEnableFlipsPersistedDiscover(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	dir := t.TempDir()
	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}),
		WithSecretStore(secretstore.Open(dir, func(string) string { return "" }, nil)), WithStateDir(dir))
	admin := httptest.NewServer(srv.AdminHandler("op"))
	defer admin.Close()

	addUpstream(t, admin.URL, "op", map[string]any{"name": "lc", "url": up.URL, "discover": true})

	req, _ := http.NewRequest(http.MethodPost, admin.URL+"/admin/upstreams/lc/enable", nil)
	req.Header.Set("Authorization", "Bearer op")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	srv2 := reloadInto(t, dir)
	if state, _ := upstreamState(srv2, "lc"); state != "enabled" {
		t.Fatalf("reloaded state = %q, want enabled after enable", state)
	}
}

// Removing an upstream must clear its persisted registration so it stays gone
// across restarts.
func TestRemovedUpstreamStaysGone(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	dir := t.TempDir()
	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}),
		WithSecretStore(secretstore.Open(dir, func(string) string { return "" }, nil)), WithStateDir(dir))
	admin := httptest.NewServer(srv.AdminHandler("op"))
	defer admin.Close()

	addUpstream(t, admin.URL, "op", map[string]any{"name": "lc", "url": up.URL, "discover": true})

	req, _ := http.NewRequest(http.MethodDelete, admin.URL+"/admin/upstreams/lc", nil)
	req.Header.Set("Authorization", "Bearer op")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}

	srv2 := reloadInto(t, dir)
	if state, ok := upstreamState(srv2, "lc"); ok {
		t.Fatalf("removed upstream reloaded (state %q) — registration not cleared", state)
	}
}

// Owner scoping set at add time must survive a restart, and a reassignment via
// the admin endpoint must persist too — otherwise a restart silently un-scopes
// a user's connection back to shared.
func TestOwnerScopingPersistsAcrossRestart(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	dir := t.TempDir()
	srv := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}),
		WithSecretStore(secretstore.Open(dir, func(string) string { return "" }, nil)), WithStateDir(dir))
	admin := httptest.NewServer(srv.AdminHandler("op"))
	defer admin.Close()

	if code, out := addUpstream(t, admin.URL, "op", map[string]any{"name": "alicedocs", "url": up.URL, "owner": "alice"}); code != http.StatusCreated || out["owner"] != "alice" {
		t.Fatalf("add owned: code=%d out=%v", code, out)
	}

	srv2 := reloadInto(t, dir)
	var owner string
	for _, u := range srv2.UpstreamList() {
		if u.Name == "alicedocs" {
			owner = u.Owner
		}
	}
	if owner != "alice" {
		t.Fatalf("owner scoping lost across restart: %q", owner)
	}
	// Enforcement holds on the reloaded server.
	if out, _ := srv2.invokeUpstream(withPrincipal("bob"), "alicedocs__search", json.RawMessage(`{}`)); !out["isError"].(bool) {
		t.Fatal("reloaded owned connection must stay refused to other principals")
	}

	// Reassign via the admin endpoint; the new scoping must persist too.
	b, _ := json.Marshal(map[string]any{"owner": "carol"})
	req, _ := http.NewRequest(http.MethodPost, admin.URL+"/admin/upstreams/alicedocs/owner", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer op")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set owner: %d", resp.StatusCode)
	}
	srv3 := reloadInto(t, dir)
	for _, u := range srv3.UpstreamList() {
		if u.Name == "alicedocs" && u.Owner != "carol" {
			t.Fatalf("reassigned owner lost across restart: %q", u.Owner)
		}
	}
}
