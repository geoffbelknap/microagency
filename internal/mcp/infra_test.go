package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"microagency/internal/secretstore"
)

// InfraStatus must report real, probed component health — never a fabricated
// all-green list. The default test server has no secret store, so its secrets
// component must honestly read "off", and gateway must read "ok" because a
// response proves it is up.
func TestInfraStatusReportsRealComponents(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st := s.InfraStatus(ctx)

	if st.Build.Go == "" || st.Build.Revision == "" {
		t.Fatalf("build info incomplete: %+v", st.Build)
	}
	valid := map[string]bool{"ok": true, "warn": true, "bad": true, "off": true}
	seen := map[string]string{}
	for _, c := range st.Components {
		if !valid[c.Status] {
			t.Errorf("component %q has invalid status %q", c.Key, c.Status)
		}
		seen[c.Key] = c.Status
	}
	for _, want := range []string{"gateway", "secrets", "index", "engines", "microvm", "audit"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("missing infra component %q", want)
		}
	}
	if seen["gateway"] != "ok" {
		t.Errorf("gateway = %q, want ok (a response proves it is up)", seen["gateway"])
	}
	if seen["secrets"] != "off" {
		t.Errorf("secrets = %q, want off — no store is configured, so it must not report healthy", seen["secrets"])
	}
}

// The /admin/infra route is wired and returns the status as JSON.
func TestInfraEndpointServesJSON(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	admin := httptest.NewServer(s.AdminHandler("op"))
	defer admin.Close()

	req, _ := http.NewRequest(http.MethodGet, admin.URL+"/admin/infra", nil)
	req.Header.Set("Authorization", "Bearer op")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got InfraStatus
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Components) == 0 {
		t.Fatal("no components returned")
	}
}

// The host block reports the OS user and the console bind, with loopback set for
// a local-only address and cleared for a network-reachable one.
func TestInfraHost(t *testing.T) {
	if got := hostInfo("127.0.0.1:8765"); !got.Loopback || got.Addr != "127.0.0.1:8765" {
		t.Errorf("loopback bind: got %+v, want Loopback=true addr=127.0.0.1:8765", got)
	}
	if got := hostInfo("0.0.0.0:8765"); got.Loopback {
		t.Errorf("network bind 0.0.0.0 reported loopback: %+v", got)
	}
	if got := hostInfo("192.168.1.10:8765"); got.Loopback {
		t.Errorf("network bind LAN IP reported loopback: %+v", got)
	}
	if got := hostInfo("localhost:8765"); !got.Loopback {
		t.Errorf("localhost should be loopback: %+v", got)
	}
	if got := hostInfo(""); got.Loopback || got.Addr != "" {
		t.Errorf("empty addr: got %+v, want no addr and not loopback", got)
	}
	if got := hostInfo("127.0.0.1:8765"); got.User == "" {
		t.Error("host user is empty — should fall back to a non-empty name")
	}
}

// The file store is a fallback used only when OpenBao can't come up, so the
// secrets component warns (degraded posture) rather than reporting a healthy ok.
func TestSecretsFileStoreWarns(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	s.secrets = &secretstore.File{Path: filepath.Join(t.TempDir(), "tokens.json")}
	var sc InfraComponent
	for _, c := range s.InfraStatus(context.Background()).Components {
		if c.Key == "secrets" {
			sc = c
		}
	}
	if sc.Status != "warn" {
		t.Fatalf("file-store secrets status = %q, want warn", sc.Status)
	}
	if sc.Label != "file" {
		t.Fatalf("label = %q, want file", sc.Label)
	}
}
