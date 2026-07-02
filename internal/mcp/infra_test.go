package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
