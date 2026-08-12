package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"microagency/internal/gateway"
)

func TestLocalRankerExactNameAndSchemaTerms(t *testing.T) {
	indexed := []map[string]any{
		{"name": "svc__get_users", "description": "List users", "inputSchema": json.RawMessage(`{"type":"object"}`), "usage": 100},
		{"name": "svc__get_user", "description": "Read one user", "inputSchema": json.RawMessage(`{"type":"object","properties":{"external_id":{"type":"string"}}}`), "usage": 0},
	}
	exact := rankIndexedTools("svc__get_user", indexed)
	if len(exact) == 0 || exact[0].tool["name"] != "svc__get_user" || !exact[0].explanation.Exact {
		t.Fatalf("exact name lost to usage or a similar family: %+v", exact)
	}
	bySchema := rankIndexedTools("external id", indexed)
	if len(bySchema) == 0 || bySchema[0].tool["name"] != "svc__get_user" {
		t.Fatalf("schema property did not contribute to local rank: %+v", bySchema)
	}
}

func TestRankToolsOperatorOutputIsScopedAndMetadataFree(t *testing.T) {
	secretDescription := "DESCRIPTION_SENTINEL must not enter debug output"
	shared := &fakeConn{endpoint: "stdio://shared", tools: []gateway.Tool{{
		Name: "inspect_key", Description: secretDescription,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"key_id":{"type":"string"}}}`),
	}}}
	owned := &fakeConn{endpoint: "stdio://owned", tools: []gateway.Tool{{
		Name: "rotate_key", Description: "Rotate access key metadata",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"key_id":{"type":"string"}}}`),
	}}}
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "shared", shared); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUpstream(context.Background(), "private", owned, WithOwner("alice")); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(s.AdminHandler("operator-token"))
	defer server.Close()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/admin/tools/rank?q=access+key&subject=bob", nil)
	req.Header.Set("Authorization", "Bearer operator-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rank debug status=%d body=%s", resp.StatusCode, raw)
	}
	var ranked []ToolRankInfo
	if err := json.Unmarshal(raw, &ranked); err != nil {
		t.Fatal(err)
	}
	if len(ranked) == 0 || ranked[0].Name != "shared__inspect_key" {
		t.Fatalf("operator rank did not use bob's scoped index: %s", raw)
	}
	if strings.Contains(string(raw), "private__rotate_key") || strings.Contains(string(raw), secretDescription) || strings.Contains(string(raw), "inputSchema") {
		t.Fatalf("operator explanation leaked scoped/protected metadata: %s", raw)
	}
}

func TestLocalRankerReflectsCatalogRefreshWithoutStaleIndex(t *testing.T) {
	oldConn := &fakeConn{endpoint: "stdio://old", tools: []gateway.Tool{{Name: "old_lookup", Description: "Lookup old records"}}}
	newConn := &fakeConn{endpoint: "stdio://new", tools: []gateway.Tool{{Name: "new_search", Description: "Search replacement records"}}}
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "svc", oldConn); err != nil {
		t.Fatal(err)
	}
	if got := s.RankTools("local", "svc__old_lookup", 10); len(got) == 0 || got[0].Name != "svc__old_lookup" {
		t.Fatalf("initial catalog missing: %+v", got)
	}
	if err := s.RebindUpstream(context.Background(), "svc", newConn); err != nil {
		t.Fatal(err)
	}
	if got := s.RankTools("local", "svc__new_search", 10); len(got) == 0 || got[0].Name != "svc__new_search" {
		t.Fatalf("refreshed catalog not ranked: %+v", got)
	}
	for _, hit := range s.RankTools("local", "old lookup", 10) {
		if hit.Name == "svc__old_lookup" {
			t.Fatalf("stale tool survived refresh: %+v", hit)
		}
	}
}
