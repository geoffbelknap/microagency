package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
)

// structuralPreview must reveal SHAPE (kind/count/keys) but never VALUES — a ref
// exists to keep the raw (often sensitive) data out of context, so the preview that
// rides alongside it must not leak it.
func TestStructuralPreviewIsSchemaOnly(t *testing.T) {
	// Array of objects → count + the row schema, no values.
	p := structuralPreview(`[{"mrn":"MRN-SECRET-1","ip":"10.9.9.9"},{"mrn":"MRN-SECRET-2","ip":"10.9.9.8"}]`)
	if p["kind"] != "array" || p["count"] != 2 {
		t.Fatalf("array preview: %v", p)
	}
	if ks, _ := p["item_keys"].([]string); len(ks) != 2 || ks[0] != "ip" || ks[1] != "mrn" {
		t.Fatalf("item_keys should be sorted schema [ip mrn], got %v", p["item_keys"])
	}
	assertNoValues(t, "array", p, "MRN-SECRET", "10.9.9")

	// Object → keys only.
	o := structuralPreview(`{"metadata":{"x":1},"title":"SECRET title","text":"SECRET body"}`)
	if o["kind"] != "object" {
		t.Fatalf("object preview: %v", o)
	}
	assertNoValues(t, "object", o, "SECRET")

	// Text → size only, never content.
	txt := structuralPreview("Here is a SENSITIVE document body with private words.\nSecond line.")
	if txt["kind"] != "text" || txt["lines"] != 2 {
		t.Fatalf("text preview: %v", txt)
	}
	assertNoValues(t, "text", txt, "SENSITIVE", "private")
}

func assertNoValues(t *testing.T, name string, p map[string]any, values ...string) {
	t.Helper()
	blob, _ := json.Marshal(p)
	for _, v := range values {
		if strings.Contains(string(blob), v) {
			t.Fatalf("%s preview leaked a value %q: %s", name, v, blob)
		}
	}
}

// A reffed proxy result carries a structural preview at the top level, so the agent
// can often act without a reduce round-trip — and it still leaks no values.
func TestProxyRefCarriesPreview(t *testing.T) {
	rows := `[` + strings.Repeat(`{"id":"SECRETID","host":"SECRETHOST"},`, 400) + `{"id":"SECRETID","host":"SECRETHOST"}]`
	up := textUpstream(t, rows)
	defer up.Close()
	rs := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: rs}),
		WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	out := call(t, s, "call_tool", map[string]any{"name": "u__get", "arguments": map[string]any{}})
	inner := toolContentJSON(t, out)
	if r, _ := inner["reffed"].(bool); !r {
		t.Fatalf("large rows should ref: %v", inner)
	}
	prev, ok := inner["preview"].(map[string]any)
	if !ok {
		t.Fatalf("ref is missing its structural preview: %v", inner)
	}
	if prev["kind"] != "array" || prev["count"].(float64) != 401 {
		t.Fatalf("preview shape wrong: %v", prev)
	}
	// item_keys survives the JSON round-trip as []any.
	keys, _ := prev["item_keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("item_keys: %v", prev["item_keys"])
	}
	// The whole returned envelope must not carry a single row value.
	if blob, _ := json.Marshal(out); strings.Contains(string(blob), "SECRETID") || strings.Contains(string(blob), "SECRETHOST") {
		t.Fatalf("the preview leaked row values into context: %s", blob)
	}
}
