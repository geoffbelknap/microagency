package mcp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
)

// toolContentJSON unwraps a content-wrapped tool result (toolResult) and parses its
// single JSON text block back into a map.
func toolContentJSON(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	var text string
	switch c := out["content"].(type) {
	case []map[string]any:
		text, _ = c[0]["text"].(string)
	case []any:
		m, _ := c[0].(map[string]any)
		text, _ = m["text"].(string)
	default:
		t.Fatalf("unexpected content shape: %T", out["content"])
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("content text not JSON: %v", err)
	}
	return m
}

// gzipBytes gzips s (to exercise the *.json.gz decompression path).
func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return buf.Bytes()
}

// offloadUpstream returns a fake MCP server whose tools/call hands back an offload
// pointer (a public URL) instead of the data — the LimaCharlie large-result shape.
func offloadUpstream(t *testing.T, resourceURL string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"export","description":"x"}]}}`)
		case "tools/call":
			// Real servers wrap the result in an MCP content text block, so the offload
			// fields live INSIDE content[0].text (not at the result top level).
			inner := `{"reason":"results too large, see resource_link","resource_link":"` + resourceURL + `","resource_size":9999,"success":true}`
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":`+strconv.Quote(inner)+`}],"isError":false}}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
}

// An upstream that offloads a large result to a public URL must be rehydrated
// host-side: the agent gets a ref to the real bytes, never the URL, and the fetch
// happens through microagency (not the agent).
func TestOffloadURLRehydratedNotLeaked(t *testing.T) {
	payload := `[{"host":"gb-desktop","cat":"noise"},{"host":"gb-desktop","cat":"noise"}]` + strings.Repeat(" ", 4000)
	gz := gzipBytes(t, payload) // serve gzip, like LimaCharlie's *.json.gz export
	var fetched int32
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&fetched, 1)
		_, _ = w.Write(gz)
	}))
	defer store.Close()

	up := offloadUpstream(t, store.URL+"/export.json.gz")
	defer up.Close()

	rs := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: rs}),
		WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "lc", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	out := call(t, s, "call_tool", map[string]any{"name": "lc__export", "arguments": map[string]any{}})

	// A reffed result is content-wrapped (refHandleResult → toolResult); unwrap it.
	inner := toolContentJSON(t, out)
	if r, _ := inner["reffed"].(bool); !r {
		t.Fatalf("expected a reffed (rehydrated) result, got %v", inner)
	}
	if atomic.LoadInt32(&fetched) == 0 {
		t.Fatal("offload URL was never fetched host-side — not rehydrated")
	}
	if blob, _ := json.Marshal(out); strings.Contains(string(blob), store.URL) {
		t.Fatalf("offload URL leaked to the agent: %s", blob)
	}
	// The ref holds the decompressed real payload, not the pointer.
	data, _, ok := rs.Get(refstore.Ref(inner["ref"].(string)))
	if !ok || !strings.Contains(data, "gb-desktop") {
		t.Fatalf("ref does not hold the rehydrated payload (ok=%v)", ok)
	}
	if strings.Contains(data, "resource_link") {
		t.Fatalf("ref holds the offload envelope, not the real data: %.120s", data)
	}
}

// A result that merely contains a URL as a data field (e.g. a detection's "link"
// to a UI timeline) is NOT an offload and must pass through untouched.
func TestNonOffloadURLPassesThrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get","description":"x"}]}}`)
		case "tools/call":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"link":"https://app.example.com/timeline","count":1}}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
	defer up.Close()

	rs := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: rs}),
		WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	out := call(t, s, "call_tool", map[string]any{"name": "u__get", "arguments": map[string]any{}})
	if r, _ := out["reffed"].(bool); r {
		t.Fatalf("a data-field URL was mistaken for an offload and rehydrated: %v", out)
	}
	if out["link"] != "https://app.example.com/timeline" {
		t.Fatalf("legit URL field was altered: %v", out)
	}
}
