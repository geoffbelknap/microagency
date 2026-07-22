package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"microagency/internal/gateway"
)

// mutableUpstream is an MCP-over-HTTP server whose tools/list payload can change
// between calls, to exercise re-listing.
func mutableUpstream(t *testing.T, initial string) (*httptest.Server, func(string)) {
	t.Helper()
	var mu sync.Mutex
	tools := initial
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		case "tools/list":
			mu.Lock()
			cur := tools
			mu.Unlock()
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":`+cur+`}}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
	return ts, func(next string) { mu.Lock(); tools = next; mu.Unlock() }
}

func hasIndexedTool(s *Server, name string) bool {
	for _, t := range s.indexedTools("local") {
		if n, _ := t["name"].(string); n == name {
			return true
		}
	}
	return false
}

// RefreshUpstream re-lists an upstream's tools: a tool added upstream is invisible
// until refresh, then appears; a tool removed upstream disappears after refresh.
func TestRefreshUpstreamPicksUpToolChanges(t *testing.T) {
	const search = `{"name":"search","description":"search the corpus","inputSchema":{"type":"object"}}`
	const summarize = `{"name":"summarize","description":"summarize a doc","inputSchema":{"type":"object"}}`
	ts, setTools := mutableUpstream(t, `[`+search+`]`)
	defer ts.Close()

	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "docs", URL: ts.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// A newly-added upstream tool is NOT visible until a refresh (stale index).
	setTools(`[` + search + `,` + summarize + `]`)
	if hasIndexedTool(s, "docs__summarize") {
		t.Fatal("added tool should be invisible before refresh")
	}
	if err := s.RefreshUpstream(context.Background(), "docs"); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !hasIndexedTool(s, "docs__summarize") {
		t.Fatal("refresh should surface the newly-added tool")
	}

	// A tool removed upstream disappears after the next refresh.
	setTools(`[` + summarize + `]`)
	if err := s.RefreshUpstream(context.Background(), "docs"); err != nil {
		t.Fatalf("refresh 2: %v", err)
	}
	if hasIndexedTool(s, "docs__search") {
		t.Fatal("refresh should drop a tool the upstream removed")
	}
}

func TestRefreshUnknownUpstream(t *testing.T) {
	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.RefreshUpstream(context.Background(), "nope"); err == nil {
		t.Fatal("refreshing an unknown upstream must error")
	}
}

// find_tools with a limit above the max clamps to 50 rather than snapping back to
// the default of 10.
func TestFindToolsLimitClampsToMax(t *testing.T) {
	// One upstream advertising 15 tools, all matching the query.
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 15; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":"search%d","description":"search the corpus %d","inputSchema":{"type":"object"}}`, i, i)
	}
	b.WriteString("]")
	ts, _ := mutableUpstream(t, b.String())
	defer ts.Close()

	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "docs", URL: ts.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// limit=100 is above the max; it must clamp to 50 (returning all 15 matches),
	// not reset to the default 10.
	got := len(foundTools(t, call(t, s, "find_tools", map[string]any{"query": "search corpus", "limit": 100})))
	if got != 15 {
		t.Fatalf("find_tools with limit=100 returned %d, want all 15 (clamp to 50, not snap to 10)", got)
	}
}
