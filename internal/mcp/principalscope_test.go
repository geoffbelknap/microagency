package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
)

// countingSessionUpstream is a canned MCP server that counts tools/call hits,
// assigns a fresh Mcp-Session-Id per initialize, and records the session id
// each tools/call presented.
type countingSessionUpstream struct {
	mu           sync.Mutex
	initializes  int
	calls        int
	callSessions []string
}

func (c *countingSessionUpstream) serve(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
			Params struct {
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			c.mu.Lock()
			c.initializes++
			id := fmt.Sprintf("sess-%d", c.initializes)
			c.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", id)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"read the corpus","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}},"annotations":{"readOnlyHint":true}}]}}`)
		case "tools/call":
			c.mu.Lock()
			c.calls++
			n := c.calls
			c.callSessions = append(c.callSessions, r.Header.Get("Mcp-Session-Id"))
			c.mu.Unlock()
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"answer-%d"}],"isError":false}}`, n)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
}

// The in-flight read cache is principal-scoped: one caller's repeat of an
// identical read is served from cache, but the same read by a DIFFERENT caller
// on the same shared connection always reaches the upstream — a result produced
// under one caller's authority is never replayed to another.
func TestInflightCacheIsPrincipalScoped(t *testing.T) {
	up := &countingSessionUpstream{}
	ts := up.serve(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}
	args := json.RawMessage(`{"q":"same"}`)

	for i := 0; i < 2; i++ { // identical read, same caller → one upstream execution
		if out, _ := s.invokeUpstream(withPrincipal("alice"), "docs__search", args); out["isError"].(bool) {
			t.Fatalf("alice call %d errored: %v", i, out)
		}
	}
	up.mu.Lock()
	afterAlice := up.calls
	up.mu.Unlock()
	if afterAlice != 1 {
		t.Fatalf("identical reads by ONE caller must share one execution; upstream saw %d", afterAlice)
	}

	if out, _ := s.invokeUpstream(withPrincipal("bob"), "docs__search", args); out["isError"].(bool) {
		t.Fatalf("bob errored: %v", out)
	}
	up.mu.Lock()
	afterBob := up.calls
	up.mu.Unlock()
	if afterBob != 2 {
		t.Fatalf("an identical read by a DIFFERENT caller must not be served from cache; upstream saw %d calls", afterBob)
	}
}

// Upstream MCP sessions are keyed by (upstream, caller): through the full
// invocation path, two principals' calls to one shared connection present
// different Mcp-Session-Id values, so upstream session state never spans them.
func TestUpstreamSessionStateIsPerPrincipal(t *testing.T) {
	up := &countingSessionUpstream{}
	ts := up.serve(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	// Distinct arguments per caller so each call really reaches the upstream.
	if out, _ := s.invokeUpstream(withPrincipal("alice"), "docs__search", json.RawMessage(`{"q":"a"}`)); out["isError"].(bool) {
		t.Fatalf("alice errored: %v", out)
	}
	if out, _ := s.invokeUpstream(withPrincipal("bob"), "docs__search", json.RawMessage(`{"q":"b"}`)); out["isError"].(bool) {
		t.Fatalf("bob errored: %v", out)
	}
	if out, _ := s.invokeUpstream(withPrincipal("alice"), "docs__search", json.RawMessage(`{"q":"a2"}`)); out["isError"].(bool) {
		t.Fatalf("alice second call errored: %v", out)
	}

	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.callSessions) != 3 {
		t.Fatalf("upstream saw %d calls, want 3: %v", len(up.callSessions), up.callSessions)
	}
	alice1, bob, alice2 := up.callSessions[0], up.callSessions[1], up.callSessions[2]
	if alice1 == "" || bob == "" {
		t.Fatalf("caller-scoped calls must carry a session id: %v", up.callSessions)
	}
	if alice1 == bob {
		t.Fatalf("two principals shared one upstream session: %q", alice1)
	}
	if alice1 != alice2 {
		t.Fatalf("one principal's session must be stable across calls: %q vs %q", alice1, alice2)
	}
}

// refPreview refuses to build a preview for anyone but the ref's owner, so a
// call site added later cannot leak a structural preview of another
// principal's parked data by handle.
func TestRefPreviewIsOwnerBound(t *testing.T) {
	store := refstore.NewMemStore()
	ref, _ := store.Put(`[{"secret":"row"}]`, pk("alice"))
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}))

	if p := s.refPreview(ref, pk("bob")); p != nil {
		t.Fatalf("another principal must not receive a preview: %v", p)
	}
	if p := s.refPreview(ref, pk("alice")); p == nil {
		t.Fatal("the owner must receive the preview")
	}
}
