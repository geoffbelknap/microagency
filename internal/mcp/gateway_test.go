package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"microagency/internal/auth"
	"microagency/internal/gateway"
)

// cannedUpstream is a minimal MCP-over-HTTP server with one tool, "search".
func cannedUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"search the corpus","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}]}}`)
		case "tools/call":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"upstream-answer"}],"isError":false}}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`)
		}
	}))
}

func TestProxyCallIsAudited(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	out := call(t, s, "call_tool", map[string]any{"name": "docs__search", "arguments": map[string]any{"q": "hello"}})
	if out["isError"].(bool) {
		t.Fatalf("call_tool errored: %v", out)
	}

	var proxy *RunInfo
	for _, r := range s.RunLog() {
		if r.Kind == "proxy" {
			rec := r
			proxy = &rec
			break
		}
	}
	if proxy == nil {
		t.Fatal("proxied call left NO audit record — the whole point of this change")
	}
	if proxy.Upstream != "docs" || proxy.Tool != "search" {
		t.Fatalf("audit record wrong: upstream=%q tool=%q", proxy.Upstream, proxy.Tool)
	}
	if !strings.Contains(proxy.Args, "hello") {
		t.Fatalf("audit must record the full args (no redaction); got %q", proxy.Args)
	}
	if proxy.OutputBytes == 0 {
		t.Fatal("audit should record the result byte size")
	}
}

func TestAggregatesUpstreamTools(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	// tools/list stays LEAN: native tools only — the aggregated upstream tool is
	// kept OUT of context. It lives behind find_tools (discover) + call_tool (invoke).
	line, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/list"})
	resp, _ := s.Handle(context.Background(), line)
	tools := resp.Result.(map[string]any)["tools"].([]map[string]any)
	names := map[string]bool{}
	for _, td := range tools {
		names[td["name"].(string)] = true
	}
	if names["docs__search"] {
		t.Fatalf("upstream tool must NOT be in tools/list (kept out of context); got %v", names)
	}
	if !names["reduce"] || !names["find_tools"] || !names["call_tool"] {
		t.Fatalf("native tools (incl. call_tool) must be listed; got %v", names)
	}

	// It's discoverable via find_tools, with its schema for the call.
	found := foundTools(t, call(t, s, "find_tools", map[string]any{"query": "search the corpus"}))
	if len(found) == 0 || found[0].Name != "docs__search" {
		t.Fatalf("upstream tool not discoverable via find_tools: %v", found)
	}

	// ... and invokable via call_tool, proxied to the upstream.
	out := call(t, s, "call_tool", map[string]any{"name": "docs__search", "arguments": map[string]any{"q": "x"}})
	if out["isError"].(bool) {
		t.Fatalf("call_tool errored: %v", out)
	}
	if b, _ := json.Marshal(out); !strings.Contains(string(b), "upstream-answer") {
		t.Fatalf("did not get the upstream's result: %s", b)
	}
}

func TestDiscoveryInvocationGate(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})

	// Discover (do NOT enable): the tool is indexed but not invocable.
	if err := s.DiscoverUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
		t.Fatalf("discover: %v", err)
	}

	// find_tools surfaces it, marked not-enabled — discovery exceeds invocation.
	found := foundTools(t, call(t, s, "find_tools", map[string]any{"query": "search the corpus"}))
	if len(found) == 0 || found[0].Name != "docs__search" {
		t.Fatalf("discovered tool not findable: %v", found)
	}
	if found[0].Enabled {
		t.Fatal("a discovered tool must be marked not-enabled")
	}

	// The gate: call_tool refuses it, with an actionable message.
	out := call(t, s, "call_tool", map[string]any{"name": "docs__search", "arguments": map[string]any{"q": "x"}})
	if !out["isError"].(bool) {
		t.Fatal("call_tool must refuse a discovered-but-not-enabled tool")
	}
	if txt := out["content"].([]map[string]any)[0]["text"].(string); !strings.Contains(txt, "not enabled") {
		t.Fatalf("gate message should say 'not enabled': %q", txt)
	}

	// The explicit operator grant: enable → now invocable.
	if err := s.EnableUpstream(context.Background(), "docs"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	out = call(t, s, "call_tool", map[string]any{"name": "docs__search", "arguments": map[string]any{"q": "x"}})
	if out["isError"].(bool) {
		t.Fatalf("an enabled tool must be invocable: %v", out)
	}
	if b, _ := json.Marshal(out); !strings.Contains(string(b), "upstream-answer") {
		t.Fatalf("did not get the upstream's result: %s", b)
	}
}

func TestUnknownNamespacedToolErrors(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	out := call(t, s, "ghost__tool", map[string]any{})
	if !out["isError"].(bool) {
		t.Fatal("a namespaced tool with no registered upstream must be a tool error")
	}
}

func TestAddUpstreamRejectsBadName(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "bad__name", &gateway.Upstream{Name: "bad__name", URL: ts.URL}); err == nil {
		t.Fatal("an upstream name containing the namespace separator must be rejected")
	}
}

// TestGatewayStateNoRace hammers the invocation gate while operator paths mutate
// the same record (read-only toggles, rebinds) and duplicate registrations race.
// It exists to fail under -race: invokeUpstream must snapshot the record under
// the lock, never read live fields the operator paths write concurrently.
func TestGatewayStateNoRace(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ { // agent traffic
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// The result varies with the racing read-only toggle (refusal vs
				// answer) — both are fine; the point is the -race detector.
				_, _ = s.invokeUpstream(context.Background(), "docs__search", json.RawMessage(`{"q":"x"}`))
			}
		}()
	}
	for i := 0; i < 25; i++ { // operator churn against the same record
		if err := s.SetUpstreamReadOnly("docs", i%2 == 0); err != nil {
			t.Errorf("set read-only: %v", err)
		}
		if err := s.RebindUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
			t.Errorf("rebind: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

// TestRegisterUpstreamAtomic races two adds of the same name; exactly one may win.
func TestRegisterUpstreamAtomic(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})

	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.AddUpstream(context.Background(), "dup", &gateway.Upstream{Name: "dup", URL: ts.URL})
		}()
	}
	wg.Wait()
	close(errs)
	won := 0
	for err := range errs {
		if err == nil {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("exactly one concurrent registration of the same name may win; %d did", won)
	}
}

// withPrincipal returns a context authenticated as the given subject, the way
// the HTTP layer injects it.
func withPrincipal(sub string) context.Context {
	return context.WithValue(context.Background(), principalKey, &auth.Principal{Subject: sub})
}

// An owner-scoped connection is invisible and uninvocable to every other
// principal — find_tools omits it and the invocation gate returns the same
// error as an unregistered tool (no existence oracle). The owner and shared
// connections behave normally.
func TestOwnerScopedUpstreamIsolation(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "alicedocs", &gateway.Upstream{Name: "alicedocs", URL: ts.URL}, WithOwner("alice")); err != nil {
		t.Fatalf("add owned upstream: %v", err)
	}
	if err := s.AddUpstream(context.Background(), "shared", &gateway.Upstream{Name: "shared", URL: ts.URL}); err != nil {
		t.Fatalf("add shared upstream: %v", err)
	}

	// find_tools: alice sees both; bob sees only the shared connection.
	if got := len(s.indexedTools("alice")); got != 2 {
		t.Fatalf("owner must see shared + own connections; got %d tools", got)
	}
	bobIdx := s.indexedTools("bob")
	if len(bobIdx) != 1 || bobIdx[0]["name"].(string) != "shared__search" {
		t.Fatalf("another principal must see ONLY shared connections; got %v", bobIdx)
	}

	// Invocation gate: bob's call is refused with the unregistered-tool error.
	out, ok := s.invokeUpstream(withPrincipal("bob"), "alicedocs__search", json.RawMessage(`{"q":"x"}`))
	if !ok || !out["isError"].(bool) {
		t.Fatalf("another principal must not invoke an owned connection: %v", out)
	}
	txt := out["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(txt, "unknown tool") || strings.Contains(txt, "owner") {
		t.Fatalf("refusal must be indistinguishable from an unregistered tool: %q", txt)
	}

	// The owner invokes it normally; everyone reaches the shared connection.
	if out, _ := s.invokeUpstream(withPrincipal("alice"), "alicedocs__search", json.RawMessage(`{"q":"x"}`)); out["isError"].(bool) {
		t.Fatalf("owner must be able to invoke their connection: %v", out)
	}
	if out, _ := s.invokeUpstream(withPrincipal("bob"), "shared__search", json.RawMessage(`{"q":"x"}`)); out["isError"].(bool) {
		t.Fatalf("shared connections must stay invocable by everyone: %v", out)
	}
}

// SetUpstreamOwner re-scopes a live connection; UpstreamList (operator view)
// reports ownership regardless of scoping.
func TestSetUpstreamOwner(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.SetUpstreamOwner("docs", "carol"); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	if out, _ := s.invokeUpstream(withPrincipal("dave"), "docs__search", json.RawMessage(`{}`)); !out["isError"].(bool) {
		t.Fatal("after scoping, another principal must be refused")
	}
	if out, _ := s.invokeUpstream(withPrincipal("carol"), "docs__search", json.RawMessage(`{"q":"x"}`)); out["isError"].(bool) {
		t.Fatalf("the new owner must be able to invoke: %v", out)
	}
	if lst := s.UpstreamList(); len(lst) != 1 || lst[0].Owner != "carol" {
		t.Fatalf("operator view must report the owner: %+v", lst)
	}
	if err := s.SetUpstreamOwner("ghost", "x"); err == nil {
		t.Fatal("scoping an unknown upstream must error")
	}
}
