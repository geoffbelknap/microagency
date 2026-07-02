package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cannedUpstream is a minimal MCP-over-HTTP server: it answers initialize,
// tools/list, and tools/call with fixed responses, and optionally requires a
// bearer token. It lets the client be tested without the real server.
func cannedUpstream(t *testing.T, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`)
		case "tools/list":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[
				{"name":"search","description":"search the corpus","inputSchema":{"type":"object"}},
				{"name":"fetch","description":"fetch a doc"}
			]}}`)
		case "tools/call":
			var p struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(req.Params, &p)
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"called `+p.Name+`"}],"isError":false}}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}))
}

func TestUpstreamListAndCall(t *testing.T) {
	ts := cannedUpstream(t, "")
	defer ts.Close()
	u := &Upstream{Name: "docs", URL: ts.URL}
	ctx := context.Background()

	if err := u.Initialize(ctx); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	tools, err := u.ListTools(ctx)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 2 || tools[0].Name != "search" || tools[1].Name != "fetch" {
		t.Fatalf("unexpected tools: %+v", tools)
	}

	res, err := u.CallTool(ctx, "search", json.RawMessage(`{"q":"x"}`))
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !strings.Contains(string(res), "called search") {
		t.Fatalf("unexpected call result: %s", res)
	}
}

func TestUpstreamToken(t *testing.T) {
	ts := cannedUpstream(t, "sekret")
	defer ts.Close()
	ctx := context.Background()

	if _, err := (&Upstream{Name: "x", URL: ts.URL}).ListTools(ctx); err == nil {
		t.Fatal("expected unauthorized without a token")
	}
	if _, err := (&Upstream{Name: "x", URL: ts.URL, Token: "sekret"}).ListTools(ctx); err != nil {
		t.Fatalf("with token: %v", err)
	}
}

func TestUpstreamSurfacesRPCError(t *testing.T) {
	ts := cannedUpstream(t, "")
	defer ts.Close()
	if _, err := (&Upstream{Name: "x", URL: ts.URL}).call(context.Background(), "bogus/method", nil); err == nil {
		t.Fatal("expected an rpc error to surface")
	}
}
