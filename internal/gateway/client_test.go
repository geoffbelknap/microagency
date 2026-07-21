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

// A Streamable-HTTP upstream may emit progress/logging NOTIFICATIONS on the SSE
// stream before the actual response. The client must skip them and read the
// response event, not misread the first notification as a malformed reply.
func TestUpstreamSSEResponseAfterNotifications(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "text/event-stream")
		switch req.Method {
		case "tools/call":
			// Two notifications (no id, has method) arrive before the response event.
			io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":0.5}}\n\n")
			io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}\n\n")
			io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"the real answer\"}],\"isError\":false}}\n\n")
		default:
			io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
		}
	}))
	defer ts.Close()

	u := &Upstream{Name: "streamy", URL: ts.URL}
	res, err := u.CallTool(context.Background(), "search", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("call tool over SSE: %v", err)
	}
	if !strings.Contains(string(res), "the real answer") {
		t.Fatalf("expected the response event, not a leading notification: %s", res)
	}
}

func TestSSEResponseSelectsResponseEvent(t *testing.T) {
	notif := `data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}`
	respEv := `data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}`
	body := []byte(notif + "\n\n" + respEv + "\n\n")
	got := sseResponse(body)
	if !strings.Contains(string(got), `"result"`) || strings.Contains(string(got), "notifications/progress") {
		t.Fatalf("sseResponse picked the wrong event: %s", got)
	}
	// An error response is also a response (no method, has error).
	errBody := []byte(notif + "\n\n" + `data: {"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}` + "\n\n")
	if got := sseResponse(errBody); !strings.Contains(string(got), `"error"`) {
		t.Fatalf("sseResponse should select an error response: %s", got)
	}
	// Non-SSE bodies pass through unchanged.
	plain := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	if got := sseResponse(plain); string(got) != string(plain) {
		t.Fatalf("non-SSE body must pass through: %s", got)
	}
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
