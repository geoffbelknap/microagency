package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"microagency/internal/gateway"
)

// fakeConn is a non-HTTP upstreamConn — the whole point of the seam is that the
// gateway's storage, invocation, and health paths work over any transport, not
// just *gateway.Upstream.
type fakeConn struct {
	endpoint string
	tools    []gateway.Tool
	result   json.RawMessage
}

func (f *fakeConn) Initialize(context.Context) error                  { return nil }
func (f *fakeConn) ListTools(context.Context) ([]gateway.Tool, error) { return f.tools, nil }
func (f *fakeConn) CallTool(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	return f.result, nil
}
func (f *fakeConn) Probe(context.Context) (string, error) { return "", nil }
func (f *fakeConn) Endpoint() string                      { return f.endpoint }

// The gateway invokes and reports an upstream through the upstreamConn seam,
// independent of the concrete HTTP transport.
func TestGatewayWorksOverUpstreamConnSeam(t *testing.T) {
	fc := &fakeConn{
		endpoint: "stdio://local/echo",
		tools:    []gateway.Tool{{Name: "echo", Description: "echo it back", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		result:   json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"isError":false}`),
	}
	s := newTestServer(t, fakeRunner{})
	if err := s.registerUpstream("svc", &upstream{conn: fc, tools: fc.tools, enabled: true, provenance: "preloaded"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// The seam's Endpoint() flows to the operator view.
	if info := s.UpstreamList()[0]; info.URL != "stdio://local/echo" {
		t.Fatalf("Endpoint() not surfaced through the seam: %+v", info)
	}

	// call_tool routes through the seam's CallTool.
	out, ok := s.invokeUpstream(withPrincipal("local"), "svc__echo", json.RawMessage(`{}`))
	if !ok {
		t.Fatal("invokeUpstream did not handle the namespaced call")
	}
	if isErr, _ := out["isError"].(bool); isErr {
		raw, _ := json.Marshal(out)
		t.Fatalf("call through the seam errored: %s", raw)
	}
}

// The PUBLIC onboarding API accepts any upstreamConn, not just *gateway.Upstream —
// so a new transport (stdio, WebSocket) is aggregated through the same AddUpstream
// path, with no HTTP-specific onboarding.
func TestAddUpstreamAcceptsNonHTTPConn(t *testing.T) {
	fc := &fakeConn{
		endpoint: "stdio://svc",
		tools:    []gateway.Tool{{Name: "echo", Description: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		result:   json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"isError":false}`),
	}
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "svc", fc); err != nil {
		t.Fatalf("AddUpstream with a non-HTTP conn: %v", err)
	}
	if info := s.UpstreamList()[0]; info.URL != "stdio://svc" || info.Tools != 1 {
		t.Fatalf("onboarded conn not reflected: %+v", info)
	}
	out, ok := s.invokeUpstream(withPrincipal("local"), "svc__echo", json.RawMessage(`{}`))
	if !ok || out["isError"].(bool) {
		raw, _ := json.Marshal(out)
		t.Fatalf("call through the onboarded non-HTTP conn failed: %s", raw)
	}
}
