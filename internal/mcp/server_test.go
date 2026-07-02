package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"microagency/internal/router"
)

// fakeRunner returns a canned Decision without booting a VM.
type fakeRunner struct {
	dec router.Decision
	err error
}

func (f fakeRunner) Run(ctx context.Context, req router.Request) (router.Decision, error) {
	return f.dec, f.err
}

func newTestServer(t *testing.T, r Runner, opts ...Option) *Server {
	t.Helper()
	return NewServer(r, opts...)
}

// call drives one tools/call through Handle and returns the parsed tool result.
func call(t *testing.T, s *Server, tool string, args map[string]any) map[string]any {
	t.Helper()
	argsB, _ := json.Marshal(args)
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": json.RawMessage(argsB)})
	line, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})
	resp, write := s.Handle(context.Background(), line)
	if !write {
		t.Fatal("expected a response")
	}
	if resp.Error != nil {
		t.Fatalf("protocol error: %+v", resp.Error)
	}
	return resp.Result.(map[string]any)
}

func TestInitialize(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	line, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize"})
	resp, write := s.Handle(context.Background(), line)
	if !write || resp.Error != nil {
		t.Fatalf("initialize failed: %+v", resp)
	}
	if resp.Result.(map[string]any)["protocolVersion"] == nil {
		t.Fatal("initialize result missing protocolVersion")
	}
}

func TestToolsListHasNativeTools(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	line, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/list"})
	resp, _ := s.Handle(context.Background(), line)
	tools := resp.Result.(map[string]any)["tools"].([]map[string]any)
	names := map[string]bool{}
	for _, td := range tools {
		names[td["name"].(string)] = true
	}
	for _, want := range []string{"reduce", "find_tools", "call_tool"} {
		if !names[want] {
			t.Fatalf("tools/list missing %q (got %v)", want, names)
		}
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	line, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "initialized"}) // no id
	_, write := s.Handle(context.Background(), line)
	if write {
		t.Fatal("a notification (no id) must not get a response")
	}
}

func TestParseErrorReturnsNullID(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	resp, write := s.Handle(context.Background(), []byte("{ this is not valid json"))
	if !write {
		t.Fatal("parse error should produce a response")
	}
	if string(resp.ID) != "null" {
		t.Fatalf("parse-error id = %q, want null (JSON-RPC 2.0 §5)", string(resp.ID))
	}
	if resp.Error == nil || resp.Error.Code != -32700 {
		t.Fatalf("expected -32700 parse error, got %+v", resp.Error)
	}
}

// mustText decodes the first text content block of a tool result into v.
func mustText(t *testing.T, res map[string]any, v any) {
	t.Helper()
	text := res["content"].([]map[string]any)[0]["text"].(string)
	if err := json.Unmarshal([]byte(text), v); err != nil {
		t.Fatalf("decode tool result text: %v\n%s", err, text)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
