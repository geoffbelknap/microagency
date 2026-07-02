package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

func handleMethod(t *testing.T, s *Server, method string) rpcResponse {
	t.Helper()
	line, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method})
	resp, write := s.Handle(context.Background(), line)
	if !write {
		t.Fatalf("%s: expected a response", method)
	}
	return resp
}

// TestProtocolCompat covers the MCP methods a real client (Claude/ChatGPT) sends
// beyond tools: ping must return an empty result (keep-alive), and resources/
// prompts listing answers empty rather than erroring.
func TestProtocolCompat(t *testing.T) {
	s := newTestServer(t, fakeRunner{})

	if resp := handleMethod(t, s, "ping"); resp.Error != nil {
		t.Fatalf("ping errored: %+v", resp.Error)
	}
	if resp := handleMethod(t, s, "resources/list"); resp.Error != nil {
		t.Fatalf("resources/list errored: %+v", resp.Error)
	} else if _, ok := resp.Result.(map[string]any)["resources"]; !ok {
		t.Fatalf("resources/list missing resources key: %+v", resp.Result)
	}
	if resp := handleMethod(t, s, "prompts/list"); resp.Error != nil {
		t.Fatalf("prompts/list errored: %+v", resp.Error)
	} else if _, ok := resp.Result.(map[string]any)["prompts"]; !ok {
		t.Fatalf("prompts/list missing prompts key: %+v", resp.Result)
	}

	// An unknown method still errors (method not found).
	if resp := handleMethod(t, s, "bogus/method"); resp.Error == nil {
		t.Fatal("unknown method should error")
	}
}
