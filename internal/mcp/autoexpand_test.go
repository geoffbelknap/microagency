package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"microagency/internal/gateway"
)

// upTool describes a tool a guardUpstream advertises.
type upTool struct {
	name     string
	schema   string // inputSchema JSON; "" → "{}"
	readOnly *bool  // nil → no annotation
}

func toolListJSON(tools []upTool) string {
	var entries []string
	for _, tl := range tools {
		schema := tl.schema
		if schema == "" {
			schema = "{}"
		}
		ann := ""
		if tl.readOnly != nil {
			ann = fmt.Sprintf(`,"annotations":{"readOnlyHint":%v}`, *tl.readOnly)
		}
		entries = append(entries, fmt.Sprintf(`{"name":%q,"description":"the %s tool","inputSchema":%s%s}`, tl.name, tl.name, schema, ann))
	}
	return `{"jsonrpc":"2.0","id":1,"result":{"tools":[` + strings.Join(entries, ",") + `]}}`
}

// guardUpstream serves the given tools and, on tools/call, increments *hit and
// returns either a success or an isError result (callErr).
func guardUpstream(t *testing.T, tools []upTool, callErr bool, hit *int32) *httptest.Server {
	t.Helper()
	list := toolListJSON(tools)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			io.WriteString(w, list)
		case "tools/call":
			atomic.AddInt32(hit, 1)
			if callErr {
				io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"upstream rejected the call"}],"isError":true}}`)
			} else {
				io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}`)
			}
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
}

func addGuarded(t *testing.T, tools []upTool, callErr bool) (*Server, *int32) {
	t.Helper()
	var hit int32
	up := guardUpstream(t, tools, callErr, &hit)
	t.Cleanup(up.Close)
	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}
	return s, &hit
}

func ptrBool(b bool) *bool { return &b }

const reqSchema = `{"type":"object","required":["x"],"properties":{"x":{"type":"string"}}}`

// Tier 1: a malformed WRITE is blocked before any egress — no upstream dial — and
// the agent gets the full spec (problems + description + inputSchema) to retry.
func TestTier1BlocksMalformedWriteBeforeEgress(t *testing.T) {
	s, hit := addGuarded(t, []upTool{{name: "create-thing", schema: reqSchema}}, false)

	out := call(t, s, "call_tool", map[string]any{"name": "u__create-thing", "arguments": map[string]any{}})

	if e, _ := out["isError"].(bool); !e {
		t.Fatalf("expected a fail-closed block, got %v", out)
	}
	blob, _ := json.Marshal(out)
	for _, want := range []string{"microagency_block", "missing required field: x", "inputSchema"} {
		if !strings.Contains(string(blob), want) {
			t.Fatalf("block result missing %q: %s", want, blob)
		}
	}
	if n := atomic.LoadInt32(hit); n != 0 {
		t.Fatalf("malformed write reached the upstream %d time(s) — not fail-closed", n)
	}
}

// Tier 1 must not block a well-formed write — it proxies through untouched.
func TestTier1AllowsValidWrite(t *testing.T) {
	s, hit := addGuarded(t, []upTool{{name: "create-thing", schema: reqSchema}}, false)

	out := call(t, s, "call_tool", map[string]any{"name": "u__create-thing", "arguments": map[string]any{"x": "hello"}})
	if e, _ := out["isError"].(bool); e {
		t.Fatalf("valid write was blocked: %v", out)
	}
	if n := atomic.LoadInt32(hit); n != 1 {
		t.Fatalf("valid write reached upstream %d time(s), want 1", n)
	}
}

// Reads are never hard-blocked pre-egress, even with a structural gap — the upstream
// judges, and Tier 2 recovers the spec on error.
func TestTier1SkipsReads(t *testing.T) {
	s, hit := addGuarded(t, []upTool{{name: "get-thing", schema: reqSchema}}, false)

	call(t, s, "call_tool", map[string]any{"name": "u__get-thing", "arguments": map[string]any{}})
	if n := atomic.LoadInt32(hit); n != 1 {
		t.Fatalf("a read was hard-blocked pre-egress (upstream hit=%d, want 1)", n)
	}
}

// Tier 2: an upstream tool error gets the full description + inputSchema appended for
// an informed retry — for reads too.
func TestTier2AttachesSpecOnUpstreamError(t *testing.T) {
	s, _ := addGuarded(t, []upTool{{name: "get-thing", schema: `{"type":"object","properties":{"q":{"type":"string"}}}`}}, true)

	out := call(t, s, "call_tool", map[string]any{"name": "u__get-thing", "arguments": map[string]any{"q": "x"}})
	if e, _ := out["isError"].(bool); !e {
		t.Fatalf("expected the upstream error to pass through, got %v", out)
	}
	blob, _ := json.Marshal(out)
	for _, want := range []string{"upstream rejected the call", "microagency_note", "inputSchema"} {
		if !strings.Contains(string(blob), want) {
			t.Fatalf("error result missing %q: %s", want, blob)
		}
	}
}

// The MCP readOnlyHint is authoritative: a write-named tool marked read-only is NOT
// hard-blocked; a read-named tool marked not-read-only IS write-guarded.
func TestReadOnlyHintOverridesNameHeuristic(t *testing.T) {
	// write name, readOnlyHint:true → treated as read → not blocked
	s, hit := addGuarded(t, []upTool{{name: "create-thing", schema: reqSchema, readOnly: ptrBool(true)}}, false)
	out := call(t, s, "call_tool", map[string]any{"name": "u__create-thing", "arguments": map[string]any{}})
	if e, _ := out["isError"].(bool); e {
		t.Fatalf("read-only-annotated tool was hard-blocked: %v", out)
	}
	if n := atomic.LoadInt32(hit); n != 1 {
		t.Fatalf("read-only tool should proxy (hit=%d, want 1)", n)
	}

	// read name, readOnlyHint:false → treated as write → blocked
	s2, hit2 := addGuarded(t, []upTool{{name: "get-thing", schema: reqSchema, readOnly: ptrBool(false)}}, false)
	out2 := call(t, s2, "call_tool", map[string]any{"name": "u__get-thing", "arguments": map[string]any{}})
	if e, _ := out2["isError"].(bool); !e {
		t.Fatalf("readOnlyHint:false must be write-guarded and blocked: %v", out2)
	}
	if n := atomic.LoadInt32(hit2); n != 0 {
		t.Fatalf("blocked write should not reach upstream (hit=%d)", n)
	}
}

func TestSchemaGapsIsConservative(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","required":["a"],"properties":{"a":{"type":"string"},"obj":{"type":"object"},"arr":{"type":"array"}}}`)
	cases := []struct {
		name    string
		args    string
		wantGap bool
	}{
		{"valid", `{"a":"x"}`, false},
		{"missing required", `{}`, true},
		{"scalar coercion not flagged", `{"a":5}`, false},          // string declared, number given — upstream may coerce
		{"unknown field not flagged", `{"a":"x","zzz":1}`, false},  // no additionalProperties:false
		{"object given scalar flagged", `{"a":"x","obj":"no"}`, true},
		{"array given scalar flagged", `{"a":"x","arr":"no"}`, true},
		{"null value not flagged", `{"a":"x","obj":null}`, false},
	}
	for _, c := range cases {
		got := len(schemaGaps(schema, json.RawMessage(c.args))) > 0
		if got != c.wantGap {
			t.Errorf("%s: gaps=%v want %v (args=%s → %v)", c.name, got, c.wantGap, c.args, schemaGaps(schema, json.RawMessage(c.args)))
		}
	}
	// Permissive schemas never block.
	if len(schemaGaps(json.RawMessage(``), json.RawMessage(`{}`))) != 0 {
		t.Error("empty schema must not flag")
	}
	if len(schemaGaps(json.RawMessage(`{"type":"object"}`), json.RawMessage(`{}`))) != 0 {
		t.Error("propertyless schema must not flag")
	}
	if len(schemaGaps(json.RawMessage(`{"type":"string"}`), json.RawMessage(`"hi"`))) != 0 {
		t.Error("non-object schema must not flag")
	}
}

func TestIsWriteToolClassification(t *testing.T) {
	writes := []string{"notion-create-database", "notion-update-page", "notion-move-pages", "notion-duplicate-page", "create_api_key", "weird-nonverb-tool"}
	reads := []string{"notion-search", "notion-get-users", "notion-query-data-sources", "notion-fetch", "batch_search_iocs"}
	for _, n := range writes {
		if !isWriteTool(gateway.Tool{Name: n}) {
			t.Errorf("%q should classify as write", n)
		}
	}
	for _, n := range reads {
		if isWriteTool(gateway.Tool{Name: n}) {
			t.Errorf("%q should classify as read", n)
		}
	}
	if isWriteTool(gateway.Tool{Name: "create-x", Annotations: &gateway.ToolAnnotations{ReadOnlyHint: ptrBool(true)}}) {
		t.Error("readOnlyHint:true must override the name heuristic → read")
	}
	if !isWriteTool(gateway.Tool{Name: "get-x", Annotations: &gateway.ToolAnnotations{ReadOnlyHint: ptrBool(false)}}) {
		t.Error("readOnlyHint:false must override the name heuristic → write")
	}
}
