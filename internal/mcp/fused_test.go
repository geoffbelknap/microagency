package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/minimize"
	"microagency/internal/refstore"
	"microagency/internal/router"
)

type fusedConn struct {
	tools  []gateway.Tool
	result json.RawMessage
	calls  int
}

func (c *fusedConn) Initialize(context.Context) error                  { return nil }
func (c *fusedConn) ListTools(context.Context) ([]gateway.Tool, error) { return c.tools, nil }
func (c *fusedConn) Probe(context.Context) (string, error)             { return "", nil }
func (c *fusedConn) Endpoint() string                                  { return "stdio://fused-fixture" }
func (c *fusedConn) CallTool(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	c.calls++
	return c.result, nil
}

type fusedEngine struct {
	output []byte
	err    error
	calls  int
	query  string
	input  string
}

func (e *fusedEngine) Run(_ context.Context, query string, input []byte) ([]byte, error) {
	e.calls++
	e.query, e.input = query, string(input)
	return e.output, e.err
}

type countingRunner struct{ calls int }

func (r *countingRunner) Run(context.Context, router.Request) (router.Decision, error) {
	r.calls++
	return router.Decision{}, errors.New("microVM runner must not be used by a declarative transform")
}

func fusedUpstreamResult(payload string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"content": []map[string]any{{"type": "text", "text": payload}},
		"isError": false,
	})
	return raw
}

func TestCallToolFusesDeclarativeTransform(t *testing.T) {
	const rawSentinel = "RAW_DATASET_SENTINEL"
	const argSentinel = "ARGUMENT_SENTINEL"
	payload := `[{"id":1,"value":"` + rawSentinel + `"},` + strings.Repeat(`{"id":2,"value":"x"},`, 200) + `{"id":3,"value":"y"}]`
	conn := &fusedConn{
		tools:  []gateway.Tool{{Name: "search_rows", Description: "Search rows", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		result: fusedUpstreamResult(payload),
	}
	engine := &fusedEngine{output: []byte(`{"count":202}`)}
	runner := &countingRunner{}
	dir := t.TempDir()
	s := newTestServer(t, runner, WithStateDir(dir),
		WithBudgetGate(budget.Gate{MaxBytes: 1024, Store: refstore.NewMemStore()}),
		WithWasmEngine("jq", engine))
	if err := s.AddUpstream(context.Background(), "data", conn); err != nil {
		t.Fatal(err)
	}

	out := call(t, s, "call_tool", map[string]any{
		"name": "data__search_rows", "arguments": map[string]any{"filter": argSentinel},
		"transform": map[string]any{"engine": "jq", "query": "length"}, "task_id": "task-fused-1",
	})
	if isErr, _ := out["isError"].(bool); isErr {
		t.Fatalf("fused call failed: %v", out)
	}
	if conn.calls != 1 || engine.calls != 1 || runner.calls != 0 {
		t.Fatalf("calls: upstream=%d engine=%d microvm=%d", conn.calls, engine.calls, runner.calls)
	}
	if engine.input != payload || strings.Contains(engine.input, argSentinel) {
		t.Fatalf("engine received anything other than the upstream payload: %q", engine.input)
	}
	result := toolContentJSON(t, out)
	if result["result"] != `{"count":202}` {
		t.Fatalf("transformed answer missing: %v", result)
	}
	provenance, _ := result["provenance"].(map[string]any)
	transformation, _ := provenance["transformation"].(map[string]any)
	if provenance["source_tool"] != "data__search_rows" || transformation["engine"] != "jq" || transformation["query_sha256"] != transformDigest("length") {
		t.Fatalf("provenance = %v", provenance)
	}
	encoded, _ := json.Marshal(out)
	if strings.Contains(string(encoded), rawSentinel) || strings.Contains(string(encoded), argSentinel) {
		t.Fatalf("raw result or arguments entered context: %s", encoded)
	}

	runs := s.RunLog()
	if len(runs) != 1 || !runs[0].FusedInvocation || runs[0].TransformStatus != "succeeded" || runs[0].TransformEngine != "jq" || runs[0].TransformQuerySHA256 != transformDigest("length") {
		t.Fatalf("fused audit record = %+v", runs)
	}
	if runs[0].TransformInputBytes != len(payload) || runs[0].TransformOutputBytes != len(engine.output) {
		t.Fatalf("transform byte accounting = %+v", runs[0])
	}
	metrics := s.Metrics()
	if metrics.Context.Tasks.FusedInvokeReduceTrips != 1 || metrics.Context.Tasks.SeparateInvokeReduceTrips != 0 {
		t.Fatalf("fused metrics = %+v", metrics.Context.Tasks)
	}
	if wasm := metrics.BySubstrate["wasm"]; wasm == nil || wasm.InputBytesTotal != len(payload) || wasm.OutputBytesTotal != len(engine.output) {
		t.Fatalf("fused substrate metrics = %+v", wasm)
	}

	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), "length") || strings.Contains(string(audit), rawSentinel) {
		t.Fatalf("audit retained transform query or raw payload: %s", audit)
	}
}

func TestFusedTransformWriteFailureDoesNotRetryOrLeak(t *testing.T) {
	const rawSentinel = "PROTECTED_ROW_SENTINEL"
	conn := &fusedConn{
		tools: []gateway.Tool{{
			Name: "create_record", Description: "Create a record",
			InputSchema: json.RawMessage(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`),
		}},
		result: fusedUpstreamResult(`{"id":"1","value":"` + rawSentinel + `"}`),
	}
	engine := &fusedEngine{err: errors.New("engine echoed " + rawSentinel)}
	s := newTestServer(t, fakeRunner{}, WithStateDir(t.TempDir()),
		WithBudgetGate(budget.Gate{MaxBytes: 1024, Store: refstore.NewMemStore()}),
		WithWasmEngine("jq", engine))
	if err := s.AddUpstream(context.Background(), "writes", conn); err != nil {
		t.Fatal(err)
	}

	out := call(t, s, "call_tool", map[string]any{
		"name": "writes__create_record", "arguments": map[string]any{"name": "one"},
		"transform": map[string]any{"query": ".id", "engine": "jq"},
	})
	raw, _ := json.Marshal(out)
	if isErr, _ := out["isError"].(bool); !isErr || !strings.Contains(string(raw), "Do not automatically retry") {
		t.Fatalf("write transform failure did not fail closed: %s", raw)
	}
	if conn.calls != 1 || engine.calls != 1 {
		t.Fatalf("mutating upstream was retried: upstream=%d engine=%d", conn.calls, engine.calls)
	}
	if strings.Contains(string(raw), rawSentinel) {
		t.Fatalf("engine/raw failure detail leaked: %s", raw)
	}
	run := s.RunLog()[0]
	if !run.FusedInvocation || run.TransformStatus != "engine_error" || run.ExitCode == 0 || strings.Contains(run.AuditErr, rawSentinel) {
		t.Fatalf("write failure audit = %+v", run)
	}
}

func TestFusedTransformWriteSucceedsWithOneMutation(t *testing.T) {
	conn := &fusedConn{
		tools: []gateway.Tool{{
			Name: "create_record", Description: "Create a record",
			InputSchema: json.RawMessage(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`),
		}},
		result: fusedUpstreamResult(`{"id":"created-1","verbose":"details"}`),
	}
	engine := &fusedEngine{output: []byte(`"created-1"`)}
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 1024, Store: refstore.NewMemStore()}),
		WithWasmEngine("jq", engine))
	if err := s.AddUpstream(context.Background(), "writes", conn); err != nil {
		t.Fatal(err)
	}
	out := call(t, s, "call_tool", map[string]any{
		"name": "writes__create_record", "arguments": map[string]any{"name": "one"},
		"transform": map[string]any{"query": ".id", "engine": "jq"},
	})
	if isErr, _ := out["isError"].(bool); isErr || conn.calls != 1 || engine.calls != 1 {
		t.Fatalf("successful mutation/transform calls=%d/%d out=%v", conn.calls, engine.calls, out)
	}
	if got := toolContentJSON(t, out)["result"]; got != `"created-1"` {
		t.Fatalf("projected mutation result = %v", got)
	}
}

func TestFusedTransformValidationIsPreEgress(t *testing.T) {
	validEngine := &fusedEngine{output: []byte("ok")}
	for _, tc := range []struct {
		name      string
		transform map[string]any
		withStore bool
	}{
		{name: "unknown engine", transform: map[string]any{"query": ".", "engine": "missing"}, withStore: true},
		{name: "arbitrary code", transform: map[string]any{"query": ".", "code": "print(1)"}, withStore: true},
		{name: "missing references", transform: map[string]any{"query": ".", "engine": "jq"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &fusedConn{tools: []gateway.Tool{{Name: "create_record", Description: "Create record"}}, result: fusedUpstreamResult("ok")}
			opts := []Option{WithWasmEngine("jq", validEngine)}
			if tc.withStore {
				opts = append(opts, WithBudgetGate(budget.Gate{MaxBytes: 1024, Store: refstore.NewMemStore()}))
			}
			s := newTestServer(t, fakeRunner{}, opts...)
			if err := s.AddUpstream(context.Background(), "svc", conn); err != nil {
				t.Fatal(err)
			}
			out := call(t, s, "call_tool", map[string]any{
				"name": "svc__create_record", "arguments": map[string]any{}, "transform": tc.transform,
			})
			if isErr, _ := out["isError"].(bool); !isErr || conn.calls != 0 {
				t.Fatalf("invalid transform reached upstream: calls=%d out=%v", conn.calls, out)
			}
		})
	}
}

func TestFusedTransformOutputThresholdAndOwnerIsolation(t *testing.T) {
	projected := strings.Repeat("projected-only-", 200)
	store := refstore.NewMemStore()
	conn := &fusedConn{
		tools:  []gateway.Tool{{Name: "search_private", Description: "Search private records"}},
		result: fusedUpstreamResult(`{"raw":"RAW_MUST_NOT_BE_STORED"}`),
	}
	engine := &fusedEngine{output: []byte(projected)}
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 128, Store: store}), WithWasmEngine("jq", engine))
	if err := s.AddUpstream(context.Background(), "owned", conn, WithOwner(pk("alice"))); err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(map[string]any{
		"name": "owned__search_private", "arguments": map[string]any{},
		"transform": map[string]any{"query": ".", "engine": "jq"},
	})
	denied := s.callTool(withPrincipal("bob"), args)
	if isErr, _ := denied["isError"].(bool); !isErr || conn.calls != 0 || engine.calls != 0 {
		t.Fatalf("owner isolation bypassed: calls=%d/%d out=%v", conn.calls, engine.calls, denied)
	}

	allowed := s.callTool(withPrincipal("alice"), args)
	result := toolContentJSON(t, allowed)
	ref, _ := result["ref"].(string)
	stored, owner, ok := store.Get(refstore.Ref(ref))
	if ref == "" || !ok || owner != pk("alice") || stored != projected || strings.Contains(stored, "RAW_MUST_NOT_BE_STORED") {
		t.Fatalf("transformed output reference = ref:%q owner:%q ok:%v bytes:%d", ref, owner, ok, len(stored))
	}
}

func TestFusedTransformPreservesFieldMinimization(t *testing.T) {
	conn := &fusedConn{tools: []gateway.Tool{{Name: "search_cards", Description: "Search cards"}}, result: fusedUpstreamResult(`[{"id":1}]`)}
	engine := &fusedEngine{output: []byte(`{"card":"` + secretCard + `"}`)}
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 1024, Store: refstore.NewMemStore()}),
		WithWasmEngine("jq", engine),
		WithMinimizer(cardTokenizer(), minimize.NewMemTokenStore()))
	if err := s.AddUpstream(context.Background(), "cards", conn); err != nil {
		t.Fatal(err)
	}
	s.SetMinimizePolicy("cards", []byte(`{"card":"tokenize"}`))
	out := call(t, s, "call_tool", map[string]any{
		"name": "cards__search_cards", "arguments": map[string]any{},
		"transform": map[string]any{"query": ".", "engine": "jq"},
	})
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), secretCard) || !strings.Contains(string(raw), "mtok_card") || !hasMinimizeAlert(s) {
		t.Fatalf("field minimization did not protect fused output: %s", raw)
	}
}
