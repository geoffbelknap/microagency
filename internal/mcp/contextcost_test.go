package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
)

// contextEvalConn is a hermetic upstream fixture. It validates the selected
// tool and arguments before returning a large result, so the baseline exercises
// discovery quality, argument validity, parking, and task completion without
// network access or a microVM.
type contextEvalConn struct {
	tools  []gateway.Tool
	result json.RawMessage
	calls  int
}

func (c *contextEvalConn) Initialize(context.Context) error                  { return nil }
func (c *contextEvalConn) ListTools(context.Context) ([]gateway.Tool, error) { return c.tools, nil }
func (c *contextEvalConn) Probe(context.Context) (string, error)             { return "", nil }
func (c *contextEvalConn) Endpoint() string                                  { return "stdio://context-eval" }
func (c *contextEvalConn) CallTool(_ context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	if name != "search_reports" {
		return nil, fmt.Errorf("unexpected tool %q", name)
	}
	var in struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(args, &in); err != nil || in.Status == "" {
		return nil, fmt.Errorf("status is required")
	}
	c.calls++
	return c.result, nil
}

func contextEvalTools() []gateway.Tool {
	tools := make([]gateway.Tool, 0, 64)
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("catalog_operation_%02d", i)
		desc := "manage catalog records " + strings.Repeat("with bounded fixture detail. ", 20)
		if i == 0 {
			name = "search_reports"
			desc = "quarterly dossier search across reports " + strings.Repeat("with bounded fixture detail. ", 20)
		}
		tools = append(tools, gateway.Tool{
			Name:        name,
			Description: desc,
			InputSchema: json.RawMessage(`{"type":"object","required":["status"],"properties":{"status":{"type":"string","description":"report status filter"},"team":{"type":"string","description":"optional owning team"}}}`),
		})
	}
	return tools
}

// TestContextCostBaseline is the reproducible offline evaluation entry point:
//
//	go test ./internal/mcp -run TestContextCostBaseline -v
//
// Keep its thresholds explicit. A change that grows context or degrades tool
// selection must update the behavior intentionally, not silently move a fixture.
func TestContextCostBaseline(t *testing.T) {
	dir := t.TempDir()
	store := refstore.NewMemStore()
	payload := `[{"id":1,"status":"open"},` + strings.Repeat(`{"id":2,"status":"open"},`, 800) + `{"id":3,"status":"closed"}]`
	result, _ := json.Marshal(map[string]any{
		"content": []map[string]any{{"type": "text", "text": payload}},
		"isError": false,
	})
	conn := &contextEvalConn{tools: contextEvalTools(), result: result}
	s := newTestServer(t, fakeRunner{}, WithStateDir(dir),
		WithBudgetGate(budget.Gate{MaxBytes: 1024, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))
	if err := s.AddUpstream(context.Background(), "reports", conn); err != nil {
		t.Fatalf("add fixture upstream: %v", err)
	}

	const taskID = "eval-task-001"
	const discoveryQuery = "quarterly dossier"
	broad := call(t, s, "find_tools", map[string]any{"query": discoveryQuery, "limit": 64, "task_id": taskID})
	found := foundTools(t, broad)
	if len(found) == 0 || found[0].Name != "reports__search_reports" {
		t.Fatalf("selection failed: top result = %+v", found)
	}
	if found[0].InputSchema == nil {
		t.Fatal("argument schema missing from selected tool")
	}
	// Fetching the exact schema after a broad search is an observable escalation.
	call(t, s, "find_tools", map[string]any{"query": "reports__search_reports", "task_id": taskID})

	invocation := call(t, s, "call_tool", map[string]any{
		"name": "reports__search_reports", "arguments": map[string]any{"status": "open"}, "task_id": taskID,
	})
	if isErr, _ := invocation["isError"].(bool); isErr || conn.calls != 1 {
		t.Fatalf("valid invocation did not complete: calls=%d result=%v", conn.calls, invocation)
	}
	invPayload := toolContentJSON(t, invocation)
	ref, _ := invPayload["ref"].(string)
	if ref == "" {
		t.Fatalf("large result was not parked: %v", invPayload)
	}
	reduced := call(t, s, "reduce", map[string]any{"ref": ref, "query": ".", "engine": "jq", "task_id": taskID})
	if isErr, _ := reduced["isError"].(bool); isErr {
		t.Fatalf("reduction did not complete: %v", reduced)
	}

	m := s.Metrics()
	if m.Context.Discovery.Calls != 2 || m.Context.Tasks.SchemaEscalations != 1 {
		t.Fatalf("discovery accounting = %+v tasks=%+v", m.Context.Discovery, m.Context.Tasks)
	}
	if m.Context.Discovery.FullSchemaEntries == 0 || m.Context.Discovery.SchemaDigestEntries == 0 || m.Context.Discovery.SummarizedEntries != m.Context.Discovery.SchemaDigestEntries {
		t.Fatalf("schema detail accounting = %+v", m.Context.Discovery)
	}
	if m.Context.Invocation.Calls != 1 || m.Context.Invocation.RawUpstreamBytes != int64(len(result)) || m.Context.Invocation.ParkedBytes != int64(len(payload)) {
		t.Fatalf("invocation accounting = %+v", m.Context.Invocation)
	}
	if m.Context.Invocation.ContextBytes >= m.Context.Invocation.RawUpstreamBytes {
		t.Fatalf("parked invocation did not reduce context: %+v", m.Context.Invocation)
	}
	if m.Context.Reduction.Calls != 1 || m.Context.Reduction.InputBytes != int64(len(payload)) {
		t.Fatalf("reduction accounting = %+v", m.Context.Reduction)
	}
	if m.Context.Tasks.CorrelatedTasks != 1 || m.Context.Tasks.SeparateInvokeReduceTrips != 1 || m.Context.Tasks.FusedInvokeReduceTrips != 0 {
		t.Fatalf("task accounting = %+v", m.Context.Tasks)
	}
	if got, want := m.Context.BytesToContext, measuredContextBytes(s.RunLog()); got != want {
		t.Fatalf("context bytes = %d, want exact run sum %d", got, want)
	}
	if m.Context.Discovery.ContextBytes > 2*(findToolsHardMax+8<<10) {
		t.Fatalf("discovery context exceeded baseline: %d", m.Context.Discovery.ContextBytes)
	}

	// Neither the task value nor the discovery query is retained in the durable
	// metric/audit records. Only a one-way task correlation key and query byte count
	// survive; raw tool arguments remain covered by the existing audit contract.
	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), taskID) || strings.Contains(string(audit), discoveryQuery) {
		t.Fatalf("audit retained task/query content: %s", audit)
	}
	if prom := m.Prometheus(); strings.Contains(prom, taskID) || strings.Contains(prom, "task_id=") {
		t.Fatalf("Prometheus output has unbounded task labels:\n%s", prom)
	}

	report, _ := json.Marshal(map[string]any{
		"catalog_tools": len(conn.tools), "selection": found[0].Name,
		"arguments_valid":              conn.calls == 1,
		"discovery_context_bytes":      m.Context.Discovery.ContextBytes,
		"full_schema_entries":          m.Context.Discovery.FullSchemaEntries,
		"schema_digest_entries":        m.Context.Discovery.SchemaDigestEntries,
		"summarized_entries":           m.Context.Discovery.SummarizedEntries,
		"omitted_entries":              m.Context.Discovery.OmittedEntries,
		"invocation_raw_bytes":         m.Context.Invocation.RawUpstreamBytes,
		"invocation_context_bytes":     m.Context.Invocation.ContextBytes,
		"reduce_input_bytes":           m.Context.Reduction.InputBytes,
		"reduce_context_bytes":         m.Context.Reduction.ContextBytes,
		"total_context_bytes":          m.Context.BytesToContext,
		"approx_context_tokens":        m.Context.EstTokensToContext,
		"schema_escalations":           m.Context.Tasks.SchemaEscalations,
		"separate_invoke_reduce_trips": m.Context.Tasks.SeparateInvokeReduceTrips,
		"task_completed":               true,
	})
	t.Logf("context-cost baseline: %s", report)
}

func measuredContextBytes(runs []RunInfo) int64 {
	var total int64
	for _, run := range runs {
		if run.ContextMeasured && (run.Kind == "discovery" || run.Kind == "proxy" || run.Kind == "reduce") {
			total += int64(run.OutputBytes)
		}
	}
	return total
}

func TestContextMetricsReplayDoesNotRelabelLegacyOutput(t *testing.T) {
	dir := t.TempDir()
	s := newTestServer(t, fakeRunner{}, WithStateDir(dir))
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", OutputBytes: 500})
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", RawBytes: 900, OutputBytes: 90, ContextMeasured: true})

	replayed := newTestServer(t, fakeRunner{}, WithStateDir(dir)).Metrics()
	if replayed.Context.Invocation.Calls != 1 || replayed.Context.Invocation.ContextBytes != 90 || replayed.Context.Invocation.RawUpstreamBytes != 900 {
		t.Fatalf("legacy output was relabeled during replay: %+v", replayed.Context.Invocation)
	}
	if replayed.Impact.BytesToContext != 590 {
		t.Fatalf("legacy impact compatibility lost: %+v", replayed.Impact)
	}
}

func TestContextTaskAggregationMeasuresFusedAndSeparatePaths(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	task, err := validateTaskID("aggregate-task")
	if err != nil {
		t.Fatal(err)
	}
	s.putRun(s.nextRunID(), runRecord{Kind: "discovery", TaskID: task, LatencyMs: 3, ContextMeasured: true})
	s.putRun(s.nextRunID(), runRecord{Kind: "discovery", TaskID: task, ExactSchemaLookup: true, LatencyMs: 7, ContextMeasured: true})
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", TaskID: task, Reffed: true, Ref: "<ref_separate>", LatencyMs: 11, ContextMeasured: true})
	s.putRun(s.nextRunID(), runRecord{Kind: "reduce", TaskID: task, SourceID: "<ref_separate>", LatencyMs: 13, ContextMeasured: true})
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", TaskID: task, FusedInvocation: true, LatencyMs: 17, ContextMeasured: true})

	m := s.Metrics()
	if m.Context.Tasks.CorrelatedTasks != 1 || m.Context.Tasks.SchemaEscalations != 1 || m.Context.Tasks.SeparateInvokeReduceTrips != 1 || m.Context.Tasks.FusedInvokeReduceTrips != 1 {
		t.Fatalf("task paths = %+v", m.Context.Tasks)
	}
	if m.Context.Discovery.P50LatencyMs != 7 || m.Context.Invocation.P50LatencyMs != 17 || m.Context.Reduction.P50LatencyMs != 13 {
		t.Fatalf("stage latency = discovery %d invocation %d reduction %d", m.Context.Discovery.P50LatencyMs, m.Context.Invocation.P50LatencyMs, m.Context.Reduction.P50LatencyMs)
	}
}

func TestTaskIDValidationAndOneWayStorage(t *testing.T) {
	for _, invalid := range []string{"contains space", "user@example.com", strings.Repeat("a", maxTaskIDBytes+1), "-starts-wrong"} {
		if _, err := validateTaskID(invalid); err == nil {
			t.Errorf("validateTaskID(%q) succeeded", invalid)
		}
	}
	a, err := validateTaskID("run-123:attempt_2")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := validateTaskID("run-123:attempt_2")
	if a != b || a == "run-123:attempt_2" || !strings.HasPrefix(a, "task_") {
		t.Fatalf("task correlation key is not stable and one-way: %q / %q", a, b)
	}
}
