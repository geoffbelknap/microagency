package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
	"microagency/internal/router"
	"microagency/internal/sandbox"
	"microagency/internal/wasmexec"
)

// capturingRunner records the router.Request it received, so a test can assert how
// reduce wired the guest inputs.
type capturingRunner struct{ got router.Request }

func (c *capturingRunner) Run(_ context.Context, req router.Request) (router.Decision, error) {
	c.got = req
	return router.Decision{Inline: "ok", ExitCode: 0}, nil
}

func TestReduceSingleRefUsesAppInput(t *testing.T) {
	store := refstore.NewMemStore()
	a, _ := store.Put(`{"x":1}`)
	runner := &capturingRunner{}
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}))
	call(t, s, "reduce", map[string]any{"ref": string(a), "code": "print(1)"})
	if len(runner.got.Inputs) != 1 || runner.got.Inputs[0].Path != "/app/input" {
		t.Fatalf("a single ref must land at /app/input, got %+v", runner.got.Inputs)
	}
}

func TestReduceMultiRefJoinsInputsInCode(t *testing.T) {
	store := refstore.NewMemStore()
	a, _ := store.Put(`[{"id":1}]`)
	b, _ := store.Put(`[{"id":2}]`)
	runner := &capturingRunner{}
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}))
	out := call(t, s, "reduce", map[string]any{"refs": []string{string(a), string(b)}, "code": "print('x')"})
	if isErr, _ := out["isError"].(bool); isErr {
		raw, _ := json.Marshal(out)
		t.Fatalf("multi-ref reduce errored: %s", raw)
	}
	if len(runner.got.Inputs) != 2 {
		t.Fatalf("want 2 guest inputs, got %d", len(runner.got.Inputs))
	}
	if runner.got.Inputs[0].Path != "/app/input_1" || runner.got.Inputs[1].Path != "/app/input_2" {
		t.Fatalf("multi-ref inputs must be /app/input_1../2, got %q %q", runner.got.Inputs[0].Path, runner.got.Inputs[1].Path)
	}
	if string(runner.got.Inputs[0].Data) != `[{"id":1}]` || string(runner.got.Inputs[1].Data) != `[{"id":2}]` {
		t.Fatalf("inputs carry the wrong payloads: %q %q", runner.got.Inputs[0].Data, runner.got.Inputs[1].Data)
	}
}

func TestReduceMultiRefQueryRejectedSteerToCode(t *testing.T) {
	store := refstore.NewMemStore()
	a, _ := store.Put(`[1]`)
	b, _ := store.Put(`[2]`)
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))
	out := call(t, s, "reduce", map[string]any{"refs": []string{string(a), string(b)}, "query": "keys"})
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatal("a multi-ref declarative query must be a tool error (steer to code)")
	}
	if txt := out["content"].([]map[string]any)[0]["text"].(string); !strings.Contains(txt, "code") {
		t.Fatalf("the error must steer to code, got %q", txt)
	}
}

func TestReduceInlineDataCodeUsesAppInput(t *testing.T) {
	store := refstore.NewMemStore()
	runner := &capturingRunner{}
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}))
	out := call(t, s, "reduce", map[string]any{"data": "hello world", "code": "print(open('/app/input').read())"})
	if isErr, _ := out["isError"].(bool); isErr {
		raw, _ := json.Marshal(out)
		t.Fatalf("inline reduce errored: %s", raw)
	}
	if len(runner.got.Inputs) != 1 || runner.got.Inputs[0].Path != "/app/input" {
		t.Fatalf("inline data must land at /app/input, got %+v", runner.got.Inputs)
	}
	if string(runner.got.Inputs[0].Data) != "hello world" {
		t.Fatalf("inline input carries the wrong bytes: %q", runner.got.Inputs[0].Data)
	}
}

func TestReduceInlineDataWasm(t *testing.T) {
	store := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))
	out := call(t, s, "reduce", map[string]any{"data": `[{"x":1}]`, "query": "length"})
	if isErr, _ := out["isError"].(bool); isErr {
		raw, _ := json.Marshal(out)
		t.Fatalf("inline wasm reduce errored: %s", raw)
	}
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), "over 9 bytes") { // fakeEngine reports the input size
		t.Fatalf("wasm engine should have run over the 9-byte inline data, got %s", raw)
	}
}

func TestReduceInlineDataAndRefsRejected(t *testing.T) {
	store := refstore.NewMemStore()
	a, _ := store.Put(`[1]`)
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}))
	out := call(t, s, "reduce", map[string]any{"ref": string(a), "data": "x", "code": "print(1)"})
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatal("providing both a reference and inline data must be a tool error")
	}
}

func TestReduceInlineDataTooLargeRejected(t *testing.T) {
	store := refstore.NewMemStore()
	runner := &capturingRunner{}
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 1024, Store: store}))
	out := call(t, s, "reduce", map[string]any{"data": strings.Repeat("x", 2000), "code": "print(1)"})
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatal("inline data over the cap must be rejected (steer to a reference)")
	}
	if runner.got.Code != "" {
		t.Fatal("oversized inline data must not execute")
	}
}

func TestReduceUnknownRefInListFailsClosed(t *testing.T) {
	store := refstore.NewMemStore()
	a, _ := store.Put(`[1]`)
	runner := &capturingRunner{}
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}))
	out := call(t, s, "reduce", map[string]any{"refs": []string{string(a), "<ref_nope>"}, "code": "print(1)"})
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatal("an unknown ref anywhere in the list must fail closed")
	}
	if runner.got.Code != "" {
		t.Fatal("the run must not execute when a ref is unresolved")
	}
}

// fakeEngine is a stand-in wasm engine: it runs a "query" over provided bytes and
// returns a small summary, so reduce's WASM path is exercised without a real module.
type fakeEngine struct{}

func (fakeEngine) Run(_ context.Context, query string, data []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("reduced(%s) over %d bytes", query, len(data))), nil
}

// namedEngine reports which engine name ran, so a test can assert that reduce
// selects the engine WITHOUT rerouting (no size-based override) and never runs a
// real wasm module.
type namedEngine struct{ name string }

func (e namedEngine) Run(_ context.Context, query string, data []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("engine=%s query=%s bytes=%d", e.name, query, len(data))), nil
}

// failingEngine simulates a jq engine that exhausts its timeout, so the reduce
// error path's size-aware steer can be exercised hermetically.
type failingEngine struct{}

func (failingEngine) Run(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("context deadline exceeded")
}

// bigPayload is a ref payload at/above the large-reduce threshold.
func bigPayload() string { return strings.Repeat("x", largeReduceThreshold+1) }

// TestReduceDoesNotRerouteBySize pins the selection rule: engine choice is
// size-blind. An ambiguous (un-inferable, jq-shaped) query stays on the jq default
// at any size — it is NOT rerouted to sql (which would only mis-parse it) — and an
// explicit or inferred engine is always honored.
func TestReduceDoesNotRerouteBySize(t *testing.T) {
	newSrv := func(t *testing.T, payload string) (*Server, refstore.Ref) {
		store := refstore.NewMemStore()
		ref, _ := store.Put(payload)
		// jq registered first → wasmDefault is jq (the ambiguous/default case).
		s := newTestServer(t, fakeRunner{},
			WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
			WithWasmEngine("jq", namedEngine{"jq"}),
			WithWasmEngine("sql", namedEngine{"sql"}))
		return s, ref
	}
	reduceRaw := func(t *testing.T, s *Server, ref refstore.Ref, args map[string]any) string {
		t.Helper()
		args["ref"] = string(ref)
		out := call(t, s, "reduce", args)
		raw, _ := json.Marshal(out) // the computed result is JSON nested in content[0].text
		if isErr, _ := out["isError"].(bool); isErr {
			t.Fatalf("reduce errored: %s", raw)
		}
		return string(raw)
	}

	scan := `scan("MRN[0-9]+")` // un-inferable (not jq- or sql-shaped) → the default

	// Large ref + ambiguous query → STAYS on jq (no reroute to sql).
	sLarge, refLarge := newSrv(t, bigPayload())
	if got := reduceRaw(t, sLarge, refLarge, map[string]any{"query": scan}); !strings.Contains(got, "engine=jq") {
		t.Fatalf("a large ambiguous reduce must stay on the jq default (no sql reroute), got %q", got)
	}
	// Explicit engine is always honored.
	sExpl, refExpl := newSrv(t, bigPayload())
	if got := reduceRaw(t, sExpl, refExpl, map[string]any{"query": "SELECT 1", "engine": "sql"}); !strings.Contains(got, "engine=sql") {
		t.Fatalf("an explicit engine must always be honored, got %q", got)
	}
	// A sql-shaped query is inferred to sql at any size (already the fast substrate).
	sInfer, refInfer := newSrv(t, bigPayload())
	if got := reduceRaw(t, sInfer, refInfer, map[string]any{"query": "SELECT count(*) FROM data"}); !strings.Contains(got, "engine=sql") {
		t.Fatalf("a sql-shaped query must infer sql, got %q", got)
	}
}

// TestReduceLargeJqAdvisory: a jq reduce over a large ref succeeds AND carries a
// non-breaking advisory steering toward sql/code; a small jq reduce does not.
func TestReduceLargeJqAdvisory(t *testing.T) {
	newSrv := func(t *testing.T, payload string) (*Server, refstore.Ref) {
		store := refstore.NewMemStore()
		ref, _ := store.Put(payload)
		s := newTestServer(t, fakeRunner{},
			WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
			WithWasmEngine("jq", namedEngine{"jq"}),
			WithWasmEngine("sql", namedEngine{"sql"}))
		return s, ref
	}
	run := func(t *testing.T, payload string) string {
		s, ref := newSrv(t, payload)
		out := call(t, s, "reduce", map[string]any{"ref": string(ref), "query": "keys"})
		if isErr, _ := out["isError"].(bool); isErr {
			raw, _ := json.Marshal(out)
			t.Fatalf("reduce errored: %s", raw)
		}
		raw, _ := json.Marshal(out)
		return string(raw)
	}

	if got := run(t, bigPayload()); !strings.Contains(got, "advisory") || !strings.Contains(got, "sql") {
		t.Fatalf("a large jq reduce must carry a sql/code advisory, got %q", got)
	}
	if got := run(t, `[{"mrn":"MRN1"}]`); strings.Contains(got, "advisory") {
		t.Fatalf("a small jq reduce must NOT carry an advisory, got %q", got)
	}
}

// TestReduceLargeJqTimeoutSteer: when a large jq reduce exhausts the engine, the
// error is size-aware and names sql/code as the reformulation, not a generic timeout.
func TestReduceLargeJqTimeoutSteer(t *testing.T) {
	store := refstore.NewMemStore()
	ref, _ := store.Put(bigPayload())
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
		WithWasmEngine("jq", failingEngine{}),
		WithWasmEngine("sql", namedEngine{"sql"}))

	out := call(t, s, "reduce", map[string]any{"ref": string(ref), "query": "keys"})
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatal("a failing engine must surface an error")
	}
	raw, _ := json.Marshal(out)
	for _, want := range []string{"MB", "sql", "code"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("large jq timeout error must be a size-aware steer mentioning %q, got %s", want, raw)
		}
	}
}

// TestReduceLargeJqTimeoutSteerInlineData is the inline-data twin of the steer
// above: a large inline payload (no ref) that fails on jq must produce the same
// size-aware steer WITHOUT panicking. Regression for indexing refs[0] on the
// inline path, where refs is empty.
func TestReduceLargeJqTimeoutSteerInlineData(t *testing.T) {
	store := refstore.NewMemStore()
	// MaxBytes above the large-reduce threshold so the big inline payload is
	// accepted (not rejected as too large) and reaches the size-aware branch.
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: largeReduceThreshold * 2, Store: store}),
		WithWasmEngine("jq", failingEngine{}),
		WithWasmEngine("sql", namedEngine{"sql"}))

	out := call(t, s, "reduce", map[string]any{"data": bigPayload(), "query": "keys"})
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatal("a failing engine must surface an error")
	}
	raw, _ := json.Marshal(out)
	// The steer references the inline data (data=...), not a ref handle.
	for _, want := range []string{"MB", "sql", "code", "data="} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("large inline jq steer must mention %q, got %s", want, raw)
		}
	}
}

// errText extracts the single text block from a tool error result.
func errText(t *testing.T, out map[string]any) string {
	t.Helper()
	if isErr, _ := out["isError"].(bool); !isErr {
		raw, _ := json.Marshal(out)
		t.Fatalf("expected a tool error, got %s", raw)
	}
	return out["content"].([]map[string]any)[0]["text"].(string)
}

// auditStderrOf returns the recorded stderr of the newest "reduce" run.
func auditStderrOf(t *testing.T, s *Server) (runID, stderr string) {
	t.Helper()
	for _, r := range s.RunLog() { // newest first
		if r.Kind == "reduce" {
			return r.RunID, r.Stderr
		}
	}
	t.Fatal("no reduce run was recorded in the audit log")
	return "", ""
}

// THE stderr contract: a failed reduce-code run must NOT return the guest's
// stderr to the agent — a traceback over /app/input echoes the exact bytes the
// ref model keeps off-context. The tool error is content-free (exit code + a
// pointer to /admin/runs) and the stderr is RELOCATED, not dropped: it lands in
// the run's audit record for the operator.
func TestReduceCodeFailureKeepsStderrOutOfContext(t *testing.T) {
	const secret = `Traceback (most recent call last):\n  KeyError: 'MRN-8675309'`
	store := refstore.NewMemStore()
	ref, _ := store.Put(`{"mrn":"MRN-8675309"}`)
	s := newTestServer(t, fakeRunner{dec: router.Decision{ExitCode: 1, Stderr: secret}},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}))

	out := call(t, s, "reduce", map[string]any{"ref": string(ref), "code": "boom"})
	txt := errText(t, out)
	if strings.Contains(txt, "MRN-8675309") || strings.Contains(txt, "Traceback") {
		t.Fatalf("guest stderr leaked into the agent's context: %q", txt)
	}
	for _, want := range []string{"exit 1", "/admin/runs"} { // actionable but content-free
		if !strings.Contains(txt, want) {
			t.Fatalf("error must carry %q (exit code + operator pointer), got %q", want, txt)
		}
	}
	runID, recorded := auditStderrOf(t, s)
	if recorded != secret {
		t.Fatalf("stderr must be relocated to the audit record, got %q", recorded)
	}
	if !strings.Contains(txt, runID) {
		t.Fatalf("error must name the audit run %s, got %q", runID, txt)
	}
}

// A successful run's stderr (warnings) is recorded for the operator too.
func TestReduceCodeSuccessRecordsStderrInAudit(t *testing.T) {
	store := refstore.NewMemStore()
	ref, _ := store.Put(`[1]`)
	s := newTestServer(t, fakeRunner{dec: router.Decision{Inline: "ok", ExitCode: 0, Stderr: "DeprecationWarning: x"}},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}))
	out := call(t, s, "reduce", map[string]any{"ref": string(ref), "code": "print(1)"})
	if isErr, _ := out["isError"].(bool); isErr {
		t.Fatal("exit 0 must succeed")
	}
	if _, recorded := auditStderrOf(t, s); recorded != "DeprecationWarning: x" {
		t.Fatalf("success stderr must still reach the audit record, got %q", recorded)
	}
	if raw, _ := json.Marshal(out); strings.Contains(string(raw), "DeprecationWarning") {
		t.Fatalf("stderr leaked into a successful tool result: %s", raw)
	}
}

// exitingEngine simulates a wasm engine module that exits non-zero with data
// echoed on stderr (e.g. a jq runtime error mid-document).
type exitingEngine struct {
	code   int
	stderr string
}

func (e exitingEngine) Run(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, &wasmexec.ExitError{ExitCode: e.code, Stderr: e.stderr}
}

// Same contract on the declarative (wasm) path: an engine module's stderr can
// echo the referenced data, so it goes to the audit record, never the tool error.
func TestReduceWasmEngineExitKeepsStderrOutOfContext(t *testing.T) {
	const secret = `jq: error: cannot index "MRN-8675309"`
	store := refstore.NewMemStore()
	ref, _ := store.Put(`[{"mrn":"MRN-8675309"}]`)
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
		WithWasmEngine("jq", exitingEngine{code: 5, stderr: secret}))

	out := call(t, s, "reduce", map[string]any{"ref": string(ref), "query": "keys"})
	txt := errText(t, out)
	if strings.Contains(txt, "MRN-8675309") {
		t.Fatalf("engine stderr leaked into the agent's context: %q", txt)
	}
	for _, want := range []string{"exited 5", "/admin/runs"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("error must carry %q, got %q", want, txt)
		}
	}
	runID, recorded := auditStderrOf(t, s)
	if recorded != secret {
		t.Fatalf("engine stderr must be relocated to the audit record, got %q", recorded)
	}
	if !strings.Contains(txt, runID) {
		t.Fatalf("error must name the audit run %s, got %q", runID, txt)
	}
}

// Same contract on a sandbox guest failure: the VM console log tees guest output
// (which can echo /app/input), so it goes to the audit record, never the tool error.
func TestReduceGuestFailureKeepsSerialLogOutOfContext(t *testing.T) {
	const serial = "microagent-init: booted\npython: MRN-8675309"
	store := refstore.NewMemStore()
	ref, _ := store.Put(`{"mrn":"MRN-8675309"}`)
	s := newTestServer(t, fakeRunner{err: &sandbox.GuestFailureError{Name: "reduce-run_1", SerialLog: serial}},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}))

	out := call(t, s, "reduce", map[string]any{"ref": string(ref), "code": "print(1)"})
	txt := errText(t, out)
	if strings.Contains(txt, "MRN-8675309") || strings.Contains(txt, "booted") {
		t.Fatalf("serial log leaked into the agent's context: %q", txt)
	}
	if !strings.Contains(txt, "/admin/runs") {
		t.Fatalf("error must point the operator at the audit log, got %q", txt)
	}
	runID, recorded := auditStderrOf(t, s)
	if recorded != serial {
		t.Fatalf("serial log must be relocated to the audit record, got %q", recorded)
	}
	if !strings.Contains(txt, runID) {
		t.Fatalf("error must name the audit run %s, got %q", runID, txt)
	}
}

// upstreamReturning serves one tool whose result text is body.
func upstreamReturning(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(raw, &req)
		switch req.Method {
		case "initialize":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		case "tools/list":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"q","description":"query the db","inputSchema":{"type":"object"}}]}}`)
		case "tools/call":
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
				"content": []map[string]any{{"type": "text", "text": body}}, "isError": false,
			}})
			w.Write(b)
		}
	}))
}

func TestProxyLargeResultIsReffed(t *testing.T) {
	big := strings.Repeat("x", 5000)
	ts := upstreamReturning(t, big)
	defer ts.Close()

	store := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 1024, Store: store}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "db", URL: ts.URL}); err != nil {
		t.Fatal(err)
	}

	out := call(t, s, "call_tool", map[string]any{"name": "db__q", "arguments": map[string]any{}})
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), "ref_") || !strings.Contains(string(raw), "reffed") {
		t.Fatalf("a large proxied result must come back as a reference, got %s", raw)
	}
	if strings.Contains(string(raw), big) {
		t.Fatal("raw data leaked into context instead of being held off-context as a reference")
	}
}

func TestProxySmallResultStaysInline(t *testing.T) {
	ts := upstreamReturning(t, "small-answer")
	defer ts.Close()
	store := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 1024, Store: store}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "db", URL: ts.URL}); err != nil {
		t.Fatal(err)
	}
	out := call(t, s, "call_tool", map[string]any{"name": "db__q", "arguments": map[string]any{}})
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), "small-answer") {
		t.Fatalf("a small result should pass through inline, got %s", raw)
	}
}

func TestReduceOverRefWasm(t *testing.T) {
	store := refstore.NewMemStore()
	ref, _ := store.Put(`[{"a":1},{"a":2},{"a":3}]`)
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))

	out := call(t, s, "reduce", map[string]any{"ref": string(ref), "query": "length", "engine": "jq"})
	raw, _ := json.Marshal(out)
	if isErr, _ := out["isError"].(bool); isErr {
		t.Fatalf("reduce errored: %s", raw)
	}
	if !strings.Contains(string(raw), "reduced(length)") {
		t.Fatalf("reduce result missing the off-context computation: %s", raw)
	}
}

func TestMaterializeRefDeliversToOperator(t *testing.T) {
	store := refstore.NewMemStore()
	ref, _ := store.Put("198.51.100.7\n203.0.113.9\n") // PII the run kept off the model
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 1, Store: store}))

	req := httptest.NewRequest(http.MethodGet, "/admin/refs/x", nil)
	req.SetPathValue("ref", string(ref))
	rec := httptest.NewRecorder()
	s.adminMaterializeRef(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "198.51.100.7") {
		t.Fatalf("operator did not receive the actual referenced data: %s", rec.Body.String())
	}
	found := false
	for _, r := range s.RunLog() {
		if r.Kind == "materialize" {
			found = true
		}
	}
	if !found {
		t.Fatal("materializing a reference must leave an audit trace")
	}
}

func TestResultPayloadExtractsBareRows(t *testing.T) {
	// Supabase-style: rows wrapped in a preamble + XPIA untrusted-data tags.
	wrapped := map[string]any{
		"content": []any{map[string]any{"type": "text",
			"text": "Below is the result of the SQL query.\n<untrusted-data-abc123>\n[{\"mrn\":\"MRN1\"},{\"mrn\":\"MRN2\"}]\n</untrusted-data-abc123>\nUse this data to inform your next steps."}},
		"isError": false,
	}
	if got := resultPayload(wrapped); got != `[{"mrn":"MRN1"},{"mrn":"MRN2"}]` {
		t.Fatalf("expected bare rows, got %q", got)
	}

	// Supabase's ACTUAL shape: the rows are a JSON-encoded STRING inside a "result"
	// field, itself wrapped in a preamble + untrusted-data tags (the double wrap that
	// forced the agent into a slow regex scan). unwrapData must dig to the bare array.
	innerRows := `[{"mrn":"MRN1"},{"mrn":"MRN2"}]`
	envelope, _ := json.Marshal(map[string]string{
		"result": "Below is the result.\n<untrusted-data-zzz>\n" + innerRows + "\n</untrusted-data-zzz>\nUse this data.",
	})
	doubleWrapped := map[string]any{"content": []any{map[string]any{"type": "text", "text": string(envelope)}}}
	if got := resultPayload(doubleWrapped); got != innerRows {
		t.Fatalf("Supabase double-wrap: want bare rows %q, got %q", innerRows, got)
	}

	// structuredContent (already parsed) is preferred when present.
	structured := map[string]any{
		"structuredContent": []any{map[string]any{"mrn": "MRN9"}},
		"content":           []any{},
	}
	if got := resultPayload(structured); got != `[{"mrn":"MRN9"}]` {
		t.Fatalf("structuredContent should win: got %q", got)
	}

	// Non-JSON text is returned unchanged (no false extraction).
	plain := map[string]any{"content": []any{map[string]any{"type": "text", "text": "just a sentence"}}}
	if got := resultPayload(plain); got != "just a sentence" {
		t.Fatalf("plain text should pass through: got %q", got)
	}
}

func TestEngineFromQuery(t *testing.T) {
	cases := map[string]string{
		"SELECT count(*) FROM data":            "sql",
		"select distinct mrn from data":        "sql",
		"WITH x AS (SELECT 1) SELECT * FROM x": "sql",
		"[.[].mrn] | unique | length":          "jq",
		".result | length":                     "jq",
		"{total: length}":                      "jq",
		"MRN[0-9]+":                            "", // a bare regex — can't tell
		"just some words":                      "",
		"":                                     "",
	}
	for q, want := range cases {
		if got := engineFromQuery(q); got != want {
			t.Errorf("engineFromQuery(%q) = %q, want %q", q, got, want)
		}
	}
}

func TestReduceInfersEngineFromQuery(t *testing.T) {
	store := refstore.NewMemStore()
	ref, _ := store.Put(`[{"mrn":"MRN1"}]`)
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))

	// No engine named; the jq-shaped query routes to the jq engine.
	out := call(t, s, "reduce", map[string]any{"ref": string(ref), "query": "[.[].mrn]"})
	if isErr, _ := out["isError"].(bool); isErr {
		raw, _ := json.Marshal(out)
		t.Fatalf("reduce should infer jq from the query: %s", raw)
	}
}

func TestReduceUnknownRef(t *testing.T) {
	store := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))
	out := call(t, s, "reduce", map[string]any{"ref": "<ref_999>", "query": "length", "engine": "jq"})
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatal("reduce over an unknown reference must error")
	}
}

// A reduce output just over the raw threshold but under the reduce allowance must be
// inlined, not re-reffed — otherwise the result is un-viewable (every whole-result
// reduce of a ~2-16 KB ref re-parks it). A genuinely large output stays reffed.
func TestFinalizeReduceInlinesSmallReref(t *testing.T) {
	store := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))

	small := strings.Repeat("x", 3000) // > 2048 (would ref as a raw result), < 16 KiB
	out := s.finalizeReduce(s.budget.Apply(small))
	if out.Reffed {
		t.Fatal("a ~3 KB reduce output must inline, not re-ref (un-viewable band)")
	}
	if out.Inline != small {
		t.Fatalf("inlined content mismatch: got %d bytes", len(out.Inline))
	}

	big := strings.Repeat("y", (16<<10)+1) // > reduceInlineBytes → still parked
	if out2 := s.finalizeReduce(s.budget.Apply(big)); !out2.Reffed {
		t.Fatal("a >16 KiB reduce output must stay reffed so the agent reduces further")
	}
}
