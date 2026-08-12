package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
	"microagency/internal/router"
)

type runnerFunc func(context.Context, router.Request) (router.Decision, error)

func (f runnerFunc) Run(ctx context.Context, req router.Request) (router.Decision, error) {
	return f(ctx, req)
}

func programRequestCall(t *testing.T, broker *programBroker, req programRequest) programResponse {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, broker.path, strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	broker.ServeHTTP(w, r)
	var response programResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode broker response (http %d): %v; body=%s", w.Code, err, w.Body.String())
	}
	return response
}

func programRawRequest(t *testing.T, broker *programBroker, body string) programResponse {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, broker.path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	broker.ServeHTTP(w, r)
	var response programResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode raw broker response (http %d): %v; body=%s", w.Code, err, w.Body.String())
	}
	return response
}

func reduceWithContext(t *testing.T, s *Server, ctx context.Context, args map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return s.reduce(ctx, raw)
}

func addProgramUpstream(t *testing.T, s *Server, tools []upTool, hit *int32, opts ...UpstreamOption) {
	t.Helper()
	up := guardUpstream(t, tools, false, hit)
	t.Cleanup(up.Close)
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}, opts...); err != nil {
		t.Fatalf("add upstream: %v", err)
	}
}

func TestGovernedProgramUsesGatewayPathAndCorrelatesAudit(t *testing.T) {
	var hit int32
	var sawSDK bool
	runner := runnerFunc(func(_ context.Context, req router.Request) (router.Decision, error) {
		broker, ok := req.HostService.(*programBroker)
		if !ok || broker == nil {
			t.Fatal("governed program did not receive its run-scoped broker")
		}
		for _, input := range req.Inputs {
			if input.Path == programSDKPath && strings.Contains(string(input.Data), "def call_tool") && !strings.Contains(string(input.Data), "host-secret") {
				sawSDK = true
			}
		}
		discovery := programRequestCall(t, broker, programRequest{ID: "discover-1", Operation: "find_tools", Query: "thing", Limit: 10})
		if !discovery.OK {
			t.Fatalf("program discovery failed: %+v", discovery)
		}
		found := false
		if result, ok := discovery.Result.(map[string]any); ok {
			for _, raw := range result["tools"].([]any) {
				if raw.(map[string]any)["name"] == "u__get-thing" {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("granted typed tool missing from discovery: %+v", discovery.Result)
		}

		callReq := programRequest{ID: "call-1", Operation: "call_tool", Name: "u__get-thing", Arguments: json.RawMessage(`{"page":1}`)}
		first := programRequestCall(t, broker, callReq)
		if !first.OK || first.Result != "ok" {
			t.Fatalf("program call failed: %+v", first)
		}
		replay := programRequestCall(t, broker, callReq)
		if !replay.OK || replay.Result != "ok" {
			t.Fatalf("identical replay did not return the cached result: %+v", replay)
		}
		return router.Decision{Inline: "joined answer"}, nil
	})
	store := refstore.NewMemStore()
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))
	addProgramUpstream(t, s, []upTool{{name: "get-thing", readOnly: ptrBool(true)}}, &hit)

	out := reduceWithContext(t, s, withPrincipal("alice"), map[string]any{
		"data": "{}", "code": "from microagency import call_tool",
		"task_id": "task-program", "program": map[string]any{"allowed_tools": []string{"u__get-thing"}},
	})
	if isError, _ := out["isError"].(bool); isError {
		t.Fatalf("governed reduce failed: %s", errText(t, out))
	}
	if !sawSDK {
		t.Fatal("generated credential-free Python SDK was not injected")
	}
	if got := atomic.LoadInt32(&hit); got != 1 {
		t.Fatalf("identical replay reached upstream %d times, want 1", got)
	}

	var outer, proxy, discovery, replay *RunInfo
	runs := s.RunLog()
	for i := range runs {
		run := runs[i]
		switch {
		case run.Kind == "reduce":
			copy := run
			outer = &copy
		case run.Kind == "proxy":
			copy := run
			proxy = &copy
		case run.Kind == "discovery":
			copy := run
			discovery = &copy
		case run.Kind == "program" && run.Tool == "replay":
			copy := run
			replay = &copy
		}
	}
	if outer == nil || proxy == nil || discovery == nil || replay == nil {
		t.Fatalf("missing correlated program audit records: %+v", s.RunLog())
	}
	if outer.ProgramCalls != 1 || outer.ProgramStatus != "completed" || len(outer.ProgramTools) != 1 || outer.ProgramTools[0] != "u__get-thing" {
		t.Fatalf("outer program summary = %+v", outer)
	}
	for _, child := range []*RunInfo{proxy, discovery, replay} {
		if child.ParentRunID != outer.RunID || child.Delivery != "program" {
			t.Fatalf("child not correlated to outer run: outer=%s child=%+v", outer.RunID, child)
		}
	}
	if proxy.OutputBytes != 0 || discovery.OutputBytes != 0 || !proxy.ContextMeasured || !discovery.ContextMeasured {
		t.Fatalf("intermediate bytes were counted as model context: proxy=%+v discovery=%+v", proxy, discovery)
	}
	if blob, _ := json.Marshal(s.RunLog()); strings.Contains(string(blob), "/v1/program/") || strings.Contains(string(blob), "host-secret") {
		t.Fatalf("run capability or credential leaked into audit: %s", blob)
	}
}

func TestGovernedProgramRejectsWriteGrantBeforeSandbox(t *testing.T) {
	var ran int32
	runner := runnerFunc(func(context.Context, router.Request) (router.Decision, error) {
		atomic.AddInt32(&ran, 1)
		return router.Decision{}, nil
	})
	store := refstore.NewMemStore()
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))
	var hit int32
	addProgramUpstream(t, s, []upTool{{name: "create-thing", readOnly: ptrBool(false)}}, &hit)

	out := reduceWithContext(t, s, withPrincipal("alice"), map[string]any{
		"data": "{}", "code": "print('never')",
		"program": map[string]any{"allowed_tools": []string{"u__create-thing"}},
	})
	if isError, _ := out["isError"].(bool); !isError || !strings.Contains(errText(t, out), "read-only") {
		t.Fatalf("write grant was not refused clearly: %v", out)
	}
	if atomic.LoadInt32(&ran) != 0 || atomic.LoadInt32(&hit) != 0 {
		t.Fatal("a refused write grant reached the sandbox or upstream")
	}
	runs := s.RunLog()
	if len(runs) != 1 || runs[0].Kind != "reduce" || runs[0].ProgramStatus != "rejected" || runs[0].ExitCode == 0 {
		t.Fatalf("write-grant refusal audit = %+v", runs)
	}
}

func TestGovernedProgramRuntimeAllowlistDenyIsAuditedBeforeEgress(t *testing.T) {
	var hit int32
	runner := runnerFunc(func(_ context.Context, req router.Request) (router.Decision, error) {
		broker := req.HostService.(*programBroker)
		response := programRequestCall(t, broker, programRequest{
			ID: "call-denied", Operation: "call_tool", Name: "u__other-read", Arguments: json.RawMessage(`{}`),
		})
		if response.OK || response.Error == nil || response.Error.Code != "unauthorized_tool" {
			t.Fatalf("ungranted tool response = %+v", response)
		}
		return router.Decision{Inline: "denied as expected"}, nil
	})
	store := refstore.NewMemStore()
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))
	addProgramUpstream(t, s, []upTool{
		{name: "get-thing", readOnly: ptrBool(true)},
		{name: "other-read", readOnly: ptrBool(true)},
	}, &hit)

	out := reduceWithContext(t, s, withPrincipal("alice"), map[string]any{
		"data": "{}", "code": "print('deny')",
		"program": map[string]any{"allowed_tools": []string{"u__get-thing"}},
	})
	if isError, _ := out["isError"].(bool); isError {
		t.Fatalf("outer program failed: %s", errText(t, out))
	}
	if atomic.LoadInt32(&hit) != 0 {
		t.Fatal("ungranted tool reached upstream")
	}
	var denied *RunInfo
	for _, run := range s.RunLog() {
		if run.Kind == "proxy" && run.ProgramRequestID == "call-denied" {
			copy := run
			denied = &copy
		}
	}
	if denied == nil || denied.ExitCode == 0 || denied.Delivery != "program" || denied.AuditErr == "" || len(denied.Audit) != 0 {
		t.Fatalf("pre-egress allowlist denial audit = %+v", denied)
	}
}

func TestGovernedProgramRechecksReadClassificationBeforeEgress(t *testing.T) {
	var hit int32
	var s *Server
	runner := runnerFunc(func(_ context.Context, req router.Request) (router.Decision, error) {
		// Simulate an upstream schema refresh after the outer grant was validated.
		// The ordinary proxy gate must use the current schema, not the stale grant.
		s.reg.mu.Lock()
		s.reg.conns["u"].tools[0].Annotations.ReadOnlyHint = ptrBool(false)
		s.reg.mu.Unlock()

		broker := req.HostService.(*programBroker)
		response := programRequestCall(t, broker, programRequest{
			ID: "call-reclassified", Operation: "call_tool", Name: "u__get-thing", Arguments: json.RawMessage(`{}`),
		})
		if response.OK || response.Error == nil || response.Error.Code != "write_forbidden" {
			t.Fatalf("reclassified write response = %+v", response)
		}
		return router.Decision{Inline: "denied as expected"}, nil
	})
	store := refstore.NewMemStore()
	s = newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))
	addProgramUpstream(t, s, []upTool{{name: "get-thing", readOnly: ptrBool(true)}}, &hit)

	out := reduceWithContext(t, s, withPrincipal("alice"), map[string]any{
		"data": "{}", "code": "print('deny')",
		"program": map[string]any{"allowed_tools": []string{"u__get-thing"}},
	})
	if isError, _ := out["isError"].(bool); isError {
		t.Fatalf("outer program failed: %s", errText(t, out))
	}
	if atomic.LoadInt32(&hit) != 0 {
		t.Fatal("tool reclassified as write reached upstream")
	}
}

func TestGovernedProgramOwnerScopeCannotCross(t *testing.T) {
	var ran, hit int32
	runner := runnerFunc(func(context.Context, router.Request) (router.Decision, error) {
		atomic.AddInt32(&ran, 1)
		return router.Decision{}, nil
	})
	store := refstore.NewMemStore()
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))
	addProgramUpstream(t, s, []upTool{{name: "get-thing", readOnly: ptrBool(true)}}, &hit, WithOwner("alice"))

	out := reduceWithContext(t, s, withPrincipal("bob"), map[string]any{
		"data": "{}", "code": "print('never')",
		"program": map[string]any{"allowed_tools": []string{"u__get-thing"}},
	})
	if isError, _ := out["isError"].(bool); !isError || !strings.Contains(errText(t, out), "unknown to this caller") {
		t.Fatalf("cross-owner grant response = %v", out)
	}
	if atomic.LoadInt32(&ran) != 0 || atomic.LoadInt32(&hit) != 0 {
		t.Fatal("cross-owner grant reached sandbox or upstream")
	}
}

func TestGovernedProgramCallByteAndReplayBudgets(t *testing.T) {
	var hit int32
	runner := runnerFunc(func(_ context.Context, req router.Request) (router.Decision, error) {
		broker := req.HostService.(*programBroker)
		firstReq := programRequest{ID: "same-id", Operation: "call_tool", Name: "u__get-thing", Arguments: json.RawMessage(`{}`)}
		first := programRequestCall(t, broker, firstReq)
		if !first.OK {
			t.Fatalf("first call failed: %+v", first)
		}
		mismatch := firstReq
		mismatch.Arguments = json.RawMessage(`{"different":true}`)
		if got := programRequestCall(t, broker, mismatch); got.OK || got.Error == nil || got.Error.Code != "replay_mismatch" {
			t.Fatalf("mismatched replay = %+v", got)
		}
		if got := programRequestCall(t, broker, programRequest{ID: "over-call-budget", Operation: "call_tool", Name: "u__get-thing", Arguments: json.RawMessage(`{}`)}); got.OK || got.Error == nil || got.Error.Code != "budget_exhausted" {
			t.Fatalf("call budget response = %+v", got)
		}
		return router.Decision{Inline: "bounded"}, nil
	})
	store := refstore.NewMemStore()
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))
	addProgramUpstream(t, s, []upTool{{name: "get-thing", readOnly: ptrBool(true)}}, &hit)

	out := reduceWithContext(t, s, withPrincipal("alice"), map[string]any{
		"data": "{}", "code": "print('bounded')",
		"program": map[string]any{"allowed_tools": []string{"u__get-thing"}, "max_calls": 1, "max_bytes": 1024},
	})
	if isError, _ := out["isError"].(bool); isError {
		t.Fatalf("bounded program failed: %s", errText(t, out))
	}
	if atomic.LoadInt32(&hit) != 1 {
		t.Fatalf("budget/replay behavior reached upstream %d times, want 1", atomic.LoadInt32(&hit))
	}
	for _, run := range s.RunLog() {
		if run.Kind == "reduce" && (run.ProgramCalls != 1 || run.ProgramStatus != "budget_exhausted") {
			t.Fatalf("outer budget summary = %+v", run)
		}
	}
}

func TestGovernedProgramResultByteBudget(t *testing.T) {
	var hit int32
	runner := runnerFunc(func(_ context.Context, req router.Request) (router.Decision, error) {
		broker := req.HostService.(*programBroker)
		response := programRequestCall(t, broker, programRequest{
			ID: "over-byte-budget", Operation: "call_tool", Name: "u__get-thing", Arguments: json.RawMessage(`{}`),
		})
		if response.OK || response.Error == nil || response.Error.Code != "budget_exhausted" {
			t.Fatalf("result byte budget response = %+v", response)
		}
		return router.Decision{Inline: "bounded"}, nil
	})
	store := refstore.NewMemStore()
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))
	addProgramUpstream(t, s, []upTool{{name: "get-thing", readOnly: ptrBool(true)}}, &hit)

	out := reduceWithContext(t, s, withPrincipal("alice"), map[string]any{
		"data": "{}", "code": "print('bounded')",
		"program": map[string]any{"allowed_tools": []string{"u__get-thing"}, "max_bytes": 1},
	})
	if isError, _ := out["isError"].(bool); isError {
		t.Fatalf("outer program failed: %s", errText(t, out))
	}
	if atomic.LoadInt32(&hit) != 1 {
		t.Fatalf("byte-bounded call reached upstream %d times, want 1", atomic.LoadInt32(&hit))
	}
	for _, run := range s.RunLog() {
		if run.Kind == "reduce" && (run.ProgramBytes != 0 || run.ProgramStatus != "budget_exhausted") {
			t.Fatalf("outer byte-budget summary = %+v", run)
		}
	}
}

func TestGovernedProgramMaterializesLargeRefOnlyInsideSandbox(t *testing.T) {
	large := strings.Repeat("PRIVATE_ROW_", 600)
	var hit int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get-large","description":"large read","inputSchema":{},"annotations":{"readOnlyHint":true}}]}}`)
		case "tools/call":
			atomic.AddInt32(&hit, 1)
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":`+strconvQuote(large)+`}],"isError":false}}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
	t.Cleanup(up.Close)

	runner := runnerFunc(func(_ context.Context, req router.Request) (router.Decision, error) {
		broker := req.HostService.(*programBroker)
		response := programRequestCall(t, broker, programRequest{ID: "large-1", Operation: "call_tool", Name: "u__get-large", Arguments: json.RawMessage(`{}`)})
		if !response.OK || response.Result != large {
			t.Fatalf("large parked result was not materialized in sandbox: ok=%v bytes=%d error=%+v", response.OK, len(fmtSprint(response.Result)), response.Error)
		}
		return router.Decision{Inline: "PRIVATE_ROW_COUNT=600"}, nil
	})
	store := refstore.NewMemStore()
	s := newTestServer(t, runner, WithBudgetGate(budget.Gate{MaxBytes: 128, Store: store}), WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Token: "host-secret", Client: &http.Client{}}); err != nil {
		t.Fatal(err)
	}
	out := reduceWithContext(t, s, withPrincipal("alice"), map[string]any{
		"data": "{}", "code": "print('count')",
		"program": map[string]any{"allowed_tools": []string{"u__get-large"}, "max_bytes": len(large) + 1024},
	})
	if isError, _ := out["isError"].(bool); isError {
		t.Fatalf("large-result program failed: %s", errText(t, out))
	}
	if blob, _ := json.Marshal(out); strings.Contains(string(blob), "PRIVATE_ROW_PRIVATE_ROW") || strings.Contains(string(blob), "host-secret") {
		t.Fatalf("large intermediate or credential entered outer context: %s", blob)
	}
	if atomic.LoadInt32(&hit) != 1 {
		t.Fatalf("large read hit upstream %d times", atomic.LoadInt32(&hit))
	}
}

func TestGovernedProgramCancellationRefusesNewCalls(t *testing.T) {
	store := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))
	var hit int32
	addProgramUpstream(t, s, []upTool{{name: "get-thing", readOnly: ptrBool(true)}}, &hit)
	ctx, cancel := context.WithCancel(withPrincipal("alice"))
	broker, stop, err := s.newProgramBroker(ctx, "run-parent", "task-cancel", programConfig{AllowedTools: []string{"u__get-thing"}})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	cancel()
	response := programRequestCall(t, broker, programRequest{ID: "after-cancel", Operation: "call_tool", Name: "u__get-thing", Arguments: json.RawMessage(`{}`)})
	if response.OK || response.Error == nil || response.Error.Code != "canceled" {
		t.Fatalf("post-cancel request = %+v", response)
	}
	if atomic.LoadInt32(&hit) != 0 {
		t.Fatal("canceled broker reached upstream")
	}
}

func TestGovernedProgramCapsMalformedAndReplayRequests(t *testing.T) {
	store := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: store}))
	var hit int32
	addProgramUpstream(t, s, []upTool{{name: "get-thing", readOnly: ptrBool(true)}}, &hit)
	broker, stop, err := s.newProgramBroker(withPrincipal("alice"), "run-parent", "task-requests", programConfig{AllowedTools: []string{"u__get-thing"}})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	broker.maxRequests = 2

	if got := programRawRequest(t, broker, `{`); got.OK || got.Error == nil || got.Error.Code != "invalid_request" {
		t.Fatalf("malformed request response = %+v", got)
	}
	valid := programRequest{ID: "one", Operation: "call_tool", Name: "u__get-thing", Arguments: json.RawMessage(`{}`)}
	if got := programRequestCall(t, broker, valid); !got.OK {
		t.Fatalf("valid request response = %+v", got)
	}
	if got := programRequestCall(t, broker, valid); got.OK || got.Error == nil || got.Error.Code != "budget_exhausted" {
		t.Fatalf("request budget response = %+v", got)
	}
	if atomic.LoadInt32(&hit) != 1 {
		t.Fatalf("request flood reached upstream %d times, want 1", atomic.LoadInt32(&hit))
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func fmtSprint(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
