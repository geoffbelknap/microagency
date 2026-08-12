package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
	"microagency/internal/router"
	"microagency/internal/sandbox"
)

type trackedMicroagentProvider struct {
	provider sandbox.MicroagentProvider
	names    []string
}

func (p *trackedMicroagentProvider) Run(ctx context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	p.names = append(p.names, spec.Name)
	return p.provider.Run(ctx, spec)
}

// TestLiveReduceCode exercises the complete MCP reduce(code) path against the
// microagent backend selected by the current host. It is opt-in because it boots
// real VMs; scripts/dev/live-reduce.sh supplies the required environment.
func TestLiveReduceCode(t *testing.T) {
	backend := requireLiveReduceBackend(t)
	stateDir := liveReduceStateDir(t)
	provider := &trackedMicroagentProvider{provider: sandbox.MicroagentProvider{StateDir: stateDir}}
	cleanupLiveReduceState(t, provider, stateDir)

	store := refstore.NewMemStore()
	gate := budget.Gate{MaxBytes: 4096, Store: store}
	runner := router.Router{
		Provider: provider,
		Gate:     gate,
		Image:    sandbox.ReduceImage,
		CodePath: sandbox.ReduceCodePath,
		Timeout:  6 * time.Minute,
	}
	gatewayDir := filepath.Join(stateDir, "gateway")
	if err := os.MkdirAll(gatewayDir, 0o700); err != nil {
		t.Fatalf("create gateway audit state: %v", err)
	}
	s := newTestServer(t, runner, WithBudgetGate(gate), WithStateDir(gatewayDir))

	singleRef, _ := store.Put("SINGLE_INPUT_SENTINEL", "local")
	single := call(t, s, "reduce", map[string]any{
		"ref":  string(singleRef),
		"code": `print("LIVE_SINGLE|" + open("/app/input").read())`,
	})
	assertLiveReduceResult(t, single, "LIVE_SINGLE|SINGLE_INPUT_SENTINEL")
	t.Log("single-input sentinel passed")

	firstRef, _ := store.Put("ALPHA", "local")
	secondRef, _ := store.Put("BETA", "local")
	multi := call(t, s, "reduce", map[string]any{
		"refs": []string{string(firstRef), string(secondRef)},
		"code": `import socket
try:
    with socket.create_connection(("198.51.100.10", 443), timeout=2) as connection:
        connection.sendall(b"live-egress-probe")
        connection.recv(1)
except Exception:
    pass
print("LIVE_MULTI|" + open("/app/input_1").read() + "|" + open("/app/input_2").read())`,
	})
	assertLiveReduceResult(t, multi, "LIVE_MULTI|ALPHA|BETA")
	t.Log("ordered multi-input result passed")

	// A governed program receives only a run-scoped broker endpoint. The broker
	// performs both paginated calls host-side with the gateway-held credential,
	// while unrelated guest networking remains denied.
	const upstreamSecret = "LIVE_HOST_ONLY_CREDENTIAL"
	var upstreamCalls, authFailures int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+upstreamSecret {
			atomic.AddInt32(&authFailures, 1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request struct {
			Method string `json:"method"`
			Params struct {
				Arguments struct {
					Page int `json:"page"`
				} `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad JSON", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "initialize":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"live-program","version":"1"}}}`)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list-records","description":"List one page of records","inputSchema":{"type":"object","properties":{"page":{"type":"integer"}},"required":["page"]},"annotations":{"readOnlyHint":true}}]}}`)
		case "tools/call":
			atomic.AddInt32(&upstreamCalls, 1)
			page := request.Params.Arguments.Page
			payload := map[string]any{"items": []map[string]any{{"id": "ALPHA", "private": "row-a"}}}
			switch page {
			case 1:
				payload["next"] = 2
			case 2:
				payload["items"] = []map[string]any{{"id": "BETA", "private": "row-b"}}
			default:
				http.Error(w, "unexpected page", http.StatusBadRequest)
				return
			}
			payloadJSON, _ := json.Marshal(payload)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"content": []map[string]any{{"type": "text", "text": string(payloadJSON)}}, "isError": false},
			})
		default:
			http.Error(w, "unexpected method", http.StatusBadRequest)
		}
	}))
	t.Cleanup(upstream.Close)
	if err := s.AddUpstream(context.Background(), "live", &gateway.Upstream{
		Name: "live", URL: upstream.URL, Token: upstreamSecret, Client: upstream.Client(),
	}); err != nil {
		t.Fatalf("add live governed-program upstream: %v", err)
	}
	program := call(t, s, "reduce", map[string]any{
		"data": "{}",
		"code": `import socket
from microagency import call_tool, find_tools

schemas = find_tools("live__list-records", 5)
if not any(tool.get("name") == "live__list-records" for tool in schemas.get("tools", [])):
    raise RuntimeError("granted schema missing")
rows = []
page = 1
while page:
    result = call_tool("live__list-records", {"page": page})
    rows.extend(result["items"])
    page = result.get("next")
try:
    with socket.create_connection(("198.51.100.10", 443), timeout=2):
        pass
except Exception:
    pass
print("LIVE_PROGRAM|" + ",".join(row["id"] for row in rows))`,
		"program": map[string]any{
			"allowed_tools": []string{"live__list-records"},
			"max_calls":     4,
			"max_bytes":     4096,
			"max_seconds":   300,
		},
	})
	assertLiveReduceResult(t, program, "LIVE_PROGRAM|ALPHA,BETA")
	t.Log("governed paginated program result passed")
	if atomic.LoadInt32(&upstreamCalls) != 2 || atomic.LoadInt32(&authFailures) != 0 {
		t.Fatalf("governed pagination calls=%d auth_failures=%d", atomic.LoadInt32(&upstreamCalls), atomic.LoadInt32(&authFailures))
	}
	if encoded, _ := json.Marshal(program); strings.Contains(string(encoded), upstreamSecret) || strings.Contains(string(encoded), "row-a") || strings.Contains(string(encoded), "row-b") {
		t.Fatalf("credential or intermediate rows entered model-facing output: %s", encoded)
	}

	runs := s.RunLog()
	reduceRuns := make([]RunInfo, 0, 3)
	var programRun *RunInfo
	for i := range runs {
		run := runs[i]
		if run.Kind == "reduce" {
			reduceRuns = append(reduceRuns, run)
			if len(run.ProgramTools) > 0 {
				programRun = &runs[i]
			}
		}
	}
	if len(reduceRuns) != 3 {
		t.Fatalf("live reduce runs = %d, want 3; all records=%+v", len(reduceRuns), runs)
	}
	for _, run := range reduceRuns {
		if run.Substrate != "microvm" || run.ExitCode != 0 {
			t.Fatalf("live reduce run metadata = %+v", run)
		}
	}
	if programRun == nil || programRun.ProgramCalls != 2 || programRun.ProgramStatus != "completed" {
		t.Fatalf("governed program audit summary = %+v", programRun)
	}
	for _, run := range runs {
		if run.ParentRunID == programRun.RunID && run.Delivery == "program" && run.OutputBytes != 0 {
			t.Fatalf("program intermediate counted as model context: %+v", run)
		}
	}
	if encoded, _ := json.Marshal(runs); strings.Contains(string(encoded), upstreamSecret) || strings.Contains(string(encoded), "row-a") || strings.Contains(string(encoded), "row-b") {
		t.Fatalf("credential or intermediate rows leaked into audit: %s", encoded)
	}
	hasProgramDeny := false
	for _, event := range programRun.Audit {
		if strings.Contains(strings.ToLower(event.Event), "deny") &&
			(strings.Contains(event.Dst, "198.51.100.10") || strings.Contains(event.Host, "198.51.100.10")) {
			hasProgramDeny = true
			break
		}
	}
	if !hasProgramDeny {
		t.Fatalf("%s governed program did not record the denied destination: %+v", backend, programRun)
	}
	t.Log("deny-all egress exercised and audited; host-only credential and private rows absent from output and audit")
	t.Logf("live reduce(code) passed on %s; state=%s", backend, stateDir)
}

func requireLiveReduceBackend(t *testing.T) string {
	t.Helper()
	if testing.Short() || os.Getenv("MICROAGENCY_LIVE_REDUCE") != "1" {
		t.Skip("live reduce(code) validation is opt-in; run scripts/dev/live-reduce.sh on a supported host")
	}
	backend := ""
	switch runtime.GOOS {
	case "linux":
		backend = "linux-kvm"
		if _, err := os.Stat("/dev/kvm"); err != nil {
			t.Fatalf("linux-kvm live validation requires /dev/kvm: %v", err)
		}
	case "darwin":
		if runtime.GOARCH != "arm64" {
			t.Fatalf("apple-vf live validation requires macOS arm64, got %s", runtime.GOARCH)
		}
		backend = "apple-vf"
	default:
		t.Fatalf("no supported microagent backend on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	selected := strings.TrimSpace(os.Getenv("MICROAGENT_E2E_BACKEND"))
	if selected == "applevf" {
		selected = "apple-vf"
	}
	if selected == "" {
		t.Fatal("MICROAGENT_E2E_BACKEND must name the current supported host backend")
	}
	if selected != backend {
		t.Fatalf("MICROAGENT_E2E_BACKEND=%q does not match this host backend %q", selected, backend)
	}
	return backend
}

func liveReduceStateDir(t *testing.T) string {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("MICROAGENCY_LIVE_STATE_DIR"))
	if base == "" {
		base = os.TempDir()
	} else if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatalf("create live state base: %v", err)
	}
	dir, err := os.MkdirTemp(base, "run-")
	if err != nil {
		t.Fatalf("create task-owned live state: %v", err)
	}
	cache := strings.TrimSpace(os.Getenv("MICROAGENCY_LIVE_CACHE_DIR"))
	if cache == "" {
		cache = filepath.Join(dir, "build", "base-cache")
	}
	t.Setenv("MICROAGENT_ROOTFS_BASE_CACHE_DIR", cache)
	return dir
}

func cleanupLiveReduceState(t *testing.T, provider *trackedMicroagentProvider, stateDir string) {
	t.Helper()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("live reduce failed; preserved diagnostic state at %s", stateDir)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		var cleanupErrs []string
		for _, name := range provider.names {
			if err := provider.provider.DeleteWorkspace(ctx, name); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s: %v", name, err))
			}
		}
		if len(cleanupErrs) > 0 {
			t.Errorf("live workspace cleanup failed; state preserved at %s: %s", stateDir, strings.Join(cleanupErrs, "; "))
			return
		}
		if err := os.RemoveAll(stateDir); err != nil {
			t.Errorf("remove task-owned live state %s: %v", stateDir, err)
		}
	})
}

func assertLiveReduceResult(t *testing.T, out map[string]any, marker string) {
	t.Helper()
	if isError, _ := out["isError"].(bool); isError {
		t.Fatalf("live reduce failed: %v", out)
	}
	result := toolContentJSON(t, out)
	answer, _ := result["result"].(string)
	if !strings.Contains(answer, marker) {
		t.Fatalf("live reduce result %q does not contain %q", answer, marker)
	}
}
