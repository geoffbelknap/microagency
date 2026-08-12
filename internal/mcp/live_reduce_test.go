package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"microagency/internal/budget"
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

	runs := s.RunLog()
	if len(runs) != 2 {
		t.Fatalf("live reduce audit records = %d, want 2", len(runs))
	}
	if runs[0].Substrate != "microvm" || runs[0].ExitCode != 0 || runs[1].Substrate != "microvm" || runs[1].ExitCode != 0 {
		t.Fatalf("live reduce run metadata = %+v", runs)
	}
	hasDeny := false
	for _, run := range runs {
		for _, event := range run.Audit {
			if strings.Contains(strings.ToLower(event.Event), "deny") &&
				(strings.Contains(event.Dst, "198.51.100.10") || strings.Contains(event.Host, "198.51.100.10")) {
				hasDeny = true
				break
			}
		}
	}
	if !hasDeny {
		t.Fatalf("%s live reduce did not record the denied destination: %+v", backend, runs)
	}
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
