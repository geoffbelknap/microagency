package mediation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geoffbelknap/microagent/pkg/vmkit"
	"github.com/geoffbelknap/microagent/pkg/workspace"
)

func preparedWorkspace(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	opts := workspace.DefaultOptions()
	opts.StateDir, opts.Name = dir, "governed-agent"
	opts.EgressMode = vmkit.EgressModeOff
	if err := workspace.WriteManifest(opts); err != nil {
		t.Fatal(err)
	}
	return dir, opts.Name
}

func TestEnforceWritesGatewayOnlyLockedPolicy(t *testing.T) {
	workspaceDir, name := preparedWorkspace(t)
	stateDir := t.TempDir()
	b, err := Enforce(stateDir, workspaceDir, name, "HTTP://192.0.2.10:8765")
	if err != nil {
		t.Fatal(err)
	}
	if b.GatewayURL != "http://192.0.2.10:8765/mcp" || b.GatewayHost != "192.0.2.10" {
		t.Fatalf("canonical gateway = %+v", b)
	}
	m, err := workspace.ReadManifest(workspaceDir, name)
	if err != nil {
		t.Fatal(err)
	}
	if !manifestEnforces(m, b.GatewayHost) {
		t.Fatalf("manifest is not gateway-only locked: %+v", m)
	}
	loaded, err := Load(stateDir)
	if err != nil || loaded.PolicyDigest != b.PolicyDigest {
		t.Fatalf("load binding = %+v, %v", loaded, err)
	}
	status := Inspect(stateDir)
	if status.State != "configured" || status.Mode != ModeEnforcedWorkspace {
		t.Fatalf("status = %+v", status)
	}
}

func TestGatewayEndpointRejectsCredentialsAndGuestLoopback(t *testing.T) {
	for _, raw := range []string{
		"http://token@192.0.2.10:8765/mcp",
		"http://127.0.0.1:8765/mcp",
		"http://localhost:8765/mcp",
		"https://gateway.example/mcp?token=nope",
	} {
		if _, err := NewBinding(t.TempDir(), "agent", raw); err == nil {
			t.Errorf("NewBinding(%q) succeeded", raw)
		}
	}
}

func TestValidateUpstreamRejectsGatewayHostAllPorts(t *testing.T) {
	b, err := NewBinding(t.TempDir(), "agent", "http://gateway.internal:8765/mcp")
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"https://gateway.internal/mcp", "http://GATEWAY.INTERNAL:9999/other"} {
		if err := ValidateUpstream(b, endpoint); err == nil {
			t.Errorf("shared gateway endpoint %q accepted", endpoint)
		}
	}
	if err := ValidateUpstream(b, "https://api.example.com/mcp"); err != nil {
		t.Fatalf("independent upstream rejected: %v", err)
	}
	if err := ValidateUpstream(b, "stdio://local/tool"); err != nil {
		t.Fatalf("non-network upstream rejected: %v", err)
	}
}

func TestInspectCorruptBindingIsDegradedNotAdvisory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(Path(dir), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := Inspect(dir)
	if st.State != "degraded" || st.Mode != ModeEnforcedWorkspace {
		t.Fatalf("corrupt enforced state was mislabeled: %+v", st)
	}
}

func TestInspectRunningWorkspaceRequiresRuntimePolicyMatch(t *testing.T) {
	workspaceDir, name := preparedWorkspace(t)
	stateDir := t.TempDir()
	b, err := Enforce(stateDir, workspaceDir, name, "http://192.0.2.10:8765/mcp")
	if err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(workspaceDir, name)
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(workspace.RuntimeState{
		Event:  workspace.EventFile{Identity: vmkit.Identity{RuntimeID: name, Backend: vmkit.BackendLinuxKVM}, State: vmkit.StateRunning},
		Config: vmkit.Config{EgressMode: vmkit.EgressModeBroker, EgressAllow: []string{"old.example"}, EgressAllowlistLocked: true},
	})
	if err := os.WriteFile(filepath.Join(runtimeDir, "runtime.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st := Inspect(stateDir)
	if st.State != "degraded" || !strings.Contains(st.Reason, "running workspace policy differs") || st.GatewayHost != b.GatewayHost {
		t.Fatalf("runtime mismatch status = %+v", st)
	}
}

func TestDenialsCorrelateProtectedUpstreamIdentity(t *testing.T) {
	workspaceDir, name := preparedWorkspace(t)
	b, err := NewBinding(workspaceDir, name, "http://192.0.2.10:8765/mcp")
	if err != nil {
		t.Fatal(err)
	}
	path := workspace.EgressAuditPath(workspaceDir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	records := []map[string]any{
		{"event": "egress_deny", "ts": "2026-08-12T12:00:00Z", "host": "api.example.com", "dst": "203.0.113.5:443", "reason": "allowlist"},
		{"event": "egress_allow", "host": "192.0.2.10"},
	}
	var data []byte
	for _, rec := range records {
		line, _ := json.Marshal(rec)
		data = append(data, append(line, '\n')...)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Denials(b, map[string][]string{"api.example.com": {"calendar", "mail"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Destination != "api.example.com" || strings.Join(got[0].Upstreams, ",") != "calendar,mail" {
		t.Fatalf("denials = %+v", got)
	}
}
