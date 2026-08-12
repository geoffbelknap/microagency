package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"microagency/internal/gateway"
	"microagency/internal/mediation"
)

func writeMediationBinding(t *testing.T, stateDir, gatewayURL string) {
	t.Helper()
	b, err := mediation.NewBinding(t.TempDir(), "agent", gatewayURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	if err := os.MkdirAll(filepath.Dir(mediation.Path(stateDir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mediation.Path(stateDir), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnforcedMediationRejectsSharedHostRegistration(t *testing.T) {
	dir := t.TempDir()
	writeMediationBinding(t, dir, "http://gateway.internal:8765/mcp")
	s := NewServer(nil, WithStateDir(dir))
	err := s.registerUpstream("unsafe", &upstream{conn: &fakeConn{endpoint: "https://gateway.internal:9443/mcp"}, enabled: true})
	if err == nil || !strings.Contains(err.Error(), "dedicated gateway host") {
		t.Fatalf("shared-host registration error = %v", err)
	}
	if len(s.UpstreamList()) != 0 {
		t.Fatal("refused upstream was committed")
	}
}

func TestEnforcedMediationAllowsDiscoveryButRefusesUnsafeEnable(t *testing.T) {
	dir := t.TempDir()
	writeMediationBinding(t, dir, "http://gateway.internal:8765/mcp")
	s := NewServer(nil, WithStateDir(dir))
	conn := &fakeConn{endpoint: "https://gateway.internal:443/mcp", tools: []gateway.Tool{{Name: "read"}}}
	if err := s.AddDiscovered("candidate", conn, conn.tools, "catalog"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableUpstream(context.Background(), "candidate"); err == nil {
		t.Fatal("unsafe discovered upstream was enabled")
	}
	if got := s.UpstreamList()[0].State; got != "discovered" {
		t.Fatalf("state = %q after refused enable", got)
	}
}

func TestCorruptEnforcedBindingFailsClosedOnMutation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(mediation.Path(dir), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewServer(nil, WithStateDir(dir))
	err := s.registerUpstream("new", &upstream{conn: &fakeConn{endpoint: "https://api.example.com/mcp"}, enabled: true})
	if err == nil || !strings.Contains(err.Error(), "fail closed") {
		t.Fatalf("corrupt binding mutation error = %v", err)
	}
}

func TestEnforcedMediationRejectsRebindAtomically(t *testing.T) {
	dir := t.TempDir()
	writeMediationBinding(t, dir, "http://gateway.internal:8765/mcp")
	s := NewServer(nil, WithStateDir(dir))
	original := &fakeConn{endpoint: "https://api.example.com/mcp", tools: []gateway.Tool{{Name: "read"}}}
	if err := s.registerUpstream("safe", &upstream{conn: original, tools: original.tools, enabled: true}); err != nil {
		t.Fatal(err)
	}
	unsafe := &fakeConn{endpoint: "https://gateway.internal:9443/mcp", tools: original.tools}
	if err := s.RebindUpstream(context.Background(), "safe", unsafe); err == nil {
		t.Fatal("unsafe rebind succeeded")
	}
	info := s.UpstreamList()[0]
	if info.URL != original.endpoint || info.State != "enabled" {
		t.Fatalf("refused rebind changed live registration: %+v", info)
	}
}
