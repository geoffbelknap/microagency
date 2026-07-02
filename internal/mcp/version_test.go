package mcp

import (
	"context"
	"testing"
)

// The build version must flow from WithVersion (main.version via -ldflags) into
// both /admin/infra and the MCP serverInfo — not a hardcoded placeholder.
func TestVersionReportedNotHardcoded(t *testing.T) {
	s := NewServer(nil, WithVersion("0.1.2-latest.9"))
	if got := s.InfraStatus(context.Background()).Build.Version; got != "0.1.2-latest.9" {
		t.Fatalf("infra Build.Version = %q, want the injected version", got)
	}
	si := initializeResult("0.1.2-latest.9")["serverInfo"].(map[string]any)
	if got := si["version"]; got != "0.1.2-latest.9" {
		t.Fatalf("serverInfo version = %v, want the injected version", got)
	}
	// A plain build (no ldflags) falls back to "dev", never a stale literal.
	if got := initializeResult("")["serverInfo"].(map[string]any)["version"]; got != "dev" {
		t.Fatalf("empty version fallback = %v, want dev", got)
	}
}
