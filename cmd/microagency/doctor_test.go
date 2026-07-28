package main

import (
	"bytes"
	"strings"
	"testing"
)

// doctor reports the secret-store posture so "where are my credentials" has an
// answer. An external Vault/OpenBao (VAULT_ADDR) is named explicitly.
func TestReportSecretPostureExternalVault(t *testing.T) {
	t.Setenv("VAULT_ADDR", "https://vault.example:8200")
	var buf bytes.Buffer
	reportSecretPosture(&buf)
	if !strings.Contains(buf.String(), "external Vault/OpenBao") || !strings.Contains(buf.String(), "vault.example") {
		t.Fatalf("posture should name the external Vault: %q", buf.String())
	}
}

// The closing sentence answers for the whole page: a dead server can never
// sit above an ending that reads green, and only the fully healthy page may
// claim "ready".
func TestClosingVerdictGatesOnWholePage(t *testing.T) {
	healthy := "reduce(code) is verified end to end (booted and ran)"
	tests := []struct {
		name           string
		serverUp       bool
		bypassWarnings int
		runtimeHealthy bool
		wantContains   string
		wantNotReady   bool
	}{
		{"all green claims ready", true, 0, true, "microagency is ready", false},
		{"dead server never reads green", false, 0, true, "The gateway is not ready", true},
		{"back door blocks the ready claim", true, 1, true, "reachable around the gateway", true},
		{"multiple back doors are counted", true, 3, true, "3 upstreams", true},
		{"unhealthy runtime blocks the ready claim", true, 0, false, "The server is running, but", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := closingVerdict(tt.serverUp, tt.bypassWarnings, tt.runtimeHealthy, healthy)
			if !strings.Contains(got, tt.wantContains) {
				t.Errorf("verdict %q should contain %q", got, tt.wantContains)
			}
			if tt.wantNotReady && strings.Contains(got, "microagency is ready") {
				t.Errorf("page with a failing check claims ready: %q", got)
			}
		})
	}
}

// A passing lookup line carries no path; the failing line names where the
// lookup went, which is the remediation detail someone actually needs.
func TestPathWhenMissing(t *testing.T) {
	if got := pathWhenMissing(true, "/opt/supervisor"); got != "" {
		t.Errorf("healthy line leaks a path: %q", got)
	}
	if got := pathWhenMissing(false, "/opt/supervisor"); !strings.Contains(got, "/opt/supervisor") {
		t.Errorf("failing line should name the expected path: %q", got)
	}
	if got := pathWhenMissing(false, ""); got != "" {
		t.Errorf("no path known should stay empty: %q", got)
	}
}
