package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microagency/internal/secretstore"
)

func TestReportAuthPostureNamesPublicIssuerResourceAndConsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-posture.json")
	posture := authPosture{
		Mode: "oauth-tunnel", Tunnel: "cloudflare",
		Issuer: "https://gateway.example", Resource: "https://gateway.example/mcp",
		Audience:  "https://gateway.example/mcp",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(posture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reportAuthPostureAt(&out, path)
	for _, want := range []string{"built-in OAuth", "cloudflare", posture.Issuer, posture.Resource, posture.Audience, "loopback operator listener"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("auth posture %q is missing %q", out.String(), want)
		}
	}
}

// doctor reports the secret-store posture so "where are my credentials" has an
// answer. An external Vault/OpenBao (VAULT_ADDR) is named explicitly.
func TestReportSecretPostureExternalVault(t *testing.T) {
	env := map[string]string{"VAULT_ADDR": "https://vault.example:8200", "VAULT_TOKEN": "token"}
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(name string) string { return env[name] }, func() bool { return false }, t.TempDir())
	if !strings.Contains(buf.String(), "external Vault/OpenBao") || !strings.Contains(buf.String(), "vault.example") {
		t.Fatalf("posture should name the external Vault: %q", buf.String())
	}
}

func TestReportSecretPostureDistinguishesManagedCustody(t *testing.T) {
	stateDir := t.TempDir()
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(string) string { return "" }, func() bool { return true }, stateDir)
	if !strings.Contains(buf.String(), "same-disk degraded bootstrap custody") || !strings.Contains(buf.String(), "MICROAGENCY_OPENBAO_PROTECTOR") {
		t.Fatalf("managed degraded posture is not explicit: %q", buf.String())
	}

	baoDir := filepath.Join(stateDir, "openbao")
	if err := os.MkdirAll(baoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "protector")
	script := "#!/bin/sh\nif [ \"$1\" = get ]; then printf '%s' '{\"unseal_key\":\"u\",\"role_id\":\"r\",\"secret_id\":\"s\"}'; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"format":"microagency-openbao-custody-v1","kind":"command","id":"test","command":"` + helper + `"}`
	if err := os.WriteFile(filepath.Join(baoDir, "custody.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	reportSecretPostureWith(&buf, func(string) string { return "" }, func() bool { return true }, stateDir)
	if !strings.Contains(buf.String(), "managed protected OpenBao") || !strings.Contains(buf.String(), "external protector helper") || !strings.Contains(buf.String(), "root retired") {
		t.Fatalf("managed protected posture is not explicit: %q", buf.String())
	}
	buf.Reset()
	reportSecretPostureWith(&buf, func(string) string { return "" }, func() bool { return false }, stateDir)
	if !strings.Contains(buf.String(), "OpenBao binary unavailable") || !strings.Contains(buf.String(), "startup will fail closed") {
		t.Fatalf("protected posture disappeared when the binary was unavailable: %q", buf.String())
	}
}

func TestReportSecretPostureNamesPlaintextFallback(t *testing.T) {
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(string) string { return "" }, func() bool { return false }, t.TempDir())
	if !strings.Contains(buf.String(), "degraded") || !strings.Contains(buf.String(), "plaintext") || strings.Contains(buf.String(), "fine for single-user") {
		t.Fatalf("fallback posture is not explicit: %q", buf.String())
	}
}

func TestReportSecretPostureValidatesEncryptedFallback(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	keyPath := filepath.Join(root, "key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(name string) string {
		if name == secretstore.FileKeyEnv {
			return keyPath
		}
		return ""
	}
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, env, func() bool { return false }, stateDir)
	if !strings.Contains(buf.String(), "AES-256-GCM") || !strings.Contains(buf.String(), "separately supplied") {
		t.Fatalf("encrypted posture is not explicit: %q", buf.String())
	}

	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	reportSecretPostureWith(&buf, env, func() bool { return false }, stateDir)
	if !strings.Contains(buf.String(), "misconfigured") || !strings.Contains(buf.String(), "fail closed") {
		t.Fatalf("invalid key posture is not explicit: %q", buf.String())
	}
}

func TestReportSecretPostureRejectsMissingOrWrongExistingFileKey(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	store, err := secretstore.NewEncryptedFile(filepath.Join(stateDir, "upstream-tokens.json"), bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), "up/example", []byte("sentinel")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(string) string { return "" }, func() bool { return false }, stateDir)
	if !strings.Contains(buf.String(), "exists") || !strings.Contains(buf.String(), "not configured") || !strings.Contains(buf.String(), "fail closed") {
		t.Fatalf("missing existing-file key posture is not explicit: %q", buf.String())
	}

	wrongKeyPath := filepath.Join(root, "wrong-key")
	if err := os.WriteFile(wrongKeyPath, bytes.Repeat([]byte{0x22}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	reportSecretPostureWith(&buf, func(name string) string {
		if name == secretstore.FileKeyEnv {
			return wrongKeyPath
		}
		return ""
	}, func() bool { return false }, stateDir)
	if !strings.Contains(buf.String(), "wrong key") || !strings.Contains(buf.String(), "misconfigured") {
		t.Fatalf("wrong existing-file key posture is not explicit: %q", buf.String())
	}
}

func TestReportSecretPostureRejectsPartialVaultConfig(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"VAULT_ADDR": "https://vault.example:8200"}, "VAULT_TOKEN is missing"},
		{map[string]string{"VAULT_TOKEN": "token"}, "VAULT_ADDR is missing"},
	} {
		var buf bytes.Buffer
		reportSecretPostureWith(&buf, func(name string) string { return tc.env[name] }, func() bool { return false }, t.TempDir())
		if !strings.Contains(buf.String(), tc.want) || !strings.Contains(buf.String(), "fail closed") {
			t.Fatalf("partial Vault config is not explicit: %q", buf.String())
		}
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
